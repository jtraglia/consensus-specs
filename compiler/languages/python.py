import ast
import importlib
import re
import sys
import textwrap
from collections.abc import Callable, Iterator
from functools import cache
from pathlib import Path

import eth_consensus_specs
from compiler.discover import DeclarationError
from compiler.languages.base import (
    COLLECTION,
    Language,
    RECORD,
    References,
    SCALAR,
    STRUCTURE,
)
from compiler.model import (
    CONFIG,
    CONSTANT,
    Definition,
    FUNCTION,
    IMPORT,
    METHOD,
    Records,
    Spec,
    TYPE,
    VALUE,
    Variable,
    WRAPPER,
)
from compiler.values import hex_text

RECORDS_TYPE = "tuple[frozendict[str, Any], ...]"


@cache
def _parse(source: str) -> ast.Module:
    try:
        return ast.parse(source)
    except SyntaxError as error:
        raise DeclarationError(f"invalid python: {error}") from None


def _names(node: ast.AST, lazy: bool = False) -> Iterator[tuple[ast.Name, bool]]:
    if isinstance(node, ast.Name):
        yield node, lazy
    elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
        for child in [*node.decorator_list, node.args, *([node.returns] if node.returns else [])]:
            yield from _names(child, lazy)
        for child in node.body:
            yield from _names(child, lazy=True)
        return
    for child in ast.iter_child_nodes(node):
        yield from _names(child, lazy)


@cache
def _references(source: str) -> References:
    eager: set[str] = set()
    lazy: set[str] = set()
    for name, deferred in _names(_parse(source)):
        (lazy if deferred else eager).add(name.id)
    return frozenset(eager), frozenset(lazy)


def _is_dataclass(decorator: ast.expr) -> bool:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    return isinstance(target, ast.Name) and target.id == "dataclass"


def _records(records: Records) -> str:
    if not records:
        return "()"
    lines = ["("]
    for record in records:
        lines.append("        frozendict({")
        lines.extend(f'            "{key}": {value},' for key, value in record.items())
        lines.append("        }),")
    lines.append("    )")
    return "\n".join(lines)


def _annotation(value: str | Records) -> str:
    if isinstance(value, list):
        return RECORDS_TYPE
    match _parse(value).body:
        case [ast.Expr(value=ast.Call(func=ast.Name(id=name)))]:
            return name
        case [ast.Expr(value=ast.Constant(value=str()))]:
            return "str"
    return "int"


def _import_lines(statements: list[str]) -> list[str]:
    modules: dict[str, list[str]] = {}
    for statement in statements:
        node = _parse(statement).body[0]
        alias = node.names[0]
        part = alias.name if alias.asname is None else f"{alias.name} as {alias.asname}"
        module = node.module if isinstance(node, ast.ImportFrom) else None
        modules.setdefault(str(module), []).append(part)
    groups: list[list[str]] = [[], [], []]
    for module in sorted(modules):
        parts = modules[module]
        if module == "None":
            lines = [f"import {part}" for part in parts]
        else:
            lines = [f"from {module} import {', '.join(parts)}"]
        root = (parts[0] if module == "None" else module).split(".")[0]
        group = 0 if root in sys.stdlib_module_names else 2 if root == "eth_consensus_specs" else 1
        groups[group].extend(lines)
    return ["\n".join(group) for group in groups if group]


class Python(Language):
    name = "python"
    separator = "\n\n\n"

    def read_declaration(self, source: str) -> tuple[str, str, str | None]:
        body = _parse(source).body
        if body and all(isinstance(node, ast.Import | ast.ImportFrom) for node in body):
            return IMPORT, source, None
        if len(body) != 1:
            raise DeclarationError(f"expected one definition per code block, found {len(body)}")
        match body[0]:
            case ast.FunctionDef(name=name, args=ast.arguments(args=[first, *_])) if (
                first.arg == "self" and isinstance(first.annotation, ast.Name)
            ):
                return METHOD, name, first.annotation.id
            case ast.FunctionDef(name=name):
                return FUNCTION, name, None
            case ast.Assign(targets=[ast.Name(id=name)], value=value) if any(
                isinstance(node, ast.Name) and node.id == name for node in ast.walk(value)
            ):
                return WRAPPER, name, None
            case ast.ClassDef(name=name):
                return TYPE, name, None
            case ast.Assign(targets=[ast.Name(id=name)]) | ast.AnnAssign(target=ast.Name(id=name)):
                return VALUE, name, None
        raise DeclarationError(f"unrecognized definition: {source.splitlines()[0]}")

    def split_imports(self, source: str) -> list[tuple[str, str]]:
        imports = []
        for node in _parse(source).body:
            for alias in node.names:
                if isinstance(node, ast.ImportFrom):
                    statement = f"from {node.module} import {alias.name}"
                    name = alias.asname or alias.name
                else:
                    statement = f"import {alias.name}"
                    name = alias.asname or alias.name.split(".")[0]
                if alias.asname and alias.asname != alias.name:
                    statement += f" as {alias.asname}"
                imports.append((name, statement))
        return imports

    def references(self, source: str) -> References:
        return _references(source)

    def rewrite(self, source: str, replace: Callable[[str], str | None]) -> str:
        lines = [line.encode() for line in source.split("\n")]
        edits = []
        for name, _ in _names(_parse(source)):
            replacement = replace(name.id)
            if replacement is not None:
                assert name.end_col_offset is not None
                edits.append((name.lineno - 1, name.col_offset, name.end_col_offset, replacement))
        for row, start, end, replacement in sorted(edits, reverse=True):
            lines[row] = lines[row][:start] + replacement.encode() + lines[row][end:]
        return "\n".join(line.decode() for line in lines)

    def shape(self, definition: Definition) -> str:
        node = _parse(definition.source).body[0]
        assert isinstance(node, ast.ClassDef)
        if any(_is_dataclass(decorator) for decorator in node.decorator_list):
            return RECORD
        if any(isinstance(statement, ast.AnnAssign) for statement in node.body):
            return STRUCTURE
        if all(isinstance(base, ast.Name) for base in node.bases) and not any(
            isinstance(statement, ast.Assign) for statement in node.body
        ):
            return SCALAR
        return COLLECTION

    def config_reference(self, name: str) -> str:
        return f"config.{name}"

    def variable(self, variable: Variable, value: str) -> str:
        if variable.kind == CONSTANT and value.startswith(("'", '"')):
            return f"{variable.name}: Final = {value}"
        return f"{variable.name} = {value}"

    def configuration(self, configs: list[tuple[str, str | Records]]) -> str:
        fields = "\n".join(f"    {name}: {_annotation(value)}" for name, value in configs)
        values = "\n".join(
            f"    {name}={_records(value) if isinstance(value, list) else value},"
            for name, value in configs
        )
        return (
            f"class Configuration(NamedTuple):\n{fields}\n\n\nconfig = Configuration(\n{values}\n)"
        )

    def protocol(self, name: str, methods: list[str]) -> str:
        body = [
            textwrap.indent(method.replace(f"self: {name}", "self", 1), "    ")
            for method in methods
        ]
        return f"class {name}(Protocol):\n" + "\n\n".join(body)

    def alias(self, name: str, module: str) -> str:
        return f"{name}: TypeAlias = {module}.{name}"

    def banner(self, title: str) -> str:
        return f"{'#' * 100}\n# {title}\n{'#' * 100}"

    def header(self, imports: list[str], spec: Spec, preset: str) -> str:
        ancestors = "\n".join(
            f"from ..{ancestor} import {preset} as {ancestor}" for ancestor in spec.lineage[:-1]
        )
        return "\n\n".join([*_import_lines(imports), ancestors]) + f'\n\n\nfork = "{spec.fork}"'

    def load(self, out: Path, fork: str, preset: str) -> object:
        package = str(out.resolve() / "specs")
        if eth_consensus_specs.__path__[0] != package:
            if package in eth_consensus_specs.__path__:
                eth_consensus_specs.__path__.remove(package)
            eth_consensus_specs.__path__.insert(0, package)
        return importlib.import_module(f"eth_consensus_specs.{fork}.{preset}")

    def lookup(self, module: object, variable: Variable) -> object:
        source = module.config if variable.kind == CONFIG else module
        return getattr(source, variable.name)

    def source(self, definition: Definition) -> str:
        node = _parse(definition.source).body[0]
        decorators = getattr(node, "decorator_list", [])
        start = min([node.lineno, *(decorator.lineno for decorator in decorators)])
        return "\n".join(definition.source.split("\n")[start - 1 : node.end_lineno])

    def split_expression(self, expression: str) -> tuple[str | None, str]:
        match = re.fullmatch(r"([A-Z]\w*)\((.*)\)", expression, re.DOTALL)
        if match is None:
            return None, expression
        return match.group(1), match.group(2)

    def literal(self, value: object, expression: object) -> str:
        if isinstance(value, tuple):
            lines = ["("]
            for record in value:
                lines.append("    frozendict({")
                lines.extend(
                    f'        "{key}": {self.literal(field, None)},'
                    for key, field in record.items()
                )
                lines.append("    }),")
            return "\n".join([*lines, ")"])
        if isinstance(value, bytes):
            return f'"{hex_text(value, expression)}"'
        if isinstance(value, str):
            return f'"{value}"'
        assert isinstance(value, int)
        return str(value)

    def constant_hint(self, expression: str) -> str | None:
        return "Final" if expression.startswith(("'", '"')) else None

    def records_type(self) -> str:
        return RECORDS_TYPE

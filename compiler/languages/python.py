import ast
import importlib
import re
import sys
import textwrap
from collections.abc import Callable, Iterator, Mapping
from functools import cache
from pathlib import Path

import eth_consensus_specs
from compiler.languages.base import Declaration, hex_text, Target
from compiler.model import (
    Definition,
    Kind,
    Records,
    References,
    Shape,
    Spec,
    SpecError,
    Variable,
)

CALL = re.compile(r"([A-Z]\w*)\((.*)\)", re.DOTALL)
RECORDS_TYPE = "tuple[frozendict[str, Any], ...]"


@cache
def _parse(source: str) -> ast.Module:
    try:
        return ast.parse(source)
    except SyntaxError as error:
        raise SpecError(f"invalid python: {error}") from None


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


def _is_string(value: object) -> bool:
    return isinstance(value, str) and value.startswith(("'", '"'))


def _split(value: str | Records) -> tuple[str | None, str]:
    if not isinstance(value, str):
        return RECORDS_TYPE, _records(value)
    match = CALL.fullmatch(value)
    return (None, value) if match is None else (match.group(1), match.group(2))


def _annotation(value: str | Records) -> str:
    return _split(value)[0] or ("str" if _is_string(value) else "int")


def _records(records: Records) -> str:
    if not records:
        return "()"
    lines = ["("]
    for record in records:
        lines.append("    frozendict({")
        lines.extend(f'        "{key}": {value},' for key, value in record.items())
        lines.append("    }),")
    return "\n".join([*lines, ")"])


def _imports(body: list[ast.stmt]) -> list[Declaration]:
    imports = []
    for node in body:
        assert isinstance(node, ast.Import | ast.ImportFrom)
        for alias in node.names:
            if isinstance(node, ast.ImportFrom):
                statement = f"from {node.module} import {alias.name}"
                name = alias.asname or alias.name
            else:
                statement = f"import {alias.name}"
                name = alias.asname or alias.name.split(".")[0]
            if alias.asname and alias.asname != alias.name:
                statement += f" as {alias.asname}"
            imports.append(Declaration(Kind.IMPORT, name, statement))
    return imports


def _import_lines(statements: list[str]) -> list[str]:
    modules: dict[str, list[str]] = {}
    for statement in statements:
        node = _parse(statement).body[0]
        assert isinstance(node, ast.Import | ast.ImportFrom)
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


class Python(Target):
    name = "python"
    extension = "py"
    separator = "\n\n\n"
    banner = f"{'#' * 100}\n# {{}}\n{'#' * 100}"
    alias = "{name}: TypeAlias = {module}.{name}"
    config_reference = "config.{}"
    foreign_import = "from eth_consensus_specs.utils.foreign import call_foreign"

    def declarations(self, source: str) -> list[Declaration]:
        body = _parse(source).body
        if body and all(isinstance(node, ast.Import | ast.ImportFrom) for node in body):
            return _imports(body)
        if len(body) != 1:
            raise SpecError(f"expected one definition per code block, found {len(body)}")
        receiver = None
        match body[0]:
            case ast.FunctionDef(name=name, args=ast.arguments(args=[first, *_])) if (
                first.arg == "self" and isinstance(first.annotation, ast.Name)
            ):
                kind, receiver = Kind.METHOD, first.annotation.id
            case ast.FunctionDef(name=name):
                kind = Kind.FUNCTION
            case ast.Assign(targets=[ast.Name(id=name)], value=value) if any(
                isinstance(node, ast.Name) and node.id == name for node in ast.walk(value)
            ):
                kind = Kind.WRAPPER
            case ast.ClassDef(name=name):
                kind = Kind.TYPE
            case ast.Assign(targets=[ast.Name(id=name)]) | ast.AnnAssign(target=ast.Name(id=name)):
                kind = Kind.VALUE
            case _:
                raise SpecError(f"unrecognized definition: {source.splitlines()[0]}")
        return [Declaration(kind, name, source, receiver)]

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

    def shape(self, definition: Definition) -> Shape:
        node = _parse(definition.source).body[0]
        assert isinstance(node, ast.ClassDef)
        if any(_is_dataclass(decorator) for decorator in node.decorator_list):
            return Shape.DATACLASS
        if any(isinstance(statement, ast.AnnAssign) for statement in node.body):
            return Shape.CONTAINER
        if all(isinstance(base, ast.Name) for base in node.bases) and not any(
            isinstance(statement, ast.Assign) for statement in node.body
        ):
            return Shape.SCALAR
        return Shape.COLLECTION

    def expression(self, value: str | Records) -> str:
        return value if isinstance(value, str) else _records(value)

    def variable(self, variable: Variable, value: str) -> str:
        if variable.kind == Kind.CONSTANT and _is_string(value):
            return f"{variable.name}: Final = {value}"
        return f"{variable.name} = {value}"

    def configuration(self, configs: list[tuple[str, str | Records]]) -> str:
        fields = "\n".join(f"    {name}: {_annotation(value)}" for name, value in configs)
        values = "\n".join(
            f"    {name}={textwrap.indent(self.expression(value), '    ').lstrip()},"
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

    def header(self, imports: list[str], spec: Spec, preset: str) -> str:
        ancestors = "\n".join(
            f"from ..{ancestor} import {preset} as {ancestor}" for ancestor in spec.lineage[:-1]
        )
        sections = [*_import_lines(imports), ancestors]
        return "\n\n".join(filter(None, sections)) + f'\n\n\nfork = "{spec.fork}"'

    def foreign_function(
        self,
        definition: Definition,
        parameters: list[tuple[str, str]],
        result: str,
        preset: str,
    ) -> str:
        names = ", ".join(name for name, _ in parameters)
        typed = ", ".join(f"{name}: {kind}" for name, kind in parameters)
        location = f"{definition.fork}/{preset}"
        return (
            f"def {definition.name}({typed}) -> {result}:\n"
            f'    return call_foreign("{definition.lang}", "{location}", "{definition.name}", '
            f"{result}, {names})"
        )

    def write(self, out: Path, spec: Spec) -> Path:
        directory = super().write(out, spec)
        (directory / "__init__.py").write_text("from . import mainnet as spec  # noqa:F401\n")
        return directory

    def write_forks(self, out: Path, parents: dict[str, str | None]) -> None:
        graph = "\n".join(f"    {name!r}: {parent!r}," for name, parent in parents.items())
        (out / "specs" / "forks.py").write_text(f"PREVIOUS_FORK_OF = {{\n{graph}\n}}\n")

    def load(self, out: Path, fork: str, preset: str) -> Mapping[str, object]:
        package = str(out.resolve() / "specs")
        paths = eth_consensus_specs.__path__
        paths[:] = [package, *(path for path in paths if path != package)]
        module = importlib.import_module(f"eth_consensus_specs.{fork}.{preset}")
        return {**vars(module), **module.config._asdict()}

    def source(self, definition: Definition) -> str:
        node = _parse(definition.source).body[0]
        decorators = getattr(node, "decorator_list", [])
        start = min([node.lineno, *(decorator.lineno for decorator in decorators)])
        return "\n".join(definition.source.split("\n")[start - 1 : node.end_lineno])

    def split_expression(self, value: str | Records) -> tuple[str | None, str]:
        return _split(value)

    def literal(self, value: object, expression: str) -> str:
        if isinstance(value, tuple):
            fields = [{key: self.literal(field, "") for key, field in row.items()} for row in value]
            return _records(fields)
        if isinstance(value, bytes):
            return f'"{hex_text(value, expression)}"'
        if isinstance(value, str):
            return f'"{value}"'
        assert isinstance(value, int)
        return str(value)

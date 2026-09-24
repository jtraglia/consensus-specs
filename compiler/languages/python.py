import ast
import textwrap
from collections.abc import Callable, Iterator
from functools import cache

from compiler.discover import SpecError
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
)
from compiler.order import ALIAS, CONFIGURATION, Node, PROTOCOL, VARIABLE

RECORDS_TYPE = "tuple[frozendict[str, Any], ...]"


class DeclarationError(SpecError):
    pass


@cache
def _parse(source: str) -> ast.Module:
    try:
        return ast.parse(source)
    except SyntaxError as error:
        raise DeclarationError(f"invalid python: {error}") from None


def read_declaration(source: str) -> tuple[str, str, str | None]:
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
        case ast.ClassDef(name=name):
            return TYPE, name, None
        case ast.Assign(targets=[ast.Name(id=name)]) | ast.AnnAssign(target=ast.Name(id=name)):
            return VALUE, name, None
    raise DeclarationError(f"unrecognized definition: {source.splitlines()[0]}")


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
def references(source: str) -> tuple[frozenset[str], frozenset[str]]:
    eager: set[str] = set()
    lazy: set[str] = set()
    for name, deferred in _names(_parse(source)):
        (lazy if deferred else eager).add(name.id)
    return frozenset(eager), frozenset(lazy)


def rewrite(source: str, replace: Callable[[str], str | None]) -> str:
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


def _annotation(value: str | Records) -> str:
    if isinstance(value, list):
        return RECORDS_TYPE
    match _parse(value).body:
        case [ast.Expr(value=ast.Call(func=ast.Name(id=name)))]:
            return name
        case [ast.Expr(value=ast.Constant(value=str()))]:
            return "str"
    return "int"


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


class Emitter:
    def __init__(self, fork: str, lineage: tuple[str, ...], preset: str) -> None:
        self.fork = fork
        self.lineage = lineage
        self.preset = preset
        self.configs: dict[str, Variable] = {}

    def to_config(self, name: str) -> str | None:
        return f"config.{name}" if name in self.configs else None

    def config_value(self, name: str, seen: tuple[str, ...] = ()) -> str | Records:
        if name in seen:
            raise DeclarationError(f"configs reference each other: {' -> '.join((*seen, name))}")
        value = self.configs[name].values[self.preset]
        if isinstance(value, list):
            return value

        def inline(reference: str) -> str | None:
            if reference not in self.configs:
                return None
            inner = self.config_value(reference, (*seen, name))
            return f"({inner})" if isinstance(inner, str) else _records(inner)

        return rewrite(value, inline)

    def variable(self, variable: Variable) -> str:
        value = variable.values[self.preset]
        assert isinstance(value, str)
        value = rewrite(value, self.to_config)
        if variable.kind == CONSTANT and value.startswith(("'", '"')):
            return f"{variable.name}: Final = {value}"
        return f"{variable.name} = {value}"

    def configuration(self) -> str:
        fields = "\n".join(
            f"    {name}: {_annotation(variable.values[self.preset])}"
            for name, variable in self.configs.items()
        )
        values = []
        for name in self.configs:
            value = self.config_value(name)
            values.append(f"    {name}={_records(value) if isinstance(value, list) else value},")
        return (
            f"class Configuration(NamedTuple):\n{fields}\n\n\n"
            f"config = Configuration(\n" + "\n".join(values) + "\n)"
        )

    def definition(self, definition: Definition) -> str:
        return rewrite(definition.source, self.to_config)

    def protocol(self, name: str, methods: list[Definition]) -> str:
        body = []
        for method in methods:
            source = self.definition(method).replace(f"self: {name}", "self", 1)
            body.append(textwrap.indent(source, "    "))
        return f"class {name}(Protocol):\n" + "\n\n".join(body)

    def alias(self, name: str, module: str) -> str:
        return f"{name}: TypeAlias = {module}.{name}"

    def module(self, imports: list[str], blocks: list[str]) -> str:
        text = "\n\n\n".join(blocks)
        ancestors = [
            f"from eth_consensus_specs.{ancestor} import {self.preset} as {ancestor}"
            for ancestor in self.lineage[:-1]
        ]
        header = "\n\n".join([*imports, "\n".join(ancestors)]) + f"\n\n\nfork = '{self.fork}'"
        return header + "\n\n\n" + text + "\n"


def render(spec: Spec, nodes: list[Node], preset: str) -> str:
    emitter = Emitter(spec.fork, spec.lineage, preset)
    emitter.configs = {
        key: item
        for key, item in spec.items.items()
        if isinstance(item, Variable) and item.kind == CONFIG
    }
    blocks = []
    for node in nodes:
        for item in node.items:
            if isinstance(item, Definition) and item.lang != "python":
                raise DeclarationError(f"{item.path}: cannot emit `{item.name}` from {item.lang}")
        if node.kind == ALIAS:
            blocks.append(emitter.alias(node.key, spec.lineage[-2]))
        elif node.kind == CONFIGURATION:
            blocks.append(emitter.configuration())
        elif node.kind == PROTOCOL:
            blocks.append(emitter.protocol(node.key, node.items))
        elif node.kind == VARIABLE:
            blocks.extend(emitter.variable(item) for item in node.items)
        else:
            blocks.extend(emitter.definition(item) for item in node.items)
    imports = [
        item.source
        for item in spec.items.values()
        if isinstance(item, Definition) and item.kind == IMPORT
    ]
    return emitter.module(imports, blocks)

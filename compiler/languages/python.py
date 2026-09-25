import ast
import re
import textwrap
from collections.abc import Callable, Iterator
from functools import cache
from types import ModuleType

from compiler.discover import SpecError
from compiler.emit_yaml import hex_text
from compiler.model import (
    CONFIG,
    CONSTANT,
    Definition,
    FUNCTION,
    IMPORT,
    METHOD,
    PRESET,
    Records,
    Spec,
    TYPE,
    VALUE,
    Variable,
    WRAPPER,
)
from compiler.order import (
    ALIAS,
    CONFIGURATION,
    CONSTANTS,
    CONTAINER,
    DATACLASS,
    Node,
    PRESETS,
    PROTOCOL,
    TITLES,
    TYPE as TYPE_GROUP,
)

RECORDS_TYPE = "tuple[frozendict[str, Any], ...]"
SPEC_FIELDS = (
    "functions",
    "types",
    "constants",
    "presets",
    "configs",
    "containers",
    "dataclasses",
)


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
        case ast.Assign(targets=[ast.Name(id=name)], value=value) if any(
            isinstance(node, ast.Name) and node.id == name for node in ast.walk(value)
        ):
            return WRAPPER, name, None
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
        for name, variable in self.configs.items():
            value = variable.values[self.preset]
            if isinstance(value, list):
                values.append(f"    {name}={_records(value)},")
                continue
            if others := references(value)[0] & self.configs.keys():
                raise DeclarationError(
                    f"{variable.path}: config `{name}` must not reference other configs: "
                    f"{', '.join(sorted(others))}"
                )
            values.append(f"    {name}={value},")
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

    def module(self, imports: list[str], blocks: list[tuple[str, str]]) -> str:
        text = ""
        previous = None
        for group, block in blocks:
            if previous is None or group != previous[0]:
                if previous is not None:
                    text += "\n\n\n"
                text += f"{'#' * 100}\n# {TITLES[group]}\n{'#' * 100}\n\n\n"
            elif "\n" not in block and "\n" not in previous[1]:
                text += "\n"
            else:
                text += "\n\n\n"
            text += block
            previous = (group, block)
        ancestors = [
            f"from ..{ancestor} import {self.preset} as {ancestor}"
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
    blocks: list[tuple[str, str]] = []
    for node in nodes:
        for item in node.items:
            if isinstance(item, Definition) and item.lang != "python":
                raise DeclarationError(f"{item.path}: cannot emit `{item.name}` from {item.lang}")
        if node.group == ALIAS:
            texts = [emitter.alias(node.key, spec.lineage[-2])]
        elif node.group == CONFIGURATION:
            texts = [emitter.configuration()]
        elif node.group == PROTOCOL:
            texts = [emitter.protocol(node.key, node.items)]
        elif node.group in (CONSTANTS, PRESETS):
            texts = [emitter.variable(item) for item in node.items if isinstance(item, Variable)]
        else:
            texts = [
                emitter.definition(item) for item in node.items if isinstance(item, Definition)
            ]
        blocks.extend((node.group, text) for text in texts)
    imports = [
        item.source
        for item in spec.items.values()
        if isinstance(item, Definition) and item.kind == IMPORT
    ]
    return emitter.module(imports, blocks)


def _split(expression: str) -> tuple[str | None, str]:
    match = re.fullmatch(r"([A-Z]\w*)\((.*)\)", expression, re.DOTALL)
    if match is None:
        return None, expression
    return match.group(1), match.group(2)


def _literal(value: object, expression: object = None) -> str:
    if isinstance(value, tuple):
        lines = ["("]
        for record in value:
            lines.append("    frozendict({")
            lines.extend(f'        "{key}": {_literal(field)},' for key, field in record.items())
            lines.append("    }),")
        return "\n".join([*lines, ")"])
    if isinstance(value, bytes):
        return f"'{hex_text(value, expression)}'"
    if isinstance(value, str):
        return f"'{value}'"
    assert isinstance(value, int)
    return str(int(value))


def _node_source(source: str) -> str:
    node = _parse(source).body[0]
    decorators = getattr(node, "decorator_list", [])
    start = min([node.lineno, *(decorator.lineno for decorator in decorators)])
    return "\n".join(source.split("\n")[start - 1 : node.end_lineno])


def _is_dataclass(decorator: ast.expr) -> bool:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    return isinstance(target, ast.Name) and target.id == "dataclass"


def _type_field(source: str) -> str:
    node = _parse(source).body[0]
    assert isinstance(node, ast.ClassDef)
    if any(_is_dataclass(decorator) for decorator in node.decorator_list):
        return "dataclasses"
    if any(isinstance(statement, ast.AnnAssign) for statement in node.body):
        return "containers"
    return "types"


def spec_object(spec: Spec, preset: str, module: ModuleType) -> dict[str, dict]:
    result: dict[str, dict] = {field: {} for field in SPEC_FIELDS}
    for key, item in spec.items.items():
        if isinstance(item, Variable):
            expression = item.values[preset]
            if item.kind == CONSTANT:
                assert isinstance(expression, str)
                type_name, value = _split(expression)
                hint = "Final" if expression.startswith(("'", '"')) else None
                result["constants"][key] = [type_name, value, None, hint]
            elif item.kind == PRESET:
                assert isinstance(expression, str)
                value = _literal(getattr(module, key), expression)
                result["presets"][key] = [_split(expression)[0], value, None, None]
            else:
                value = _literal(getattr(module.config, key), expression)
                type_name = RECORDS_TYPE if isinstance(expression, list) else _split(expression)[0]
                result["configs"][key] = [type_name, value, None, None]
        elif item.kind == FUNCTION:
            result["functions"][key] = _node_source(item.source)
        elif item.kind == TYPE:
            result[_type_field(item.source)][item.name] = _node_source(item.source)
    return result


def classify(definition: Definition) -> str:
    field = _type_field(definition.source)
    if field == "dataclasses":
        return DATACLASS
    node = _parse(definition.source).body[0]
    assert isinstance(node, ast.ClassDef)
    scalar = all(isinstance(base, ast.Name) for base in node.bases) and not any(
        isinstance(statement, ast.Assign | ast.AnnAssign) for statement in node.body
    )
    return TYPE_GROUP if scalar else CONTAINER

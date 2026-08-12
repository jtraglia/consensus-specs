"""Emit one Python module from a Spec."""

from __future__ import annotations

import ast
import re
import textwrap
from typing import TYPE_CHECKING

from compiler.models import Spec, Value

if TYPE_CHECKING:
    from compiler.discover import Fork
    from compiler.removals import Removals

HOISTED = ("ceillog2", "floorlog2")
SCALAR_BASES = frozenset(
    {
        "Boolean",
        "Byte",
        "Bytes1",
        "Bytes4",
        "Bytes8",
        "Bytes20",
        "Bytes31",
        "Bytes32",
        "Bytes48",
        "Bytes96",
        "Uint8",
        "Uint16",
        "Uint32",
        "Uint64",
        "Uint128",
        "Uint256",
    }
)
LATE_BASES = frozenset({"Exception", "BaseException"})


def emit_python(
    *,
    spec: Spec,
    fork: Fork,
    forks: dict[str, Fork],
    preset_name: str,
    removals: Removals,
) -> str:
    spec = _apply_removals(spec, removals)
    methods, functions = _split_protocol_methods(spec.functions)
    hoisted = [functions.pop(name) for name in HOISTED if name in functions]
    aliases, types, late = _split_classes(spec.classes, methods)
    late_src = "\n\n\n".join(late.values())
    function_src = "\n\n\n".join(functions.values())

    for name in spec.configs:
        function_src = _rewrite_config_name(function_src, name)
        types = {key: _rewrite_config_name(source, name) for key, source in types.items()}
        late_src = _rewrite_config_name(late_src, name)

    gindices, constants, after_presets = _partition_constants(spec.constants, spec.presets)
    preset_src, deferred_presets, preset_asserts = _emit_presets(spec.presets, preset_name)
    early_types, late_types = _split_deferred_types(types, deferred_presets)

    parts = [
        _imports(fork, forks, preset_name),
        f"fork = '{fork.name}'\n",
        "\n\n\n".join(hoisted),
        "\n".join(gindices),
        "\n\n\n".join(aliases.values()),
        "\n".join(constants),
        preset_src,
        "\n".join(after_presets),
        _emit_config(preset_name, spec.configs),
        "\n\n\n".join(early_types.values()),
        "\n".join(deferred_presets.values()),
        "\n\n\n".join(late_types.values()),
        _emit_protocols(methods),
        function_src,
        late_src,
        "\n\n\n".join(spec.assignments.values()),
        "\n".join(preset_asserts),
    ]
    return "\n\n\n".join(part.strip("\n") for part in parts if part) + "\n"


def _apply_removals(spec: Spec, removals: Removals) -> Spec:
    return Spec(
        functions={
            key: source
            for key, source in spec.functions.items()
            if key not in removals.functions and key.rsplit(".", 1)[-1] not in removals.functions
        },
        classes={k: v for k, v in spec.classes.items() if k not in removals.classes},
        assignments=spec.assignments,
        constants={k: v for k, v in spec.constants.items() if k not in removals.constants},
        presets={k: v for k, v in spec.presets.items() if k not in removals.presets},
        configs=spec.configs,
    )


def _split_protocol_methods(
    functions: dict[str, str],
) -> tuple[dict[str, dict[str, str]], dict[str, str]]:
    """Functions written as ``def foo(self: Engine, ...)`` become Protocol methods."""
    methods: dict[str, dict[str, str]] = {}
    leftover: dict[str, str] = {}
    for name, source in functions.items():
        owner = _self_annotation(source)
        if owner is None:
            leftover[name] = source
        else:
            method = name.rsplit(".", 1)[-1]
            methods.setdefault(owner, {})[method] = source.replace(f"self: {owner}", "self")
    return methods, leftover


def _self_annotation(source: str) -> str | None:
    module = ast.parse(source)
    fn = module.body[0]
    if not isinstance(fn, ast.FunctionDef) or not fn.args.args:
        return None
    first = fn.args.args[0]
    if (
        first.arg != "self"
        or first.annotation is None
        or not isinstance(first.annotation, ast.Name)
    ):
        return None
    return first.annotation.id


def _split_classes(
    classes: dict[str, str],
    methods: dict[str, dict[str, str]],
) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    aliases: dict[str, str] = {}
    types: dict[str, str] = {}
    late: dict[str, str] = {}
    protocol_names = set(methods)
    for name, source in classes.items():
        parent = _class_parent(source)
        if parent in SCALAR_BASES and _is_bare_alias(source):
            aliases[name] = source
        elif parent in LATE_BASES or parent in protocol_names:
            late[name] = source
        else:
            types[name] = source
    return aliases, types, late


def _class_parent(source: str) -> str | None:
    module = ast.parse(source)
    cls = next((node for node in module.body if isinstance(node, ast.ClassDef)), None)
    if cls is None or not cls.bases:
        return None
    base = cls.bases[0]
    if isinstance(base, ast.Name):
        return base.id
    if isinstance(base, ast.Subscript):
        return base.value.id
    if isinstance(base, ast.Call):
        return base.func.id
    return None


def _is_bare_alias(source: str) -> bool:
    """True for ``class Slot(Uint64):`` with no LIMIT/LENGTH body bindings."""
    module = ast.parse(source)
    cls = module.body[0]
    assert isinstance(cls, ast.ClassDef)
    return not any(isinstance(node, ast.Assign) for node in cls.body)


def _partition_constants(
    constants: dict[str, Value],
    presets: dict[str, Value],
) -> tuple[list[str], list[str], list[str]]:
    """Gindex constants go first; anything that names a preset waits until after presets."""
    gindices: list[str] = []
    plain: list[str] = []
    after_presets: list[str] = []
    preset_names = list(presets)
    for name, value in constants.items():
        expr = value.mainnet
        if "get_generalized_index" in expr:
            if value.annotation_mainnet is None:
                raise ValueError(f"{name}: get_generalized_index needs an (= N) annotation")
            gindices.append(f"{name} = GeneralizedIndex({value.annotation_mainnet})")
        elif any(preset in expr for preset in preset_names):
            after_presets.append(_assignment(name, expr))
        else:
            plain.append(_assignment(name, expr))
    return gindices, plain, after_presets


def _emit_presets(
    presets: dict[str, Value], preset_name: str
) -> tuple[str, dict[str, str], list[str]]:
    lines: list[str] = []
    deferred: dict[str, str] = {}
    env: dict[str, int] = {}
    pending: list[tuple[str, str]] = []
    for name, value in presets.items():
        expr = value.select(preset_name)
        if "get_generalized_index" in expr:
            deferred[name] = _assignment(name, expr)
        elif any(other != name and other in expr for other in presets):
            pending.append((name, expr))
        else:
            lines.append(_assignment(name, expr))
            number = _literal_int(expr)
            if number is not None:
                env[name] = number
    for name, expr in pending:
        type_name, inner = _split_type(expr)
        try:
            number = int(eval(inner, {"__builtins__": {}}, env))
        except Exception:
            lines.append(_assignment(name, expr))
            continue
        lines.append(f"{name} = {type_name}({number})" if type_name else f"{name} = {number}")
        env[name] = number
    simple = "# Presets\n" + "\n".join(lines) if lines else ""
    return simple, deferred, []


def _literal_int(expression: str) -> int | None:
    _, inner = _split_type(expression)
    try:
        result = eval(inner, {"__builtins__": {}}, {})
    except Exception:
        return None
    if isinstance(result, (int, float)):
        return int(result)
    return None


def _split_deferred_types(
    types: dict[str, str], deferred: dict[str, str]
) -> tuple[dict[str, str], dict[str, str]]:
    """Types that name a deferred preset (or another late type) come after those assignments."""
    if not deferred:
        return types, {}
    late_names = set(deferred)
    changed = True
    while changed:
        changed = False
        for name, source in types.items():
            if name in late_names:
                continue
            if any(re.search(rf"\b{re.escape(dep)}\b", source) for dep in late_names):
                late_names.add(name)
                changed = True
    early = {name: source for name, source in types.items() if name not in late_names}
    late = {name: source for name, source in types.items() if name in late_names}
    return early, late


def _assignment(name: str, expression: str) -> str:
    if name == "ENDIANNESS":
        return f"{name}: Final = {expression}"
    type_name, inner = _split_type(expression)
    if type_name is None:
        return f"{name} = {expression}"
    return f"{name} = {type_name}({inner})"


def _split_type(expression: str) -> tuple[str | None, str]:
    expression = expression.strip()
    if "(" not in expression or not expression.endswith(")"):
        return None, expression
    index = expression.index("(")
    type_name = expression[:index]
    if not type_name or not type_name[0].isupper():
        return None, expression
    return type_name, expression[index + 1 : -1]


def _emit_config(preset_name: str, configs: dict[str, Value]) -> str:
    fields = ["    PRESET_BASE: str"]
    values = [f'    PRESET_BASE="{preset_name}",']
    for name, value in configs.items():
        records = value.records(preset_name)
        if records is not None:
            fields.append(f"    {name}: tuple[frozendict[str, Any], ...]")
            values.append(f"    {name}={value.select(preset_name)},")
            continue
        expr = value.select(preset_name)
        type_name, inner = _split_type(expr)
        fields.append(f"    {name}: {type_name or 'int'}")
        rhs = expr if type_name is None else f"{type_name}({inner})"
        values.append(f"    {name}={rhs},")
    return (
        "class Configuration(NamedTuple):\n"
        + "\n".join(fields)
        + "\n\n\nconfig = Configuration(\n"
        + "\n".join(values)
        + "\n)\n"
    )


def _emit_protocols(methods: dict[str, dict[str, str]]) -> str:
    chunks = []
    for name, fns in methods.items():
        block = f"class {name}(Protocol):"
        for source in fns.values():
            block += "\n\n" + textwrap.indent(source, "    ")
        chunks.append(block)
    return "\n\n\n".join(chunks)


def _imports(fork: Fork, forks: dict[str, Fork], preset_name: str) -> str:
    lines = ["from eth_consensus_specs.runtime import *"]
    for ancestor in reversed(fork.ancestors(forks)):
        if ancestor.previous is not None:
            lines.append(
                f"from eth_consensus_specs.{ancestor.previous} "
                f"import {preset_name} as {ancestor.previous}"
            )
    return "\n\n".join(lines) + "\n"


def _rewrite_config_name(source: str, name: str) -> str:
    return re.sub(rf"(?<!['\"])\b{name}\b(?!['\"])", "config." + name, source)

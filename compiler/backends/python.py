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
    yaml_presets: dict[str, str],
    yaml_configs: dict[str, str | list],
    inherited: dict[str, str],
    removals: Removals,
) -> str:
    spec = _apply_removals(spec, removals)
    methods, functions = _split_protocol_methods(spec.functions)
    hoisted = [functions.pop(name) for name in HOISTED if name in functions]
    aliases, types, late = _split_classes(spec.classes, methods)

    def render_class(name: str, source: str) -> str:
        if name in inherited:
            return f"{name}: TypeAlias = {inherited[name]}.{name}"
        return source

    alias_src = "\n\n\n".join(render_class(n, s) for n, s in aliases.items())
    type_src = "\n\n\n".join(render_class(n, s) for n, s in types.items())
    late_src = "\n\n\n".join(late.values())
    function_src = "\n\n\n".join(functions.values())

    for name in spec.configs:
        function_src = _rewrite_config_name(function_src, name)
        type_src = _rewrite_config_name(type_src, name)
        late_src = _rewrite_config_name(late_src, name)

    gindices, constants, after_presets, gindex_asserts = _partition_constants(
        spec.constants, spec.presets
    )
    preset_src, preset_asserts = _emit_presets(spec.presets, yaml_presets)

    parts = [
        _imports(fork, forks, preset_name),
        f"fork = '{fork.name}'\n",
        "\n\n\n".join(hoisted),
        "\n".join(gindices),
        alias_src,
        "\n".join(constants),
        preset_src,
        "\n".join(after_presets),
        _emit_config(preset_name, spec.configs, yaml_configs),
        type_src,
        _emit_protocols(methods),
        function_src,
        late_src,
        "\n\n\n".join(spec.assignments.values()),
        "\n".join(gindex_asserts),
        "\n".join(preset_asserts),
    ]
    return "\n\n\n".join(part.strip("\n") for part in parts if part) + "\n"


def _apply_removals(spec: Spec, removals: Removals) -> Spec:
    return Spec(
        functions={k: v for k, v in spec.functions.items() if k not in removals.functions},
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
            methods.setdefault(owner, {})[name] = source.replace(f"self: {owner}", "self")
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
) -> tuple[list[str], list[str], list[str], list[str]]:
    """Gindex constants go first; anything that names a preset waits until after presets."""
    gindices: list[str] = []
    plain: list[str] = []
    after_presets: list[str] = []
    asserts: list[str] = []
    preset_names = list(presets)
    for name, value in constants.items():
        if "get_generalized_index" in value.expression:
            if value.annotation is None:
                raise ValueError(f"{name}: get_generalized_index needs an (= N) annotation")
            gindices.append(f"{name} = GeneralizedIndex({value.annotation})")
            asserts.append(f"assert {name} == {value.expression}")
        elif any(preset in value.expression for preset in preset_names):
            after_presets.append(_assignment(name, value))
        else:
            plain.append(_assignment(name, value))
    return gindices, plain, after_presets, asserts


def _emit_presets(presets: dict[str, Value], yaml_presets: dict[str, str]) -> tuple[str, list[str]]:
    lines: list[str] = []
    asserts: list[str] = []
    for name, value in presets.items():
        if "get_generalized_index" in value.expression:
            rhs = yaml_presets.get(name)
            if rhs is None:
                if value.annotation is None:
                    raise ValueError(f"{name}: computed preset needs YAML or (= N)")
                rhs = str(value.annotation)
            type_name, _ = _split_type(value.expression)
            lines.append(f"{name} = {type_name}({rhs})" if type_name else f"{name} = {rhs}")
            asserts.append(f"assert {name} == {value.expression}  # noqa: E501")
        elif name in yaml_presets:
            type_name, _ = _split_type(value.expression)
            rhs = yaml_presets[name]
            lines.append(f"{name} = {type_name}({rhs})" if type_name else f"{name} = {rhs}")
        else:
            lines.append(_assignment(name, value))
    if not lines:
        return "", asserts
    return "# Presets\n" + "\n".join(lines), asserts


def _assignment(name: str, value: Value) -> str:
    if name == "ENDIANNESS":
        return f"{name}: Final = {value.expression}"
    type_name, inner = _split_type(value.expression)
    if type_name is None:
        return f"{name} = {value.expression}"
    return f"{name} = {type_name}({inner})"


def _split_type(expression: str) -> tuple[str | None, str]:
    expression = expression.strip()
    if "(" not in expression or not expression.endswith(")"):
        return None, expression
    index = expression.index("(")
    return expression[:index], expression[index + 1 : -1]


def _emit_config(
    preset_name: str,
    configs: dict[str, Value],
    yaml_configs: dict[str, str | list],
) -> str:
    fields = ["    PRESET_BASE: str"]
    values = [f'    PRESET_BASE="{preset_name}",']
    for name, value in configs.items():
        yaml_value = yaml_configs.get(name)
        if value.expression.startswith("("):
            fields.append("    " + f"{name}: tuple[frozendict[str, Any], ...]")
            values.append(f"    {name}={value.expression},")
            continue
        type_name, inner = _split_type(value.expression)
        fields.append(f"    {name}: {type_name or 'int'}")
        if isinstance(yaml_value, str):
            rhs = f"{type_name}({yaml_value})" if type_name else yaml_value
        else:
            rhs = value.expression if type_name is None else f"{type_name}({inner})"
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

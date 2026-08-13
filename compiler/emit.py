"""Emit Python modules and YAML from a Spec."""

from __future__ import annotations

import ast
import importlib
import re
import sys
import textwrap
from typing import TYPE_CHECKING

from ruamel.yaml import YAML

if TYPE_CHECKING:
    from pathlib import Path

    from compiler.discover import Fork
    from compiler.models import Removals, Spec, Value

TYPE_RE = re.compile(r"^([A-Z_]\w*)\((.*)\)$")
CONFIG_NAME_RE = r"(?<!['\"])\b{name}\b(?!['\"])"
WORD_RE = r"\b{name}\b"


class Emitter:
    def __init__(
        self,
        spec: Spec,
        fork: Fork,
        forks: dict[str, Fork],
        preset: str,
        removals: Removals,
    ) -> None:
        self.spec = spec.without(removals)
        self.fork = fork
        self.forks = forks
        self.preset = preset
        self.methods: dict[str, dict[str, str]] = {}
        self.functions: dict[str, str] = {}
        for name, source in self.spec.functions.items():
            owner = self_type(source)
            if owner is None:
                self.functions[name] = source
            else:
                method = name.rsplit(".", 1)[-1]
                self.methods.setdefault(owner, {})[method] = source.replace(
                    f"self: {owner}", "self"
                )

    def render(self) -> str:
        types = order_types(self.spec.types)
        protocols = set(self.methods)
        implementers = {
            name: source for name, source in types.items() if base_name(source) in protocols
        }
        types = {name: source for name, source in types.items() if name not in implementers}
        constants, after_presets, deferred = self._constants()
        preset_src, more_deferred = self._presets()
        deferred.update(more_deferred)
        hoist = self._referenced_functions(
            [
                *self.spec.aliases.values(),
                *constants,
                preset_src,
                *after_presets,
                *types.values(),
                *deferred.values(),
            ]
        )
        remaining = {name: src for name, src in self.functions.items() if name not in hoist}
        early, late = split_by_deps(types, deferred)
        parts = [
            self._imports(),
            f"fork = '{self.fork.name}'\n",
            "\n\n\n".join(self.spec.aliases.values()),
            "\n".join(constants),
            preset_src,
            "\n".join(after_presets),
            self._config(),
            "\n\n\n".join(self._qualify_configs(src) for src in hoist.values()),
            "\n\n\n".join(self._qualify_configs(src) for src in early.values()),
            "\n".join(deferred.values()),
            "\n\n\n".join(self._qualify_configs(src) for src in late.values()),
            self._protocols(),
            self._qualify_configs("\n\n\n".join(remaining.values())),
            "\n\n\n".join(self._qualify_configs(src) for src in implementers.values()),
            "\n\n\n".join(self.spec.instances.values()),
        ]
        return "\n\n\n".join(part.strip("\n") for part in parts if part) + "\n"

    def _referenced_functions(self, sources: list[str]) -> dict[str, str]:
        used: dict[str, str] = {}
        for source in sources:
            for name, fn in self.functions.items():
                if name not in used and re.search(WORD_RE.format(name=re.escape(name)), source):
                    used[name] = fn
        return used

    def _constants(self) -> tuple[list[str], list[str], dict[str, str]]:
        type_names = set(self.spec.types)
        presets = list(self.spec.presets)
        plain: list[str] = []
        after: list[str] = []
        deferred: dict[str, str] = {}
        for name, expr in self.spec.constants.items():
            if references(expr, type_names):
                deferred[name] = assign(name, expr)
            elif any(preset in expr for preset in presets):
                after.append(assign(name, expr))
            else:
                plain.append(assign(name, expr))
        return plain, after, deferred

    def _presets(self) -> tuple[str, dict[str, str]]:
        type_names = set(self.spec.types)
        lines: list[str] = []
        deferred: dict[str, str] = {}
        env: dict[str, int] = {}
        pending: list[tuple[str, str]] = []
        names = self.spec.presets
        for name, value in names.items():
            expr = value.select(self.preset)
            if references(expr, type_names):
                deferred[name] = assign(name, expr)
            elif any(other != name and other in expr for other in names):
                pending.append((name, expr))
            else:
                lines.append(assign(name, expr))
                number = literal_int(expr)
                if number is not None:
                    env[name] = number
        for name, expr in pending:
            kind, inner = split_type(expr)
            try:
                number = int(eval(inner, {"__builtins__": {}}, env))
            except Exception:
                lines.append(assign(name, expr))
                continue
            lines.append(f"{name} = {kind}({number})" if kind else f"{name} = {number}")
            env[name] = number
        header = "# Presets\n" + "\n".join(lines) if lines else ""
        return header, deferred

    def _config(self) -> str:
        fields = ["    PRESET_BASE: str"]
        values = [f'    PRESET_BASE="{self.preset}",']
        for name, value in self.spec.configs.items():
            chosen = value.select(self.preset)
            if isinstance(chosen, list):
                fields.append(f"    {name}: tuple[frozendict[str, Any], ...]")
                values.append(f"    {name}={format_records(chosen)},")
                continue
            expr = chosen
            kind, inner = split_type(expr)
            fields.append(f"    {name}: {kind or 'int'}")
            values.append(f"    {name}={expr if kind is None else f'{kind}({inner})'},")
        return (
            "class Configuration(NamedTuple):\n"
            + "\n".join(fields)
            + "\n\n\nconfig = Configuration(\n"
            + "\n".join(values)
            + "\n)\n"
        )

    def _protocols(self) -> str:
        chunks = []
        for name, fns in self.methods.items():
            block = f"class {name}(Protocol):"
            for source in fns.values():
                block += "\n\n" + textwrap.indent(source, "    ")
            chunks.append(block)
        return "\n\n\n".join(chunks)

    def _imports(self) -> str:
        lines = ["from eth_consensus_specs.runtime import *"]
        for ancestor in reversed(self.fork.ancestors(self.forks)):
            if ancestor.previous is not None:
                lines.append(
                    f"from eth_consensus_specs.{ancestor.previous} "
                    f"import {self.preset} as {ancestor.previous}"
                )
        return "\n\n".join(lines) + "\n"

    def _qualify_configs(self, source: str) -> str:
        for name in self.spec.configs:
            source = re.sub(CONFIG_NAME_RE.format(name=name), "config." + name, source)
        return source


def emit_python(
    spec: Spec,
    fork: Fork,
    forks: dict[str, Fork],
    preset_name: str,
    removals: Removals,
) -> str:
    return Emitter(spec, fork, forks, preset_name, removals).render()


def write_preset_yaml(
    path: Path,
    presets: dict[str, Value],
    preset_name: str,
    env: dict[str, int],
    *,
    fork_name: str,
    python_root: Path,
    pyspec_root: Path,
) -> dict[str, int]:
    if not presets:
        return env
    env = dict(env)
    data: dict[str, object] = {}
    pending = [(name, value.select(preset_name)) for name, value in presets.items()]
    progressed = True
    while pending and progressed:
        progressed = False
        still: list[tuple[str, str]] = []
        for name, expr in pending:
            result = evaluate(expr, env)
            if result is None:
                still.append((name, expr))
                continue
            data[name] = result
            if isinstance(result, int):
                env[name] = result
            progressed = True
        pending = still
    leftover = [name for name, _ in pending]
    if leftover:
        for entry in (str(python_root), str(pyspec_root)):
            if entry not in sys.path:
                sys.path.insert(0, entry)
        module = importlib.import_module(f"eth_consensus_specs.{fork_name}.{preset_name}")
        for name in leftover:
            value = getattr(module, name)
            data[name] = int(value) if isinstance(value, int) else value
            if isinstance(data[name], int):
                env[name] = data[name]
    dump_yaml(path, data)
    return env


def write_config_yaml(path: Path, configs: dict[str, Value], preset_name: str) -> None:
    data: dict = {"PRESET_BASE": preset_name, "CONFIG_NAME": preset_name}
    for name, value in configs.items():
        chosen = value.select(preset_name)
        if isinstance(chosen, str):
            data[name] = yaml_value(chosen)
            continue
        rows = []
        for record in chosen:
            row: dict[str, object] = {}
            for key, raw in record.items():
                if key == "DATE":
                    continue
                try:
                    row[key] = int(raw.replace(",", ""))
                except ValueError:
                    row[key] = raw
            rows.append(row)
        data[name] = rows
    dump_yaml(path, data)


def format_records(records: list[dict[str, str]]) -> str:
    lines = ["("]
    for record in records:
        lines.append("    frozendict({")
        for key, value in record.items():
            lines.append(f'        "{key}": {value},')
        lines.append("    }),")
    lines.append(")")
    return "\n".join(lines)


def assign(name: str, expression: str) -> str:
    kind, inner = split_type(expression)
    if kind is None:
        stripped = expression.strip()
        if stripped.startswith(("'", '"')):
            return f"{name}: Final = {expression}"
        return f"{name} = {expression}"
    return f"{name} = {kind}({inner})"


def split_type(expression: str) -> tuple[str | None, str]:
    expression = expression.strip()
    match = TYPE_RE.match(expression)
    if match:
        return match.group(1), match.group(2)
    if "(" not in expression or not expression.endswith(")"):
        return None, expression
    index = expression.index("(")
    kind = expression[:index]
    if not kind or not kind[0].isupper():
        return None, expression
    return kind, expression[index + 1 : -1]


def literal_int(expression: str) -> int | None:
    return evaluate(expression, {})


def evaluate(expression: str, env: dict[str, int]) -> object | None:
    _, inner = split_type(expression)
    inner = inner.strip()
    if inner.startswith(("'", '"')):
        return inner.strip("'\"")
    try:
        result = eval(inner, {"__builtins__": {}}, env)
    except Exception:
        return None
    if isinstance(result, float) and result.is_integer():
        return int(result)
    return result


def yaml_value(expression: str) -> object:
    result = evaluate(expression, {})
    if result is not None:
        return result
    _, inner = split_type(expression)
    return inner.strip()


def dump_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    yaml = YAML()
    yaml.default_flow_style = False
    yaml.allow_unicode = True
    with path.open("w") as handle:
        yaml.dump(data, handle)


def references(source: str, names: set[str]) -> bool:
    return any(re.search(WORD_RE.format(name=re.escape(name)), source) for name in names)


def split_by_deps(
    types: dict[str, str], deferred: dict[str, str]
) -> tuple[dict[str, str], dict[str, str]]:
    if not deferred:
        return types, {}
    late = set(deferred)
    changed = True
    while changed:
        changed = False
        for name, source in types.items():
            if name not in late and references(source, late):
                late.add(name)
                changed = True
    return (
        {name: src for name, src in types.items() if name not in late},
        {name: src for name, src in types.items() if name in late},
    )


def order_types(types: dict[str, str]) -> dict[str, str]:
    ordered = dict(types)
    previous: dict[str, str] = {}
    while list(previous) != list(ordered):
        previous = dict(ordered)
        for name, source in list(ordered.items()):
            for dep in type_dependencies(name, source, ordered):
                keys = list(ordered)
                for item in [dep, name] + keys[keys.index(dep) + 1 :]:
                    ordered[item] = ordered.pop(item)
    return ordered


def type_dependencies(name: str, source: str, types: dict[str, str]) -> list[str]:
    lines = source.split("\n")
    signature_end = next((i for i, line in enumerate(lines) if line.rstrip().endswith("):")), 0)
    signature = " ".join(
        line[: line.index("#")] if "#" in line else line for line in lines[: signature_end + 1]
    )
    names: list[str] = []
    for i, line in enumerate([signature, *lines[signature_end + 1 :]]):
        match = re.match(r".+?\((.+)\):", line) if i == 0 else re.match(r"\s+\w+: (.+)", line)
        if not match:
            continue
        expr = match.group(1)
        if "#" in expr:
            expr = expr[: expr.index("#")]
        names.extend(re.findall(r"(\w+)", expr))
    return [dep for dep in names if dep in types and dep != name]


def self_type(source: str) -> str | None:
    fn = ast.parse(source).body[0]
    if not isinstance(fn, ast.FunctionDef) or not fn.args.args:
        return None
    first = fn.args.args[0]
    if first.arg != "self" or not isinstance(getattr(first, "annotation", None), ast.Name):
        return None
    return first.annotation.id


def base_name(source: str) -> str | None:
    cls = next((node for node in ast.parse(source).body if isinstance(node, ast.ClassDef)), None)
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

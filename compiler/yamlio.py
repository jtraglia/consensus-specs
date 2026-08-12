"""Write comment-free preset and config YAML from a Spec."""

from __future__ import annotations

import importlib
import re
import sys
from typing import TYPE_CHECKING

from ruamel.yaml import YAML

if TYPE_CHECKING:
    from pathlib import Path

    from compiler.models import Value

TYPE_RE = re.compile(r"^([A-Z_]\w*)\((.*)\)$")


def _split_type(expression: str) -> tuple[str | None, str]:
    match = TYPE_RE.match(expression.strip())
    if not match:
        return None, expression.strip()
    return match.group(1), match.group(2)


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
    data, env, leftover = _evaluate_presets(presets, preset_name, env)
    if leftover:
        live = _values_from_module(
            fork_name, preset_name, leftover, python_root=python_root, pyspec_root=pyspec_root
        )
        data.update(live)
        for name, value in live.items():
            if isinstance(value, int):
                env[name] = value
    _dump(path, data)
    return env


def write_config_yaml(path: Path, configs: dict[str, Value], preset_name: str) -> None:
    data: dict = {
        "PRESET_BASE": preset_name,
        "CONFIG_NAME": preset_name,
    }
    for name, value in configs.items():
        records = value.records(preset_name)
        if records is not None:
            data[name] = _records_to_yaml(records)
        else:
            data[name] = _to_yaml(value.select(preset_name), {})
    _dump(path, data)


def _evaluate_presets(
    presets: dict[str, Value], preset_name: str, env: dict[str, int]
) -> tuple[dict[str, object], dict[str, int], list[str]]:
    env = dict(env)
    data: dict[str, object] = {}
    leftover: list[str] = []
    pending = [(name, value.select(preset_name)) for name, value in presets.items()]
    progressed = True
    while pending and progressed:
        progressed = False
        still: list[tuple[str, str]] = []
        for name, expr in pending:
            if "get_generalized_index" in expr:
                leftover.append(name)
                continue
            result = _try_eval(expr, env)
            if result is None:
                still.append((name, expr))
                continue
            data[name] = result
            if isinstance(result, int):
                env[name] = result
            progressed = True
        pending = still
    leftover.extend(name for name, _ in pending)
    return data, env, leftover


def _try_eval(expression: str, env: dict[str, int]) -> object | None:
    _, inner = _split_type(expression)
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


def _to_yaml(expression: str, env: dict[str, int]) -> object:
    result = _try_eval(expression, env)
    if result is not None:
        return result
    _, inner = _split_type(expression)
    return inner.strip()


def _values_from_module(
    fork_name: str,
    preset_name: str,
    names: list[str],
    *,
    python_root: Path,
    pyspec_root: Path,
) -> dict[str, object]:
    for entry in (str(python_root), str(pyspec_root)):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    module = importlib.import_module(f"eth_consensus_specs.{fork_name}.{preset_name}")
    out: dict[str, object] = {}
    for name in names:
        value = getattr(module, name)
        out[name] = int(value) if isinstance(value, int) else value
    return out


def _records_to_yaml(records: list[dict[str, str]]) -> list[dict[str, object]]:
    out = []
    for record in records:
        row: dict[str, object] = {}
        for key, raw in record.items():
            if key == "DATE":
                continue
            try:
                row[key] = int(raw.replace(",", ""))
            except ValueError:
                row[key] = raw
        out.append(row)
    return out


def _dump(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    yaml = YAML()
    yaml.default_flow_style = False
    yaml.allow_unicode = True
    with path.open("w") as handle:
        yaml.dump(data, handle)

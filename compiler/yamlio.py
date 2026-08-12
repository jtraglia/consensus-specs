"""Write comment-free preset and config YAML from a Spec."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ruamel.yaml import YAML

if TYPE_CHECKING:
    from pathlib import Path

    from compiler.models import Value

TYPE_RE = re.compile(r"^([A-Za-z_]\w*)\((.*)\)$")


def _split_type(expression: str) -> tuple[str | None, str]:
    match = TYPE_RE.match(expression.strip())
    if not match:
        return None, expression.strip()
    return match.group(1), match.group(2)


def write_preset_yaml(path: Path, presets: dict[str, Value], preset_name: str) -> None:
    if not presets:
        return
    data: dict[str, object] = {}
    env: dict[str, int] = {}
    pending: list[tuple[str, Value]] = []
    for name, value in presets.items():
        expr = value.select(preset_name)
        if any(other != name and other in expr for other in presets):
            pending.append((name, value))
            continue
        data[name] = _to_yaml(expr, value.annotation(preset_name))
        if isinstance(data[name], int):
            env[name] = data[name]
    for name, value in pending:
        _, inner = _split_type(value.select(preset_name))
        try:
            data[name] = int(eval(inner, {"__builtins__": {}}, env))
        except Exception:
            data[name] = _to_yaml(value.select(preset_name), value.annotation(preset_name))
    _dump(path, data)


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
            data[name] = _to_yaml(value.select(preset_name), value.annotation(preset_name))
    _dump(path, data)


def _to_yaml(expression: str, annotation: int | None) -> object:
    _, inner = _split_type(expression)
    inner = inner.strip()
    if inner.startswith(("'", '"')):
        return inner.strip("'\"")
    if annotation is not None:
        return annotation
    try:
        result = eval(inner, {"__builtins__": {}}, {})
    except Exception:
        return inner
    if isinstance(result, float) and result.is_integer():
        return int(result)
    return result


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

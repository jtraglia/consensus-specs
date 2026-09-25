import importlib
import re
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import eth_consensus_specs

from .discover import SpecError
from .model import CONFIG, PRESET, PRESETS, Spec, Variable


def hex_text(value: bytes, expression: object = None) -> str:
    text = "0x" + value.hex()
    if isinstance(expression, str):
        for literal in re.findall(r"0x[0-9a-fA-F]+", expression):
            if literal.lower() == text:
                return literal
    return text


def scalar(value: Any, expression: object = None) -> str:
    if isinstance(value, bytes):
        return hex_text(value, expression)
    if isinstance(value, str):
        return f"'{value}'"
    if isinstance(value, bool):
        raise SpecError(f"booleans are not supported in configs: {value}")
    return str(int(value))


def entry(name: str, value: Any, expression: object = None) -> str:
    if isinstance(value, tuple):
        if not value:
            return f"{name}: []"
        lines = [f"{name}:"]
        for record in value:
            for index, (key, field) in enumerate(record.items()):
                lines.append(f"{'  - ' if index == 0 else '    '}{key}: {scalar(field)}")
        return "\n".join(lines)
    return f"{name}: {scalar(value, expression)}"


def document(spec: Spec, source: Any, kind: str, preset: str) -> str:
    groups: dict[str, list[str]] = {fork: [] for fork in spec.lineage}
    for key, item in spec.items.items():
        if isinstance(item, Variable) and item.kind == kind:
            expression = item.values[preset]
            groups[item.fork].append(entry(key, getattr(source, key), expression))
    return "\n\n".join("\n".join(lines) for lines in groups.values() if lines) + "\n"


def load_module(out: Path, fork: str, preset: str) -> ModuleType:
    package = str(out.resolve() / "specs")
    if eth_consensus_specs.__path__[0] != package:
        if package in eth_consensus_specs.__path__:
            eth_consensus_specs.__path__.remove(package)
        eth_consensus_specs.__path__.insert(0, package)
    return importlib.import_module(f"eth_consensus_specs.{fork}.{preset}")


def plain(value: Any) -> object:
    if isinstance(value, bytes):
        return bytes(value)
    if isinstance(value, str):
        return value
    if isinstance(value, tuple):
        return tuple(
            tuple((key, plain(field)) for key, field in record.items()) for record in value
        )
    return int(value)


def check_same(out: Path, fork: str, spec: Spec) -> None:
    default = load_module(out, fork, PRESETS[0])
    for key, item in spec.items.items():
        if not (isinstance(item, Variable) and item.same and key in spec.own):
            continue
        for preset in item.same:
            module = load_module(out, fork, preset)
            source, base = (
                (module.config, default.config) if item.kind == CONFIG else (module, default)
            )
            value, expected = getattr(source, key), getattr(base, key)
            if plain(value) != plain(expected):
                raise SpecError(
                    f"{item.path}: `{key}` is marked *same* but is {value!r} on {preset} "
                    f"and {expected!r} on {PRESETS[0]}"
                )


def emit_yaml(out: Path, specs: Mapping[str, Spec]) -> None:
    for fork, spec in specs.items():
        check_same(out, fork, spec)
        for preset in PRESETS:
            module = load_module(out, fork, preset)
            for directory, source, kind in (
                ("configs", module.config, CONFIG),
                ("presets", module, PRESET),
            ):
                path = out / directory / fork / f"{preset}.yaml"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(document(spec, source, kind, preset))

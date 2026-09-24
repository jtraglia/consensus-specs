import importlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import eth_consensus_specs

from .discover import SpecError
from .model import CONFIG, PRESET, PRESETS, Spec, Variable


def scalar(value: Any) -> str:
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if isinstance(value, str):
        return f"'{value}'"
    if isinstance(value, bool):
        raise SpecError(f"booleans are not supported in configs: {value}")
    return str(int(value))


def entry(name: str, value: Any) -> str:
    if isinstance(value, tuple):
        if not value:
            return f"{name}: []"
        lines = [f"{name}:"]
        for record in value:
            for index, (key, field) in enumerate(record.items()):
                lines.append(f"{'  - ' if index == 0 else '    '}{key}: {scalar(field)}")
        return "\n".join(lines)
    return f"{name}: {scalar(value)}"


def document(spec: Spec, source: Any, kind: str) -> str:
    groups: dict[str, list[str]] = {fork: [] for fork in spec.lineage}
    for key, item in spec.items.items():
        if isinstance(item, Variable) and item.kind == kind:
            groups[item.fork].append(entry(key, getattr(source, key)))
    return "\n\n".join("\n".join(lines) for lines in groups.values() if lines) + "\n"


def emit_yaml(out: Path, specs: Mapping[str, Spec]) -> None:
    package = str(out.resolve() / "pyspec" / "eth_consensus_specs")
    if package not in eth_consensus_specs.__path__:
        eth_consensus_specs.__path__.append(package)

    for fork, spec in specs.items():
        for preset in PRESETS:
            module = importlib.import_module(f"eth_consensus_specs.{fork}.{preset}")
            for directory, source, kind in (
                ("configs", module.config, CONFIG),
                ("presets", module, PRESET),
            ):
                path = out / directory / fork / f"{preset}.yaml"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(document(spec, source, kind))

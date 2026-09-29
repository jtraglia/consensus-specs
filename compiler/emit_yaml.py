from collections.abc import Mapping
from pathlib import Path

from .discover import SpecError
from .model import CONFIG, PRESET, PRESETS, Spec, Variable
from .values import hex_text, Values


def scalar(value: object, expression: object = None) -> str:
    if isinstance(value, bytes):
        return hex_text(value, expression)
    if isinstance(value, str):
        return f"'{value}'"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    raise SpecError(f"unsupported value in configs: {value!r}")


def entry(name: str, value: object, expression: object = None) -> str:
    if isinstance(value, tuple):
        if not value:
            return f"{name}: []"
        lines = [f"{name}:"]
        for record in value:
            for index, (key, field) in enumerate(record.items()):
                lines.append(f"{'  - ' if index == 0 else '    '}{key}: {scalar(field)}")
        return "\n".join(lines)
    return f"{name}: {scalar(value, expression)}"


def document(spec: Spec, values: Values, kind: str, preset: str) -> str:
    groups: dict[str, list[str]] = {fork: [] for fork in spec.lineage}
    for key, item in spec.items.items():
        if isinstance(item, Variable) and item.kind == kind:
            groups[item.fork].append(entry(key, values[key], item.values[preset]))
    return "\n\n".join("\n".join(lines) for lines in groups.values() if lines) + "\n"


def emit_yaml(
    out: Path, specs: Mapping[str, Spec], values: Mapping[str, dict[str, Values]]
) -> None:
    for fork, spec in specs.items():
        for preset in PRESETS:
            for directory, kind in (("configs", CONFIG), ("presets", PRESET)):
                path = out / directory / fork / f"{preset}.yaml"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(document(spec, values[fork][preset], kind, preset))

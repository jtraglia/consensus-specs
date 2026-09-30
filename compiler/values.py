import json
from collections.abc import Mapping
from pathlib import Path

from .languages.base import hex_text, Target
from .model import Kind, PRESETS, Spec, SpecError, Values, Variable


def check_same(spec: Spec, values: Mapping[str, Values]) -> None:
    for key, item in spec.items.items():
        if not (isinstance(item, Variable) and item.same and key in spec.own):
            continue
        expected = values[PRESETS[0]][key]
        for preset in item.same:
            if values[preset][key] != expected:
                raise SpecError(
                    f"{item.path}: `{key}` is marked *same* but is {values[preset][key]!r} "
                    f"on {preset} and {expected!r} on {PRESETS[0]}"
                )


def scalar(value: object, expression: object = None) -> str:
    if isinstance(value, bytes):
        return hex_text(value, expression)
    if isinstance(value, str):
        return f"'{value}'"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    raise SpecError(f"unsupported value in configs: {value!r}")


def entry(name: str, value: object, expression: object) -> str:
    if not isinstance(value, tuple):
        return f"{name}: {scalar(value, expression)}"
    if not value:
        return f"{name}: []"
    lines = [f"{name}:"]
    for record in value:
        for index, (key, field) in enumerate(record.items()):
            lines.append(f"{'  - ' if index == 0 else '    '}{key}: {scalar(field)}")
    return "\n".join(lines)


def write_yaml(
    out: Path, specs: Mapping[str, Spec], values: Mapping[str, Mapping[str, Values]]
) -> None:
    for fork, spec in specs.items():
        for preset in PRESETS:
            for directory, kind in (("configs", Kind.CONFIG), ("presets", Kind.PRESET)):
                groups: dict[str, list[str]] = {name: [] for name in spec.lineage}
                for key, item in spec.items.items():
                    if isinstance(item, Variable) and item.kind == kind:
                        value = values[fork][preset][key]
                        groups[item.fork].append(entry(key, value, item.values[preset]))
                text = "\n\n".join("\n".join(lines) for lines in groups.values() if lines)
                path = out / directory / fork / f"{preset}.yaml"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text + "\n")


def write_json(
    out: Path,
    target: Target,
    specs: Mapping[str, Spec],
    values: Mapping[str, Mapping[str, Values]],
) -> None:
    data = {
        preset: {
            fork: target.spec_object(spec, preset, values[fork][preset])
            for fork, spec in specs.items()
        }
        for preset in PRESETS
    }
    (out / "spec.json").write_text(json.dumps(data))

"""Load today's committed preset/config YAML. Removed once markdown is the source."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ruamel.yaml import YAML

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


def parse_config_vars(conf: dict) -> dict[str, str | list[dict[str, str]]]:
    out: dict[str, str | list[dict[str, str]]] = {}
    for key, value in conf.items():
        if isinstance(value, list):
            out[key] = value
        elif isinstance(value, str) and (
            value.startswith("0x") or key in ("PRESET_BASE", "CONFIG_NAME")
        ):
            out[key] = f"'{value}'"
        else:
            out[key] = str(int(value))
    return out


def load_preset(preset_files: Sequence[Path]) -> dict[str, str]:
    preset: dict[str, str] = {}
    yaml = YAML(typ="base")
    for fork_file in preset_files:
        fork_preset = yaml.load(fork_file)
        if fork_preset is None:
            continue
        overlap = set(fork_preset) & set(preset)
        if overlap:
            raise ValueError(f"duplicate preset var(s): {', '.join(sorted(overlap))}")
        preset.update(fork_preset)
    if not preset:
        raise ValueError("no preset values loaded")
    return parse_config_vars(preset)  # type: ignore[return-value]


def load_config(config_path: Path) -> dict[str, str | list[dict[str, str]]]:
    yaml = YAML(typ="base")
    return parse_config_vars(yaml.load(config_path))

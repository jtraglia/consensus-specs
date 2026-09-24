import json
from collections.abc import Mapping
from pathlib import Path

from .emit_yaml import load_module
from .languages.python import spec_object
from .model import PRESETS, Spec


def emit_json(out: Path, specs: Mapping[str, Spec]) -> None:
    data = {
        preset: {
            fork: spec_object(spec, preset, load_module(out, fork, preset))
            for fork, spec in specs.items()
        }
        for preset in PRESETS
    }
    (out / "spec.json").write_text(json.dumps(data))

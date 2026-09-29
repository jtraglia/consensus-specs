import json
from collections.abc import Mapping
from pathlib import Path

from .languages import Language
from .model import PRESETS, Spec
from .values import Values


def emit_json(
    out: Path, target: Language, specs: Mapping[str, Spec], values: Mapping[str, dict[str, Values]]
) -> None:
    data = {
        preset: {
            fork: target.spec_object(spec, preset, values[fork][preset])
            for fork, spec in specs.items()
        }
        for preset in PRESETS
    }
    (out / "spec.json").write_text(json.dumps(data))

import re

from .discover import SpecError
from .model import PRESETS, Spec, Variable

Values = dict[str, object]


def hex_text(value: bytes, expression: object = None) -> str:
    text = "0x" + value.hex()
    if isinstance(expression, str):
        for literal in re.findall(r"0x[0-9a-fA-F]+", expression):
            if literal.lower() == text:
                return literal
    return text


def check_same(spec: Spec, values: dict[str, Values]) -> None:
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

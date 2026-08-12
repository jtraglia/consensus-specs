"""Merge specs and order class definitions."""

from __future__ import annotations

import re

from compiler.models import Spec, Value

GINDEX_UNQUALIFIED_RE = re.compile(r"(get_generalized_index\(\s*)([A-Za-z_][A-Za-z0-9_]*)(\s*,)")


def order_classes(classes: dict[str, str]) -> dict[str, str]:
    """Stable topological pass: a class is moved after anything it names."""
    ordered = dict(classes)
    previous: dict[str, str] = {}
    while list(previous) != list(ordered):
        previous = dict(ordered)
        for name, source in list(ordered.items()):
            for dep in _class_dependencies(name, source, ordered):
                keys = list(ordered)
                for item in [dep, name] + keys[keys.index(dep) + 1 :]:
                    ordered[item] = ordered.pop(item)
    return ordered


def qualify_inherited_gindices(spec: Spec, fork_name: str) -> Spec:
    """Point inherited ``get_generalized_index`` calls at the fork that defined them."""
    classes = set(spec.classes)

    def qualify(expr: str) -> str:
        return GINDEX_UNQUALIFIED_RE.sub(
            lambda match: (
                f"{match.group(1)}{fork_name}.{match.group(2)}{match.group(3)}"
                if match.group(2) in classes
                else match.group(0)
            ),
            expr,
        )

    def qualify_value(value: Value) -> Value:
        mainnet = qualify(value.mainnet)
        minimal = qualify(value.minimal)
        if mainnet == value.mainnet and minimal == value.minimal:
            return value
        return Value(
            mainnet=mainnet,
            minimal=minimal,
            annotation_mainnet=value.annotation_mainnet,
            annotation_minimal=value.annotation_minimal,
            records_mainnet=value.records_mainnet,
            records_minimal=value.records_minimal,
        )

    return Spec(
        functions=spec.functions,
        classes=spec.classes,
        assignments=spec.assignments,
        constants={name: qualify_value(value) for name, value in spec.constants.items()},
        presets={name: qualify_value(value) for name, value in spec.presets.items()},
        configs=spec.configs,
    )


def _class_dependencies(name: str, source: str, classes: dict[str, str]) -> list[str]:
    lines = source.split("\n")
    signature_end = next((i for i, line in enumerate(lines) if line.rstrip().endswith("):")), 0)
    signature = " ".join(
        line[: line.index("#")] if "#" in line else line for line in lines[: signature_end + 1]
    )
    body = [signature, *lines[signature_end + 1 :]]
    names: list[str] = []
    for i, line in enumerate(body):
        match = re.match(r".+?\((.+)\):", line) if i == 0 else re.match(r"\s+\w+: (.+)", line)
        if not match:
            continue
        expr = match.group(1)
        if "#" in expr:
            expr = expr[: expr.index("#")]
        names.extend(re.findall(r"(\w+)", expr))
    return [dep for dep in names if dep in classes and dep != name]

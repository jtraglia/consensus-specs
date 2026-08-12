"""Merge specs and order class definitions."""

from __future__ import annotations

import ast
import re


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


def inherited_classes(
    previous: str | None,
    redefined: set[str],
    classes: dict[str, str],
) -> dict[str, str]:
    """Unchanged classes, mapped to the previous fork's module name."""
    if previous is None:
        return {}
    built_from = {
        name: {node.id for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Name)}
        for name, source in classes.items()
    }
    changed = set(redefined)
    candidates = set(classes) - changed
    while newly := {name for name in candidates if built_from[name] & changed}:
        candidates -= newly
        changed |= newly
    return dict.fromkeys(sorted(candidates), previous)


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

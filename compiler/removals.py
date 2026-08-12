"""Parse specs/<fork>/removed.md and accumulate removals along a fork chain."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from compiler.discover import Fork

HEADING_RE = re.compile(r"^##\s+(.+?)\s*$")
ITEM_RE = re.compile(r"^-\s+`([^`]+)`")

SECTION_ATTR = {
    "Functions": "functions",
    "Containers": "containers",
    "Constants": "constants",
    "Presets": "presets",
    "Aliases": "aliases",
    "Types": "types",
}


@dataclass
class Removals:
    functions: set[str] = field(default_factory=set)
    containers: set[str] = field(default_factory=set)
    constants: set[str] = field(default_factory=set)
    presets: set[str] = field(default_factory=set)
    aliases: set[str] = field(default_factory=set)
    types: set[str] = field(default_factory=set)

    def update(self, other: Removals) -> None:
        self.functions |= other.functions
        self.containers |= other.containers
        self.constants |= other.constants
        self.presets |= other.presets
        self.aliases |= other.aliases
        self.types |= other.types

    @property
    def classes(self) -> set[str]:
        return self.containers | self.aliases | self.types


def parse_removed(path: Path) -> Removals:
    removals = Removals()
    section: str | None = None
    for line in path.read_text().splitlines():
        heading = HEADING_RE.match(line)
        if heading:
            title = heading.group(1).strip()
            if title not in SECTION_ATTR:
                raise ValueError(f"{path}: unknown removed.md heading {title!r}")
            section = SECTION_ATTR[title]
            continue
        item = ITEM_RE.match(line)
        if item:
            if section is None:
                raise ValueError(f"{path}: list item before a section heading")
            getattr(removals, section).add(item.group(1))
    return removals


def removals_for(fork: Fork, forks: dict[str, Fork]) -> Removals:
    combined = Removals()
    for ancestor in reversed(fork.ancestors(forks)):
        path = ancestor.directory / "removed.md"
        if path.exists():
            combined.update(parse_removed(path))
    return combined

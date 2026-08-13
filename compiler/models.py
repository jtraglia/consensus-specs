"""In-memory form of one fork's compiled markdown."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

REMOVED_HEADING_RE = re.compile(r"^##\s+(.+?)\s*$")
REMOVED_ITEM_RE = re.compile(r"^-\s+`([^`]+)`")
REMOVED_SECTIONS = {
    "Functions": "functions",
    "Containers": "containers",
    "Constants": "constants",
    "Presets": "presets",
    "Aliases": "aliases",
    "Types": "types",
    "Dataclasses": "dataclasses",
    "Exceptions": "exceptions",
}


@dataclass(frozen=True)
class Value:
    mainnet: str | list[dict[str, str]]
    minimal: str | list[dict[str, str]]

    def select(self, preset: str) -> str | list[dict[str, str]]:
        return self.mainnet if preset == "mainnet" else self.minimal


@dataclass
class Removals:
    functions: set[str] = field(default_factory=set)
    constants: set[str] = field(default_factory=set)
    presets: set[str] = field(default_factory=set)
    aliases: set[str] = field(default_factory=set)
    types: set[str] = field(default_factory=set)
    containers: set[str] = field(default_factory=set)
    dataclasses: set[str] = field(default_factory=set)
    exceptions: set[str] = field(default_factory=set)

    @classmethod
    def from_path(cls, path: Path) -> Removals:
        removals = cls()
        section: str | None = None
        for line in path.read_text().splitlines():
            heading = REMOVED_HEADING_RE.match(line)
            if heading:
                title = heading.group(1).strip()
                if title not in REMOVED_SECTIONS:
                    raise ValueError(f"{path}: unknown removed.md heading {title!r}")
                section = REMOVED_SECTIONS[title]
                continue
            item = REMOVED_ITEM_RE.match(line)
            if item:
                if section is None:
                    raise ValueError(f"{path}: list item before a section heading")
                getattr(removals, section).add(item.group(1))
        return removals

    def update(self, other: Removals) -> None:
        self.functions |= other.functions
        self.constants |= other.constants
        self.presets |= other.presets
        self.aliases |= other.aliases
        self.types |= other.types
        self.containers |= other.containers
        self.dataclasses |= other.dataclasses
        self.exceptions |= other.exceptions


@dataclass
class Spec:
    functions: dict[str, str] = field(default_factory=dict)
    aliases: dict[str, str] = field(default_factory=dict)
    types: dict[str, str] = field(default_factory=dict)
    containers: dict[str, str] = field(default_factory=dict)
    dataclasses: dict[str, str] = field(default_factory=dict)
    exceptions: dict[str, str] = field(default_factory=dict)
    constants: dict[str, str] = field(default_factory=dict)
    presets: dict[str, Value] = field(default_factory=dict)
    configs: dict[str, Value] = field(default_factory=dict)

    def merge(self, other: Spec) -> Spec:
        return Spec(
            functions={**self.functions, **other.functions},
            aliases={**self.aliases, **other.aliases},
            types={**self.types, **other.types},
            containers={**self.containers, **other.containers},
            dataclasses={**self.dataclasses, **other.dataclasses},
            exceptions={**self.exceptions, **other.exceptions},
            constants={**self.constants, **other.constants},
            presets={**self.presets, **other.presets},
            configs={**self.configs, **other.configs},
        )

    def without(self, gone: Removals) -> Spec:
        return Spec(
            functions={k: v for k, v in self.functions.items() if k not in gone.functions},
            aliases={k: v for k, v in self.aliases.items() if k not in gone.aliases},
            types={k: v for k, v in self.types.items() if k not in gone.types},
            containers={k: v for k, v in self.containers.items() if k not in gone.containers},
            dataclasses={k: v for k, v in self.dataclasses.items() if k not in gone.dataclasses},
            exceptions={k: v for k, v in self.exceptions.items() if k not in gone.exceptions},
            constants={k: v for k, v in self.constants.items() if k not in gone.constants},
            presets={k: v for k, v in self.presets.items() if k not in gone.presets},
            configs=self.configs,
        )

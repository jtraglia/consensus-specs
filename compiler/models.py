"""In-memory form of one fork's compiled markdown."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

GINDEX_UNQUALIFIED_RE = re.compile(r"(get_generalized_index\(\s*)([A-Za-z_][A-Za-z0-9_]*)(\s*,)")
REMOVED_HEADING_RE = re.compile(r"^##\s+(.+?)\s*$")
REMOVED_ITEM_RE = re.compile(r"^-\s+`([^`]+)`")
REMOVED_SECTIONS = {
    "Functions": "functions",
    "Containers": "containers",
    "Constants": "constants",
    "Presets": "presets",
    "Aliases": "aliases",
    "Types": "types",
}


@dataclass(frozen=True)
class Value:
    mainnet: str
    minimal: str
    records_mainnet: list[dict[str, str]] | None = None
    records_minimal: list[dict[str, str]] | None = None

    def select(self, preset: str) -> str:
        return self.mainnet if preset == "mainnet" else self.minimal

    def records(self, preset: str) -> list[dict[str, str]] | None:
        return self.records_mainnet if preset == "mainnet" else self.records_minimal

    def map_expr(self, fn: Callable[[str], str]) -> Value:
        mainnet, minimal = fn(self.mainnet), fn(self.minimal)
        if (mainnet, minimal) == (self.mainnet, self.minimal):
            return self
        return Value(mainnet, minimal, self.records_mainnet, self.records_minimal)


@dataclass
class Removals:
    functions: set[str] = field(default_factory=set)
    containers: set[str] = field(default_factory=set)
    constants: set[str] = field(default_factory=set)
    presets: set[str] = field(default_factory=set)
    aliases: set[str] = field(default_factory=set)
    types: set[str] = field(default_factory=set)

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
        self.containers |= other.containers
        self.constants |= other.constants
        self.presets |= other.presets
        self.aliases |= other.aliases
        self.types |= other.types

    @property
    def classes(self) -> set[str]:
        return self.containers | self.aliases | self.types


@dataclass
class Spec:
    functions: dict[str, str] = field(default_factory=dict)
    aliases: dict[str, str] = field(default_factory=dict)
    types: dict[str, str] = field(default_factory=dict)
    instances: dict[str, str] = field(default_factory=dict)
    constants: dict[str, str] = field(default_factory=dict)
    presets: dict[str, Value] = field(default_factory=dict)
    configs: dict[str, Value] = field(default_factory=dict)

    def merge(self, other: Spec) -> Spec:
        return Spec(
            functions={**self.functions, **other.functions},
            aliases={**self.aliases, **other.aliases},
            types={**self.types, **other.types},
            instances={**self.instances, **other.instances},
            constants={**self.constants, **other.constants},
            presets={**self.presets, **other.presets},
            configs={**self.configs, **other.configs},
        )

    def without(self, gone: Removals) -> Spec:
        drop_fn = gone.functions
        drop_cls = gone.classes
        return Spec(
            functions={
                key: source
                for key, source in self.functions.items()
                if key not in drop_fn and key.rsplit(".", 1)[-1] not in drop_fn
            },
            aliases={k: v for k, v in self.aliases.items() if k not in drop_cls},
            types={k: v for k, v in self.types.items() if k not in drop_cls},
            instances=self.instances,
            constants={k: v for k, v in self.constants.items() if k not in gone.constants},
            presets={k: v for k, v in self.presets.items() if k not in gone.presets},
            configs=self.configs,
        )

    def qualify_gindices(self, fork_name: str) -> Spec:
        names = set(self.types)

        def qualify(expr: str) -> str:
            return GINDEX_UNQUALIFIED_RE.sub(
                lambda match: (
                    f"{match.group(1)}{fork_name}.{match.group(2)}{match.group(3)}"
                    if match.group(2) in names
                    else match.group(0)
                ),
                expr,
            )

        return Spec(
            functions=self.functions,
            aliases=self.aliases,
            types=self.types,
            instances=self.instances,
            constants={n: qualify(v) for n, v in self.constants.items()},
            presets={n: v.map_expr(qualify) for n, v in self.presets.items()},
            configs=self.configs,
        )

from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

PRESETS = ("mainnet", "minimal")

FUNCTION = "function"
IMPORT = "import"
METHOD = "method"
TYPE = "type"
VALUE = "value"
WRAPPER = "wrapper"

CONSTANT = "constant"
PRESET = "preset"
CONFIG = "config"

Records = list[dict[str, str]]


@dataclass(frozen=True)
class Definition:
    name: str
    kind: str
    lang: str
    source: str
    fork: str
    path: Path
    receiver: str | None = None
    build: bool = False

    @property
    def key(self) -> str:
        if self.kind == WRAPPER:
            return f"{self.name}@{WRAPPER}"
        return f"{self.receiver}.{self.name}" if self.receiver else self.name


@dataclass(frozen=True)
class Variable:
    name: str
    kind: str
    values: dict[str, str | Records]
    fork: str
    path: Path
    same: tuple[str, ...] = ()

    @property
    def key(self) -> str:
        return self.name


Item = Definition | Variable


@dataclass
class Document:
    path: Path
    fork: str
    parent: str | None
    items: list[Item] = field(default_factory=list)
    removed: dict[str, list[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class Fork:
    name: str
    parent: str | None
    documents: tuple[Path, ...]


@dataclass
class Spec:
    fork: str
    lineage: tuple[str, ...]
    items: dict[str, Item]

    @cached_property
    def own(self) -> set[str]:
        return {key for key, item in self.items.items() if item.fork == self.fork}

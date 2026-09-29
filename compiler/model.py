from dataclasses import dataclass, field
from enum import auto, StrEnum
from functools import cached_property
from pathlib import Path
from typing import ClassVar

PRESETS = ("mainnet", "minimal")

Records = list[dict[str, str]]
References = tuple[frozenset[str], frozenset[str]]
Values = dict[str, object]


class SpecError(Exception):
    pass


class Kind(StrEnum):
    FUNCTION = auto()
    IMPORT = auto()
    METHOD = auto()
    TYPE = auto()
    VALUE = auto()
    WRAPPER = auto()
    CONSTANT = auto()
    PRESET = auto()
    CONFIG = auto()


class Group(StrEnum):
    ALIAS = "Aliases"
    HELPER = "Helpers"
    TYPE = "Types"
    PRESET = "Presets"
    CONSTANT = "Constants"
    CONFIGURATION = "Configuration"
    CONTAINER = "Containers"
    DATACLASS = "Dataclasses"
    PROTOCOL = "Protocols"
    CLASS = "Classes"
    VALUE = "Values"
    FUNCTION = "Functions"
    CACHE = "Caches"


class Shape(StrEnum):
    SCALAR = auto()
    COLLECTION = auto()
    CONTAINER = auto()
    DATACLASS = auto()


def wrapper_key(name: str) -> str:
    return f"{name}@{Kind.WRAPPER}"


@dataclass(frozen=True)
class Definition:
    name: str
    kind: Kind
    lang: str
    source: str
    fork: str
    path: Path
    receiver: str | None = None
    build: bool = False

    @property
    def key(self) -> str:
        if self.kind == Kind.WRAPPER:
            return wrapper_key(self.name)
        return f"{self.receiver}.{self.name}" if self.receiver else self.name


@dataclass(frozen=True)
class Variable:
    name: str
    kind: Kind
    values: dict[str, str | Records]
    fork: str
    path: Path
    same: tuple[str, ...] = ()
    build: ClassVar[bool] = False

    @property
    def key(self) -> str:
        return self.name


Item = Definition | Variable


@dataclass
class Document:
    path: Path
    fork: str
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

"""In-memory form of one fork's compiled markdown."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Value:
    """A table value. Constants use the same expression in both columns."""

    mainnet: str
    minimal: str
    annotation_mainnet: int | None = None
    annotation_minimal: int | None = None
    records_mainnet: list[dict[str, str]] | None = None
    records_minimal: list[dict[str, str]] | None = None

    def select(self, preset: str) -> str:
        return self.mainnet if preset == "mainnet" else self.minimal

    def annotation(self, preset: str) -> int | None:
        return self.annotation_mainnet if preset == "mainnet" else self.annotation_minimal

    def records(self, preset: str) -> list[dict[str, str]] | None:
        return self.records_mainnet if preset == "mainnet" else self.records_minimal


@dataclass
class Spec:
    functions: dict[str, str] = field(default_factory=dict)
    classes: dict[str, str] = field(default_factory=dict)
    assignments: dict[str, str] = field(default_factory=dict)
    constants: dict[str, Value] = field(default_factory=dict)
    presets: dict[str, Value] = field(default_factory=dict)
    configs: dict[str, Value] = field(default_factory=dict)

    def merge(self, other: Spec) -> Spec:
        """Later files win when the same name is defined again."""
        return Spec(
            functions={**self.functions, **other.functions},
            classes={**self.classes, **other.classes},
            assignments={**self.assignments, **other.assignments},
            constants={**self.constants, **other.constants},
            presets={**self.presets, **other.presets},
            configs={**self.configs, **other.configs},
        )

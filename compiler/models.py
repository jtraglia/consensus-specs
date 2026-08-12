"""In-memory form of one fork's compiled markdown."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Value:
    """A table cell: the spec expression and optional ``(= N)`` annotation."""

    expression: str
    annotation: int | None = None


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

"""Discover forks from specs/ and specs/_features/."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from compiler.models import Removals

PREVIOUS_FORK_RE = re.compile(r"<!--\s*previous-fork:\s*([a-z][a-z0-9_]*)\s*-->")
SKIP_SOURCE_NAMES = frozenset({"removed.md"})


@dataclass(frozen=True)
class Fork:
    name: str
    directory: Path
    previous: str | None
    feature: bool

    def ancestors(self, forks: dict[str, Fork]) -> list[Fork]:
        chain = [self]
        current = self
        seen = {self.name}
        while current.previous is not None:
            if current.previous not in forks:
                raise ValueError(
                    f"{current.name} declares previous-fork {current.previous!r}, "
                    f"but that directory does not exist"
                )
            if current.previous in seen:
                raise ValueError(f"cycle in previous-fork chain at {current.name}")
            current = forks[current.previous]
            seen.add(current.name)
            chain.append(current)
        return chain

    def lineage(self, forks: dict[str, Fork]) -> list[Fork]:
        return list(reversed(self.ancestors(forks)))

    def markdown_files(self) -> list[Path]:
        return sorted(
            path for path in self.directory.rglob("*.md") if path.name not in SKIP_SOURCE_NAMES
        )

    def removals(self, forks: dict[str, Fork]) -> Removals:
        combined = Removals()
        for ancestor in reversed(self.ancestors(forks)):
            path = ancestor.directory / "removed.md"
            if path.exists():
                combined.update(Removals.from_path(path))
        return combined


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def discover_forks(root: Path | None = None) -> dict[str, Fork]:
    root = root or repo_root()
    found: dict[str, Fork] = {}
    for feature, parent in (
        (False, root / "specs"),
        (True, root / "specs" / "_features"),
    ):
        if not parent.is_dir():
            continue
        for directory in sorted(parent.iterdir()):
            if directory.name.startswith("_") or not directory.is_dir():
                continue
            if not any(directory.rglob("*.md")):
                continue
            previous = _read_previous_fork(directory)
            if directory.name == "phase0":
                if previous is not None:
                    raise ValueError("phase0 must not declare a previous-fork")
            elif previous is None:
                raise ValueError(
                    f"{directory} is missing `<!-- previous-fork: name -->` "
                    f"in a top-level markdown file"
                )
            found[directory.name] = Fork(
                name=directory.name,
                directory=directory,
                previous=previous,
                feature=feature,
            )
    if "phase0" not in found:
        raise ValueError("no specs/phase0 directory found")
    for fork in found.values():
        fork.ancestors(found)
    return found


def build_order(forks: dict[str, Fork]) -> list[Fork]:
    ordered: list[Fork] = []
    remaining = set(forks)

    def visit(name: str) -> None:
        if name not in remaining:
            return
        fork = forks[name]
        remaining.discard(name)
        if fork.previous is not None:
            visit(fork.previous)
        ordered.append(fork)

    for name in sorted(forks):
        visit(name)
    return ordered


def _read_previous_fork(directory: Path) -> str | None:
    declared: list[tuple[Path, str]] = []
    for path in sorted(directory.glob("*.md")):
        matches = PREVIOUS_FORK_RE.findall(path.read_text())
        if len(matches) > 1:
            raise ValueError(f"{path} declares previous-fork more than once")
        if len(matches) == 1:
            declared.append((path, matches[0]))
    if len(declared) > 1:
        files = ", ".join(str(path) for path, _ in declared)
        raise ValueError(f"{directory} declares previous-fork in multiple files: {files}")
    if not declared:
        return None
    return declared[0][1]

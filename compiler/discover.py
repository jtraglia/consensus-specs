"""Discover forks from specs/ and specs/_features/. No compiler-side registry."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

PREVIOUS_FORK_RE = re.compile(r"<!--\s*previous-fork:\s*([a-z][a-z0-9_]*)\s*-->")

# Prefer beacon-chain.md when collecting a fork's sources.
SOURCE_SORT_PRIORITY = ("beacon-chain",)

SKIP_SOURCE_NAMES = frozenset({"removed.md"})


@dataclass(frozen=True)
class Fork:
    name: str
    directory: Path
    previous: str | None
    feature: bool

    def ancestors(self, forks: dict[str, Fork]) -> list[Fork]:
        """This fork first, then each parent up to phase0."""
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
    _validate_graph(found)
    return found


def build_order(forks: dict[str, Fork]) -> list[Fork]:
    """Parents before children."""
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


def source_files(fork: Fork, forks: dict[str, Fork]) -> list[Path]:
    """Markdown sources for this fork, ancestors first, beacon-chain first per fork."""
    paths: list[Path] = []
    for ancestor in reversed(fork.ancestors(forks)):
        paths.extend(fork_markdown_files(ancestor.directory))
    return paths


def _read_previous_fork(directory: Path) -> str | None:
    declared: list[tuple[Path, str]] = []
    for path in sorted(directory.glob("*.md")):
        text = path.read_text()
        matches = PREVIOUS_FORK_RE.findall(text)
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


def fork_markdown_files(directory: Path) -> list[Path]:
    files = [path for path in directory.rglob("*.md") if path.name not in SKIP_SOURCE_NAMES]
    return sorted(files, key=_source_sort_key)


def _source_sort_key(path: Path) -> tuple[int, str]:
    text = str(path)
    for index, token in enumerate(SOURCE_SORT_PRIORITY):
        if token in text:
            return (index, text)
    return (len(SOURCE_SORT_PRIORITY), text)


def _validate_graph(forks: dict[str, Fork]) -> None:
    if "phase0" not in forks:
        raise ValueError("no specs/phase0 directory found")
    for fork in forks.values():
        fork.ancestors(forks)

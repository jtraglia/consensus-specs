import re
from pathlib import Path

from .model import Fork

DIRECTIVE = re.compile(r"<!--\s*eth_consensus_specs:\s*(.*?)\s*-->", re.DOTALL)
REMOVED = "removed.md"


class SpecError(Exception):
    pass


def parse_directive(text: str) -> dict[str, str]:
    match = DIRECTIVE.fullmatch(text.strip())
    if match is None:
        return {}
    words = match.group(1).split()
    return dict(word.partition("=")[::2] for word in words)


def read_parent(path: Path) -> str | None:
    first_line = path.read_text().split("\n", 1)[0]
    directive = parse_directive(first_line)
    if "parent" not in directive:
        raise SpecError(
            f"{path}: first line must declare `<!-- eth_consensus_specs: parent=... -->`"
        )
    parent = directive["parent"]
    return None if parent == "none" else parent


def document_order(path: Path) -> tuple[int, str]:
    if path.name == REMOVED:
        return (2, path.as_posix())
    if "beacon-chain" in path.as_posix():
        return (0, path.as_posix())
    return (1, path.as_posix())


def discover_forks(specs_dir: Path) -> dict[str, Fork]:
    directories = sorted(p for p in specs_dir.iterdir() if p.is_dir() and p.name != "_features")
    features = specs_dir / "_features"
    if features.is_dir():
        directories += sorted(p for p in features.iterdir() if p.is_dir())

    forks: dict[str, Fork] = {}
    for directory in directories:
        if directory.name in forks:
            raise SpecError(f"{directory}: fork `{directory.name}` is defined twice")
        documents = tuple(sorted(directory.rglob("*.md"), key=document_order))
        if not documents:
            continue
        parents = {path: read_parent(path) for path in documents}
        distinct = set(parents.values())
        if len(distinct) != 1:
            listing = ", ".join(f"{path.name}={parent}" for path, parent in parents.items())
            raise SpecError(f"{directory}: documents disagree on the parent fork ({listing})")
        forks[directory.name] = Fork(directory.name, distinct.pop(), documents)

    roots = [fork.name for fork in forks.values() if fork.parent is None]
    if len(roots) != 1:
        raise SpecError(f"expected exactly one fork with `parent=none`, found {roots}")
    for fork in forks.values():
        if fork.parent is not None and fork.parent not in forks:
            raise SpecError(f"fork `{fork.name}` has unknown parent `{fork.parent}`")

    ordered: dict[str, Fork] = {}
    pending = list(forks.values())
    while pending:
        ready = [f for f in pending if f.parent is None or f.parent in ordered]
        if not ready:
            raise SpecError(f"fork parents form a cycle: {[f.name for f in pending]}")
        for fork in ready:
            ordered[fork.name] = fork
            pending.remove(fork)
    return ordered


def lineage(forks: dict[str, Fork], name: str) -> tuple[str, ...]:
    chain = []
    current: str | None = name
    while current is not None:
        chain.append(current)
        current = forks[current].parent
    return tuple(reversed(chain))

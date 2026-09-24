import argparse
import shutil
import sys
from pathlib import Path

from .discover import discover_forks, lineage, SpecError
from .emit_json import emit_json
from .emit_yaml import emit_yaml
from .languages import LANGUAGES
from .languages.python import render
from .merge import merge, shared_types
from .model import Definition, Item, PRESETS, Spec
from .order import order
from .parse import parse_document

REPO = Path(__file__).resolve().parent.parent


def references(item: Item) -> tuple[frozenset[str], frozenset[str]]:
    language = LANGUAGES["python" if not isinstance(item, Definition) else item.lang]
    if isinstance(item, Definition):
        return language.references(item.source)
    eager: frozenset[str] = frozenset()
    for value in item.values.values():
        sources = [value] if isinstance(value, str) else [v for r in value for v in r.values()]
        for source in sources:
            eager |= language.references(source)[0]
    return eager, frozenset()


def everything(item: Item) -> frozenset[str]:
    eager, lazy = references(item)
    return eager | lazy


def build(out: Path, selected: list[str], verbose: bool) -> None:
    forks = discover_forks(REPO / "specs")
    if unknown := set(selected) - set(forks):
        raise SpecError(f"unknown forks: {sorted(unknown)}, available: {list(forks)}")
    wanted = set(forks) if not selected else {a for f in selected for a in lineage(forks, f)}
    targets = [name for name in forks if name in wanted]

    documents = {
        name: [parse_document(path, name, forks[name].parent) for path in forks[name].documents]
        for name in forks
    }

    package = out / "specs"
    if not selected:
        for directory in ("specs", "configs", "presets"):
            shutil.rmtree(out / directory, ignore_errors=True)
        (out / "spec.json").unlink(missing_ok=True)
    package.mkdir(parents=True, exist_ok=True)

    specs: dict[str, Spec] = {}
    for name in targets:
        spec = merge(forks, documents, name)
        nodes = order(spec, shared_types(spec, everything), references)
        directory = package / name
        directory.mkdir(parents=True, exist_ok=True)
        for preset in PRESETS:
            (directory / f"{preset}.py").write_text(render(spec, nodes, preset))
        (directory / "__init__.py").write_text("from . import mainnet as spec  # noqa:F401\n")
        specs[name] = spec
        if verbose:
            print(f"built {name}")

    graph = "\n".join(f"    {name!r}: {fork.parent!r}," for name, fork in forks.items())
    (package / "forks.py").write_text(f"PREVIOUS_FORK_OF = {{\n{graph}\n}}\n")

    if not selected:
        emit_yaml(out, specs)
        emit_json(out, {name: merge(forks, documents, name, build=False) for name in targets})


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m compiler")
    parser.add_argument("--fork", action="append", default=[], help="fork to build (repeatable)")
    parser.add_argument("--out", type=Path, default=REPO / "build", help="output directory")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    try:
        build(args.out, args.fork, args.verbose)
    except SpecError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

import argparse
import shutil
import sys
from pathlib import Path

from .discover import discover_forks, lineage, SpecError
from .emit_json import emit_json
from .emit_yaml import emit_yaml
from .languages import Foreign, LANGUAGES, Target
from .merge import merge, shared_types
from .model import Definition, PRESETS, Spec
from .order import order
from .parse import parse_document
from .values import check_same, Values

REPO = Path(__file__).resolve().parent.parent
TARGET = LANGUAGES["python"]
assert isinstance(TARGET, Target)


def build(out: Path, selected: list[str], verbose: bool) -> None:
    forks = discover_forks(REPO / "specs")
    if unknown := set(selected) - set(forks):
        raise SpecError(f"unknown forks: {sorted(unknown)}, available: {list(forks)}")
    wanted = set(forks) if not selected else {a for f in selected for a in lineage(forks, f)}
    targets = [name for name in forks if name in wanted]

    documents = {
        name: [parse_document(path, name) for path in forks[name].documents] for name in forks
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
        aliases = shared_types(spec, TARGET.all_references)
        nodes = order(spec, aliases, TARGET.item_references, TARGET.classify)
        directory = package / name
        directory.mkdir(parents=True, exist_ok=True)
        for preset in PRESETS:
            (directory / f"{preset}.py").write_text(TARGET.render(spec, nodes, preset))
        (directory / "__init__.py").write_text("from . import mainnet as spec  # noqa:F401\n")
        specs[name] = spec
        if verbose:
            print(f"built {name}")

    for spec in specs.values():
        foreign = [
            item
            for item in spec.items.values()
            if isinstance(item, Definition) and item.lang != TARGET.name
        ]
        for lang in sorted({item.lang for item in foreign if item.key in spec.own}):
            language = LANGUAGES[lang]
            assert isinstance(language, Foreign)
            definitions = [item for item in foreign if item.lang == lang]
            for preset in PRESETS:
                language.build(package / spec.fork, preset, definitions)

    graph = "\n".join(f"    {name!r}: {fork.parent!r}," for name, fork in forks.items())
    (package / "forks.py").write_text(f"PREVIOUS_FORK_OF = {{\n{graph}\n}}\n")

    if not selected:
        values: dict[str, dict[str, Values]] = {}
        for name, spec in specs.items():
            values[name] = {preset: TARGET.evaluate(out, spec, preset) for preset in PRESETS}
            check_same(spec, values[name])
        emit_yaml(out, specs, values)
        normative = {name: merge(forks, documents, name, build=False) for name in targets}
        emit_json(out, TARGET, normative, values)


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

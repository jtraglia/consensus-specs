import argparse
import shutil
import sys
from pathlib import Path

from .discover import discover_forks, lineage
from .languages import PYTHON
from .merge import merge
from .model import PRESETS, Spec, SpecError
from .parse import parse_document
from .values import check_same, write_json, write_yaml

REPO = Path(__file__).resolve().parent.parent


def build(out: Path, selected: list[str], verbose: bool) -> None:
    forks = discover_forks(REPO / "specs")
    if unknown := set(selected) - set(forks):
        raise SpecError(f"unknown forks: {sorted(unknown)}, available: {list(forks)}")
    wanted = set(forks) if not selected else {a for f in selected for a in lineage(forks, f)}
    targets = [name for name in forks if name in wanted]
    documents = {
        name: [parse_document(path, name) for path in forks[name].documents] for name in targets
    }

    if not selected:
        for directory in ("specs", "configs", "presets"):
            shutil.rmtree(out / directory, ignore_errors=True)
        (out / "spec.json").unlink(missing_ok=True)

    specs: dict[str, Spec] = {}
    for name in targets:
        specs[name] = merge(forks, documents, name)
        PYTHON.write(out, specs[name])
        if verbose:
            print(f"built {name}")
    PYTHON.write_forks(out, {name: fork.parent for name, fork in forks.items()})

    if not selected:
        values = {
            name: {preset: PYTHON.evaluate(out, spec, preset) for preset in PRESETS}
            for name, spec in specs.items()
        }
        for name, spec in specs.items():
            check_same(spec, values[name])
        write_yaml(out, specs, values)
        normative = {name: merge(forks, documents, name, build=False) for name in targets}
        write_json(out, PYTHON, normative)


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

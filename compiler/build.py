"""Build every discovered fork into build/."""

from __future__ import annotations

import copy
import re
from collections import OrderedDict
from typing import TYPE_CHECKING

from compiler.backends.python import emit_python
from compiler.discover import (
    build_order,
    discover_forks,
    Fork,
    parse_gindex_annotations,
    repo_root,
    source_files,
)
from pysetup import generate_specs, md_doc_paths
from pysetup.generate_specs import (
    collect_shared_types,
    get_spec,
    load_config,
    load_preset,
)
from pysetup.helpers import (
    combine_spec_objects,
    dependency_order_class_objects,
    finalized_spec_object,
)

if TYPE_CHECKING:
    from pathlib import Path

GINDEX_NAME_RE = re.compile(r"\|\s*`([A-Z][A-Z0-9_]*)`\s*\|\s*`get_generalized_index")

PRESETS = ("minimal", "mainnet")


def build(
    *,
    root: Path | None = None,
    only: str | None = None,
    verbose: bool = False,
) -> Path:
    root = root or repo_root()
    forks = discover_forks(root)
    targets = [fork for fork in build_order(forks) if only is None or fork.name == only]
    if only is not None and not targets:
        raise ValueError(f"unknown fork: {only}")

    out_root = root / "build" / "python" / "eth_consensus_specs"
    for fork in targets:
        _build_fork(fork, forks, root, out_root, verbose)
    return out_root


def _build_fork(
    fork: Fork,
    forks: dict[str, Fork],
    root: Path,
    out_root: Path,
    verbose: bool,
) -> None:
    sources = source_files(fork, forks)
    gindices = parse_gindex_annotations(sources)
    missing = _missing_gindices(sources, gindices)
    if missing:
        raise ValueError(
            f"{fork.name}: get_generalized_index constants missing (= N) annotations: "
            + ", ".join(sorted(missing))
        )

    dest = out_root / fork.name
    dest.mkdir(parents=True, exist_ok=True)
    if verbose:
        print(f"Building {fork.name} from {len(sources)} markdown files -> {dest}")

    for preset_name in PRESETS:
        preset_dir = root / "presets" / preset_name
        preset_files = sorted(preset_dir.glob("*.yaml"))
        config_file = root / "configs" / f"{preset_name}.yaml"
        spec_str = _build_spec(
            fork,
            forks,
            preset_name,
            sources,
            preset_files,
            config_file,
            gindices,
        )
        output = dest / f"{preset_name}.py"
        output.write_text(spec_str)
        if verbose:
            print(f"  wrote {output} ({len(spec_str):,} bytes)")

    (dest / "__init__.py").touch()


def _build_spec(
    fork: Fork,
    forks: dict[str, Fork],
    preset_name: str,
    sources: list[Path],
    preset_files: list[Path],
    config_file: Path,
    gindices: dict[str, int],
) -> str:
    preset = load_preset(tuple(preset_files))
    config = load_config(config_file)
    parsed = [get_spec(path, preset, config, preset_name) for path in sources]

    spec_object = parsed[0]
    for part in parsed[1:]:
        spec_object = combine_spec_objects(spec_object, part)
    spec_object = finalized_spec_object(spec_object)

    class_objects = {**spec_object.ssz_objects, **spec_object.dataclasses}
    new_objects: dict[str, str] = {}
    while OrderedDict(new_objects) != OrderedDict(class_objects):
        new_objects = copy.deepcopy(class_objects)
        dependency_order_class_objects(class_objects)

    redefined: set[str] = set()
    for source_file, parsed_file in zip(sources, parsed, strict=True):
        if f"/{fork.name}/" not in source_file.as_posix():
            continue
        redefined |= set(parsed_file.custom_types)
        redefined |= set(parsed_file.ssz_objects)
        redefined |= set(parsed_file.dataclasses)

    # collect_shared_types still reads PREVIOUS_FORK_OF from md_doc_paths.
    # Install the discovered graph there first.
    _install_previous_fork_of(forks)
    shared_types = collect_shared_types(fork.name, redefined, spec_object, class_objects)

    return emit_python(
        fork=fork,
        forks=forks,
        preset_name=preset_name,
        spec_object=spec_object,
        class_objects=class_objects,
        shared_types=shared_types,
        gindices=gindices,
    )


def _install_previous_fork_of(forks: dict[str, Fork]) -> None:
    mapping = {name: item.previous for name, item in forks.items()}
    md_doc_paths.PREVIOUS_FORK_OF = mapping
    generate_specs.PREVIOUS_FORK_OF = mapping


def _missing_gindices(sources: list[Path], annotated: dict[str, int]) -> set[str]:
    """Names whose markdown value is get_generalized_index but have no (= N)."""
    missing: set[str] = set()
    for path in sources:
        for match in GINDEX_NAME_RE.finditer(path.read_text()):
            if match.group(1) not in annotated:
                missing.add(match.group(1))
    return missing

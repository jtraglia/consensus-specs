"""Build every discovered fork into build/."""

from __future__ import annotations

from typing import TYPE_CHECKING

from compiler.backends.python import emit_python
from compiler.combine import inherited_classes, order_classes
from compiler.discover import build_order, discover_forks, repo_root, source_files
from compiler.parse import parse_file
from compiler.removals import removals_for
from compiler.yamlio import load_config, load_preset

if TYPE_CHECKING:
    from pathlib import Path

    from compiler.discover import Fork
    from compiler.removals import Removals

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
    dest = out_root / fork.name
    dest.mkdir(parents=True, exist_ok=True)
    if verbose:
        print(f"Building {fork.name} from {len(sources)} markdown files -> {dest}")

    removals = removals_for(fork, forks)
    for preset_name in PRESETS:
        yaml_presets = load_preset(tuple(sorted((root / "presets" / preset_name).glob("*.yaml"))))
        yaml_configs = load_config(root / "configs" / f"{preset_name}.yaml")
        spec_str = _build_spec(
            fork, forks, preset_name, sources, yaml_presets, yaml_configs, removals
        )
        output = dest / f"{preset_name}.py"
        output.write_text(spec_str)
        if verbose:
            print(f"  wrote {output} ({len(spec_str):,} bytes)")

    (dest / "__init__.py").write_text("")


def _build_spec(
    fork: Fork,
    forks: dict[str, Fork],
    preset_name: str,
    sources: list[Path],
    yaml_presets: dict[str, str],
    yaml_configs: dict[str, str | list],
    removals: Removals,
) -> str:
    parsed = [parse_file(path, yaml_presets, yaml_configs, preset_name) for path in sources]
    spec = parsed[0]
    for part in parsed[1:]:
        spec = spec.merge(part)
    spec.classes = order_classes(spec.classes)

    redefined: set[str] = set()
    for source_file, file_spec in zip(sources, parsed, strict=True):
        if f"/{fork.name}/" not in source_file.as_posix():
            continue
        redefined |= set(file_spec.classes)

    inherited = inherited_classes(fork.previous, redefined, spec.classes)
    return emit_python(
        spec=spec,
        fork=fork,
        forks=forks,
        preset_name=preset_name,
        yaml_presets=yaml_presets,
        yaml_configs=yaml_configs,
        inherited=inherited,
        removals=removals,
    )

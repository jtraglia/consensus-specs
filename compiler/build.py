"""Build every discovered fork into build/."""

from __future__ import annotations

from typing import TYPE_CHECKING

from compiler.backends.python import emit_python
from compiler.combine import inherited_classes, order_classes
from compiler.discover import (
    build_order,
    discover_forks,
    fork_markdown_files,
    repo_root,
    source_files,
)
from compiler.parse import parse_file
from compiler.removals import removals_for
from compiler.yamlio import write_config_yaml, write_preset_yaml

if TYPE_CHECKING:
    from pathlib import Path

    from compiler.discover import Fork
    from compiler.models import Spec, Value
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

    python_root = root / "build" / "python" / "eth_consensus_specs"
    pyspec_root = root / "tests" / "core" / "pyspec"
    configs_acc: dict[str, Value] = {}
    preset_env: dict[str, dict[str, int]] = {name: {} for name in PRESETS}
    for fork in targets:
        own = _parse_sources(source_files(fork, forks))
        _build_fork(fork, forks, python_root, own, removals_for(fork, forks), verbose)
        own_only = _parse_sources(_own_sources(fork))
        for preset_name in PRESETS:
            preset_env[preset_name] = write_preset_yaml(
                root / "build" / "presets" / preset_name / f"{fork.name}.yaml",
                own_only.presets,
                preset_name,
                preset_env[preset_name],
                fork_name=fork.name,
                python_root=python_root.parent,
                pyspec_root=pyspec_root,
            )
        configs_acc = {**configs_acc, **own_only.configs}

    for preset_name in PRESETS:
        write_config_yaml(
            root / "build" / "configs" / f"{preset_name}.yaml", configs_acc, preset_name
        )

    return python_root


def _build_fork(
    fork: Fork,
    forks: dict[str, Fork],
    python_root: Path,
    spec: Spec,
    removals: Removals,
    verbose: bool,
) -> None:
    dest = python_root / fork.name
    dest.mkdir(parents=True, exist_ok=True)
    if verbose:
        print(f"Building {fork.name} -> {dest}")

    spec.classes = order_classes(spec.classes)
    own_names = set(_parse_sources(_own_sources(fork)).classes)
    inherited = inherited_classes(fork.previous, own_names, spec.classes)
    for preset_name in PRESETS:
        spec_str = emit_python(
            spec=spec,
            fork=fork,
            forks=forks,
            preset_name=preset_name,
            inherited=inherited,
            removals=removals,
        )
        output = dest / f"{preset_name}.py"
        output.write_text(spec_str)
        if verbose:
            print(f"  wrote {output} ({len(spec_str):,} bytes)")
    (dest / "__init__.py").write_text("")


def _parse_sources(sources: list[Path]) -> Spec:
    parsed = [parse_file(path) for path in sources]
    spec = parsed[0]
    for part in parsed[1:]:
        spec = spec.merge(part)
    return spec


def _own_sources(fork: Fork) -> list[Path]:
    return fork_markdown_files(fork.directory)

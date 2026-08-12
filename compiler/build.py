"""Build every discovered fork into build/."""

from __future__ import annotations

from typing import TYPE_CHECKING

from compiler.discover import build_order, discover_forks, repo_root
from compiler.emit import emit_python, write_config_yaml, write_preset_yaml
from compiler.models import Spec
from compiler.parse import parse_file

if TYPE_CHECKING:
    from pathlib import Path

    from compiler.discover import Fork
    from compiler.models import Value

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
        spec = _parse_fork(fork, forks)
        _write_python(fork, forks, spec, python_root, verbose)
        own = _parse_files(fork.markdown_files())
        for preset_name in PRESETS:
            preset_env[preset_name] = write_preset_yaml(
                root / "build" / "presets" / preset_name / f"{fork.name}.yaml",
                own.presets,
                preset_name,
                preset_env[preset_name],
                fork_name=fork.name,
                python_root=python_root.parent,
                pyspec_root=pyspec_root,
            )
        configs_acc = {**configs_acc, **own.configs}

    for preset_name in PRESETS:
        write_config_yaml(
            root / "build" / "configs" / f"{preset_name}.yaml", configs_acc, preset_name
        )
    return python_root


def _write_python(
    fork: Fork,
    forks: dict[str, Fork],
    spec: Spec,
    python_root: Path,
    verbose: bool,
) -> None:
    dest = python_root / fork.name
    dest.mkdir(parents=True, exist_ok=True)
    if verbose:
        print(f"Building {fork.name} -> {dest}")
    removals = fork.removals(forks)
    for preset_name in PRESETS:
        output = dest / f"{preset_name}.py"
        output.write_text(emit_python(spec, fork, forks, preset_name, removals))
        if verbose:
            print(f"  wrote {output} ({len(output.read_text()):,} bytes)")
    (dest / "__init__.py").write_text("")


def _parse_fork(fork: Fork, forks: dict[str, Fork]) -> Spec:
    spec = Spec()
    previous: str | None = None
    for ancestor in fork.lineage(forks):
        if previous is not None:
            spec = spec.qualify_gindices(previous)
        spec = spec.merge(_parse_files(ancestor.markdown_files()))
        previous = ancestor.name
    return spec


def _parse_files(paths: list[Path]) -> Spec:
    spec = Spec()
    for path in paths:
        spec = spec.merge(parse_file(path))
    return spec

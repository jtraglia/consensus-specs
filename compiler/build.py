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


class Builder:
    def __init__(
        self,
        *,
        root: Path | None = None,
        only: str | None = None,
        verbose: bool = False,
    ) -> None:
        self.root = root or repo_root()
        self.only = only
        self.verbose = verbose
        self.forks = discover_forks(self.root)
        self.python_root = self.root / "build" / "python" / "eth_consensus_specs"
        self.pyspec_root = self.root / "tests" / "core" / "pyspec"

    def run(self) -> Path:
        targets = [
            fork for fork in build_order(self.forks) if self.only is None or fork.name == self.only
        ]
        if self.only is not None and not targets:
            raise ValueError(f"unknown fork: {self.only}")

        configs_acc: dict[str, Value] = {}
        preset_env: dict[str, dict[str, int]] = {name: {} for name in PRESETS}
        for fork in targets:
            spec = self.parse_fork(fork)
            self.write_python(fork, spec)
            own = self.parse_files(fork.markdown_files())
            for preset_name in PRESETS:
                preset_env[preset_name] = write_preset_yaml(
                    self.root / "build" / "presets" / preset_name / f"{fork.name}.yaml",
                    own.presets,
                    preset_name,
                    preset_env[preset_name],
                    fork_name=fork.name,
                    python_root=self.python_root.parent,
                    pyspec_root=self.pyspec_root,
                )
            configs_acc = {**configs_acc, **own.configs}

        for preset_name in PRESETS:
            write_config_yaml(
                self.root / "build" / "configs" / f"{preset_name}.yaml",
                configs_acc,
                preset_name,
            )
        return self.python_root

    def write_python(self, fork: Fork, spec: Spec) -> None:
        dest = self.python_root / fork.name
        dest.mkdir(parents=True, exist_ok=True)
        if self.verbose:
            print(f"Building {fork.name} -> {dest}")
        removals = fork.removals(self.forks)
        for preset_name in PRESETS:
            output = dest / f"{preset_name}.py"
            output.write_text(emit_python(spec, fork, self.forks, preset_name, removals))
            if self.verbose:
                print(f"  wrote {output} ({len(output.read_text()):,} bytes)")
        (dest / "__init__.py").write_text("")

    def parse_fork(self, fork: Fork) -> Spec:
        spec = Spec()
        for ancestor in fork.lineage(self.forks):
            spec = spec.merge(self.parse_files(ancestor.markdown_files()))
        return spec

    def parse_files(self, paths: list[Path]) -> Spec:
        spec = Spec()
        for path in paths:
            spec = spec.merge(parse_file(path))
        return spec


def build(
    *,
    root: Path | None = None,
    only: str | None = None,
    verbose: bool = False,
) -> Path:
    return Builder(root=root, only=only, verbose=verbose).run()

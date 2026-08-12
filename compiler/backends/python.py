"""Emit a Python module for one fork and preset."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysetup import helpers
from pysetup.helpers import objects_to_spec
from pysetup.spec_builders import spec_builders
from pysetup.spec_builders.base import BaseSpecBuilder

if TYPE_CHECKING:
    from compiler.discover import Fork
    from pysetup.typing import SpecObject


def emit_python(
    *,
    fork: Fork,
    forks: dict[str, Fork],
    preset_name: str,
    spec_object: SpecObject,
    class_objects: dict[str, str],
    shared_types: dict[str, str],
    gindices: dict[str, int],
) -> str:
    """Render one Python module. SpecBuilder classes are used only for leftover stubs."""
    _install_adapters(forks, gindices)
    return objects_to_spec(preset_name, spec_object, fork.name, class_objects, shared_types)


def _install_adapters(forks: dict[str, Fork], gindices: dict[str, int]) -> None:
    """Point pysetup helpers at discovered forks and markdown gindices."""
    helpers.PREVIOUS_FORK_OF = {name: item.previous for name, item in forks.items()}
    helpers.spec_builders = {name: _adapter_class(item, gindices) for name, item in forks.items()}


def _adapter_class(fork: Fork, gindices: dict[str, int]) -> type:
    base = spec_builders.get(fork.name, BaseSpecBuilder)
    previous = fork.previous
    fork_name = fork.name

    class Adapter(base):
        fork = fork_name

        @classmethod
        def imports(cls, preset_name: str) -> str:
            if previous is None:
                return "from eth_consensus_specs.runtime import *\n"
            return f"from eth_consensus_specs.{previous} import {preset_name} as {previous}\n"

        @classmethod
        def hardcoded_ssz_dep_constants(cls) -> dict[str, str]:
            return {name: f"GeneralizedIndex({value})" for name, value in gindices.items()}

        @classmethod
        def hardcoded_func_dep_presets(cls, spec_object: SpecObject) -> dict[str, str]:
            return {
                name: spec_object.preset_vars[name].value
                for name in spec_object.func_dep_presets
                if name in spec_object.preset_vars
            }

    Adapter.__name__ = f"{fork.name.title().replace('_', '')}Adapter"
    return Adapter

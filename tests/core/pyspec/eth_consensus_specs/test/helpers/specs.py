from .constants import (
    ALL_PHASES,
    MAINNET,
    MINIMAL,
)
from .typing import (
    PresetBaseName,
    Spec,
    SpecForkName,
)

ALL_EXECUTABLE_SPEC_NAMES = ALL_PHASES

# During the eth-ssz-specs migration, only some forks have been migrated. Import each
# fork's spec best-effort so that a fork that is not yet migrated (and therefore fails
# to import) does not block running the migrated forks' tests.
# TODO: remove this tolerance once every fork is migrated.
_MIGRATED_FORKS = {"phase0"}

_loaded_minimal: dict[SpecForkName, Spec] = {}
_loaded_mainnet: dict[SpecForkName, Spec] = {}
for fork in ALL_EXECUTABLE_SPEC_NAMES:
    namespace: dict = {}
    try:
        exec(
            f"from eth_consensus_specs.{fork} import mainnet as _mainnet, minimal as _minimal",
            namespace,
        )
    except Exception:
        if fork in _MIGRATED_FORKS:
            raise
        continue
    _loaded_minimal[fork] = namespace["_minimal"]
    _loaded_mainnet[fork] = namespace["_mainnet"]

# this is the only output of this file
spec_targets: dict[PresetBaseName, dict[SpecForkName, Spec]] = {
    MINIMAL: _loaded_minimal,
    MAINNET: _loaded_mainnet,
}

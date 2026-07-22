"""
Post-build invariant check for fork-type inheritance.

Types a fork does not redefine are emitted as aliases to the previous fork's
class (e.g. `Slot = deneb.Slot` in electra) rather than fresh definitions, so
values flow across fork boundaries without exact-type mismatches. This script
runs after the specs are generated and fails loudly if that aliasing ever
regresses, so the problem surfaces at compile time instead of test time.

Two kinds of checks are performed for every adjacent fork pair in
`ENABLED_FORKS` and every preset:

1. Structural: every `name = <prev>.name` line in a module's inherited-aliases
   block must still resolve to the *same* object as the previous fork's
   attribute. This catches later shadowing -- if a subsequent section of the
   generated module re-defines an aliased name, identity silently breaks.

2. Semantic: a small curated list of types whose sharing behavior is
   load-bearing and easy to reason about (see `SHARED_ACROSS_ALL_FORKS`,
   `BeaconState`, `Attestation`). Keep this list small; extend it only when a
   new fork introduces a sharing boundary worth pinning.
"""

import importlib
import itertools
import re
import sys
from pathlib import Path
from types import ModuleType

# The compiled spec package lives under tests/core/pyspec while the pysetup
# package lives at the repo root. Make both importable regardless of how this
# script is invoked (`python -m pysetup.verify_type_inheritance` or a direct
# path), and resolve `eth_consensus_specs` the same way the tests do.
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
PYSPEC_DIR = REPO_ROOT / "tests" / "core" / "pyspec"
# When run by path, Python puts this script's directory (the pysetup package
# dir) on sys.path, where pysetup/typing.py would shadow the stdlib `typing`
# module that the generated specs import. Drop it so both invocation styles
# behave like `-m pysetup.verify_type_inheritance`.
sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() != SCRIPT_DIR]
for _path in (str(REPO_ROOT), str(PYSPEC_DIR)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from pysetup.constants import ENABLED_FORKS  # noqa: E402
from pysetup.md_doc_paths import PREVIOUS_FORK_OF  # noqa: E402

# Build targets always compiled by `make _pyspec` (see generate_specs.py).
PRESETS = ("minimal", "mainnet")

# Header that opens the inherited-aliases block emitted by objects_to_spec().
ALIAS_BLOCK_HEADER = "# Types inherited unchanged from "

# Matches a single alias line, e.g. `Slot = deneb.Slot`. Group 1 is the type
# name; group 2 is the previous-fork module alias. The `\1` backreference
# requires both sides to name the same type.
ALIAS_LINE = re.compile(r"^(\w+) = (\w+)\.\1$")

# --- Curated semantic invariants -------------------------------------------
# Primitive/value types no migrated fork has ever redefined; they must be the
# identical object in every enabled fork so arithmetic and comparisons flow
# across boundaries. Add here only when a truly fork-invariant type appears.
SHARED_ACROSS_ALL_FORKS = (
    "Slot",
    "Epoch",
    "Gwei",
    "Root",
    "ValidatorIndex",
    "Checkpoint",
    "AttestationData",
)
# `Attestation` gained `committee_bits` in electra (EIP-7549); it is shared
# across phase0..deneb and must differ at the deneb->electra boundary.
ATTESTATION_SHARED_FORKS = ("phase0", "altair", "bellatrix", "capella", "deneb")
ATTESTATION_CHANGED_AT = ("deneb", "electra")


def module_path(fork: str, preset: str) -> Path:
    """Return the path to a generated spec module."""
    return PYSPEC_DIR / "eth_consensus_specs" / fork / f"{preset}.py"


def parse_alias_lines(path: Path) -> dict[str, str]:
    """
    Extract the inherited-type aliases from a generated module.

    Returns a mapping of type name to the previous-fork module alias it points
    at (e.g. `{"Slot": "deneb"}`). Forks without a previous fork (phase0) or
    with nothing inherited return an empty mapping.
    """
    aliases: dict[str, str] = {}
    lines = path.read_text().splitlines()
    in_block = False
    for line in lines:
        if line.startswith(ALIAS_BLOCK_HEADER):
            in_block = True
            continue
        if not in_block:
            continue
        # The block is a contiguous run of alias lines terminated by a blank
        # line separating it from the next section.
        if line == "":
            break
        match = ALIAS_LINE.match(line)
        if match is None:
            break
        aliases[match.group(1)] = match.group(2)
    return aliases


def load_module(fork: str, preset: str) -> ModuleType:
    """Import a generated spec module via its canonical package path."""
    return importlib.import_module(f"eth_consensus_specs.{fork}.{preset}")


def check_aliases(fork: str, preset: str, errors: list[str]) -> int:
    """
    Verify every alias line in `fork`/`preset` still resolves to the identical
    object in the previous fork. Returns the number of aliases checked.
    """
    prev = PREVIOUS_FORK_OF[fork]
    if prev is None or prev not in ENABLED_FORKS:
        return 0

    aliases = parse_alias_lines(module_path(fork, preset))
    if not aliases:
        # Every enabled non-genesis fork inherits at least some types; an empty
        # block means the header/format changed and parsing silently broke.
        errors.append(
            f"{fork}/{preset}: no inherited aliases parsed -- the alias block "
            f"format may have changed (expected lines under "
            f"'{ALIAS_BLOCK_HEADER}{prev}')"
        )
        return 0

    mod = load_module(fork, preset)
    prev_mod = load_module(prev, preset)
    for name, module_alias in aliases.items():
        if module_alias != prev:
            errors.append(
                f"{fork}/{preset}: alias '{name}' points at '{module_alias}' "
                f"but the previous fork is '{prev}'"
            )
            continue
        if getattr(mod, name) is not getattr(prev_mod, name):
            errors.append(
                f"{fork}/{preset}: '{name}' is aliased to {prev}.{name} but is "
                f"not identical to it -- a later section likely re-defines it"
            )
    return len(aliases)


def check_semantic_invariants(preset: str, errors: list[str]) -> None:
    """Verify the curated cross-fork sharing invariants for a preset."""
    # ENABLED_FORKS is the contiguous fork chain, so its neighbours are the
    # adjacent fork pairs used below.
    enabled = list(ENABLED_FORKS)
    mods = {fork: load_module(fork, preset) for fork in enabled}

    # 1. Fork-invariant types are the identical object in every enabled fork.
    for name in SHARED_ACROSS_ALL_FORKS:
        reference = getattr(mods[enabled[0]], name)
        for fork in enabled[1:]:
            if getattr(mods[fork], name) is not reference:
                errors.append(
                    f"{preset}: '{name}' must be identical across all enabled "
                    f"forks but {fork}.{name} differs from {enabled[0]}.{name}"
                )

    # 2. BeaconState changes at every fork, so adjacent forks must differ.
    for prev, fork in itertools.pairwise(enabled):
        if mods[fork].BeaconState is mods[prev].BeaconState:
            errors.append(
                f"{preset}: BeaconState must differ between adjacent forks but "
                f"{fork}.BeaconState is identical to {prev}.BeaconState"
            )

    # 3. Attestation is shared across phase0..deneb and changes in electra.
    shared = [fork for fork in ATTESTATION_SHARED_FORKS if fork in mods]
    if len(shared) > 1:
        reference = mods[shared[0]].Attestation
        for fork in shared[1:]:
            if mods[fork].Attestation is not reference:
                errors.append(
                    f"{preset}: Attestation must be shared across "
                    f"{shared[0]}..deneb but {fork}.Attestation differs"
                )
    before, after = ATTESTATION_CHANGED_AT
    if before in mods and after in mods:
        if mods[after].Attestation is mods[before].Attestation:
            errors.append(
                f"{preset}: Attestation must differ between {before} and {after} "
                f"(EIP-7549) but they are identical"
            )


def main() -> int:
    """Run all inheritance checks; return 0 on success, 1 on any violation."""
    errors: list[str] = []

    print("Verifying fork-type inheritance invariants...")
    for preset in PRESETS:
        for fork in ENABLED_FORKS:
            count = check_aliases(fork, preset, errors)
            if count:
                prev = PREVIOUS_FORK_OF[fork]
                print(f"  {fork}/{preset}: {count} inherited aliases identical to {prev}")
        check_semantic_invariants(preset, errors)
        print(f"  {preset}: curated semantic invariants OK")

    if errors:
        print("\nfork-type inheritance check FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("All fork-type inheritance invariants hold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

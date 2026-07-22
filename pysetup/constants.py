# Definitions in context.py
PHASE0 = "phase0"
ALTAIR = "altair"
BELLATRIX = "bellatrix"
CAPELLA = "capella"
DENEB = "deneb"
ELECTRA = "electra"
FULU = "fulu"
GLOAS = "gloas"
HEZE = "heze"
EIP8025 = "eip8025"
EIP8148 = "eip8148"

# Forks compiled by `--all-forks`. phase0 through fulu have been migrated to
# eth-ssz-specs; gloas, heze, and the eip* forks are not built yet because they
# rely on progressive-SSZ types the library does not provide. Their spec files
# are kept in the tree; add a fork here once it is migrated.
ENABLED_FORKS = [PHASE0, ALTAIR, BELLATRIX, CAPELLA, DENEB, ELECTRA, FULU]


# The helper functions that are used when defining constants
CONSTANT_DEP_SUNDRY_CONSTANTS_FUNCTIONS = """
def ceillog2(x: Uint64) -> Uint64:
    if x < 1:
        raise ValueError(f"ceillog2 accepts only positive values, x={x}")
    return Uint64((x - Uint64(1)).bit_length())


def floorlog2(x: Uint64) -> Uint64:
    if x < 1:
        raise ValueError(f"floorlog2 accepts only positive values, x={x}")
    return Uint64(x.bit_length() - 1)
"""


OPTIMIZED_BLS_AGGREGATE_PUBKEYS = """
def eth_aggregate_pubkeys(pubkeys: Sequence[BLSPubkey]) -> BLSPubkey:
    return bls.AggregatePKs(pubkeys)
"""

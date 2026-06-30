from pysetup.constants import GLOAS

from .base import BaseSpecBuilder


class GloasSpecBuilder(BaseSpecBuilder):
    fork: str = GLOAS

    @classmethod
    def imports(cls, preset_name: str):
        return f"""
from eth_consensus_specs.fulu import {preset_name} as fulu
"""

    @classmethod
    def hardcoded_ssz_dep_constants(cls) -> dict[str, str]:
        return {
            "EXECUTION_BLOCK_HASH_GINDEX": "GeneralizedIndex(412)",
            "EXECUTION_BLOCK_HASH_GINDEX_DENEB": "GeneralizedIndex(812)",
            "EXECUTION_BLOCK_HASH_GINDEX_GLOAS": "GeneralizedIndex(832)",
        }

    @classmethod
    def sundry_functions(cls) -> str:
        return """
def retrieve_column_sidecars_and_kzg_commitments(
    beacon_block_root: Root
) -> tuple[Sequence[DataColumnSidecar], Sequence[KZGCommitment]]:
    return [], []

_get_parent_payload_status = get_parent_payload_status
get_parent_payload_status = cache_this(
    lambda store, block: block.hash_tree_root(),
    _get_parent_payload_status, lru_size=1024)
"""

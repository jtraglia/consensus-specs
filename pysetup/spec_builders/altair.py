from pysetup.constants import ALTAIR, OPTIMIZED_BLS_AGGREGATE_PUBKEYS

from .base import BaseSpecBuilder


class AltairSpecBuilder(BaseSpecBuilder):
    fork: str = ALTAIR

    @classmethod
    def imports(cls, preset_name: str) -> str:
        return f"""
from eth_consensus_specs.phase0 import {preset_name} as phase0
from ssz import compute_merkle_proof as ssz_compute_merkle_proof
from ssz import get_generalized_index
"""

    @classmethod
    def preparations(cls):
        return """
GeneralizedIndex = int
"""

    @classmethod
    def sundry_functions(cls) -> str:
        return """
# The in-document definition is a stub; the SSZ library provides the implementation.
compute_merkle_proof = ssz_compute_merkle_proof"""

    @classmethod
    def hardcoded_ssz_dep_constants(cls) -> dict[str, str]:
        return {
            "FINALIZED_ROOT_GINDEX": "GeneralizedIndex(105)",
            "CURRENT_SYNC_COMMITTEE_GINDEX": "GeneralizedIndex(54)",
            "NEXT_SYNC_COMMITTEE_GINDEX": "GeneralizedIndex(55)",
        }

    @classmethod
    def implement_optimizations(cls, functions: dict[str, str]) -> dict[str, str]:
        if "eth_aggregate_pubkeys" in functions:
            functions["eth_aggregate_pubkeys"] = OPTIMIZED_BLS_AGGREGATE_PUBKEYS.strip()
        return functions

    @classmethod
    def deprecate_containers(cls) -> set[str]:
        return {
            "PendingAttestation",
            "PendingAttestations",
        }

    @classmethod
    def deprecate_functions(cls) -> set[str]:
        return {
            "get_attestation_component_deltas",
            "get_attestation_deltas",
            "get_attesting_balance",
            "get_head_deltas",
            "get_inclusion_delay_deltas",
            "get_matching_head_attestations",
            "get_matching_source_attestations",
            "get_matching_target_attestations",
            "get_proposer_reward",
            "get_source_deltas",
            "get_target_deltas",
            "get_unslashed_attesting_indices",
            "initialize_beacon_state_from_eth1",
            "is_valid_genesis_state",
            "process_participation_record_updates",
        }

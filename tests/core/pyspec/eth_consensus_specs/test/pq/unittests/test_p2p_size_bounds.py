from eth_consensus_specs.test.context import (
    single_phase,
    spec_test,
    with_pq_and_later,
)
from eth_consensus_specs.test.helpers.p2p_size_bounds import (
    build_max_size_signed_global_aggregate_and_proof,
)


@with_pq_and_later
@spec_test
@single_phase
def test_max_signed_global_aggregate_and_proof_size(spec):
    encoded = build_max_size_signed_global_aggregate_and_proof(spec).encode_bytes()
    assert len(encoded) == spec.MAX_SIGNED_GLOBAL_AGGREGATE_AND_PROOF_SIZE_PQ

from eth_consensus_specs.test.context import (
    single_phase,
    spec_state_test,
    spec_test,
    with_pq_and_later,
    with_presets,
)
from eth_consensus_specs.test.helpers.attestations import (
    get_aggregate_and_proof,
    get_aggregator_index,
    get_valid_attestations_at_slot,
)
from eth_consensus_specs.test.helpers.constants import MINIMAL
from eth_consensus_specs.test.helpers.keys import privkeys
from eth_consensus_specs.test.helpers.state import next_slot


@with_pq_and_later
@spec_test
@single_phase
def test_global_aggregate_constants(spec):
    assert spec.LEAF_OFFSET_GLOBAL_AGGREGATE_AND_PROOF == 6
    assert spec.LEAF_OFFSET_GLOBAL_AGGREGATE_AND_PROOF < spec.XMSS_LEAVES_PER_SLOT
    other_offsets = {
        spec.LEAF_OFFSET_BEACON_PROPOSER,
        spec.LEAF_OFFSET_AGGREGATE_AND_PROOF,
        spec.LEAF_OFFSET_PTC_ATTESTER,
        spec.LEAF_OFFSET_PROPOSER_PREFERENCES,
        spec.LEAF_OFFSET_EXECUTION_PAYLOAD_BID,
        spec.LEAF_OFFSET_EXECUTION_PAYLOAD_ENVELOPE,
    }
    assert spec.LEAF_OFFSET_GLOBAL_AGGREGATE_AND_PROOF not in other_offsets
    assert spec.config.AGGREGATE_DUE_BPS_GLOAS < spec.config.GLOBAL_AGGREGATE_DUE_BPS
    assert spec.config.GLOBAL_AGGREGATE_DUE_BPS <= spec.BASIS_POINTS
    assert spec.get_global_aggregate_due_ms() == spec.get_slot_component_duration_ms(
        spec.config.GLOBAL_AGGREGATE_DUE_BPS
    )


def get_network_aggregates(spec, state, attestations):
    """The ``AggregateAndProof`` of each per-committee ``attestation``."""
    network_aggregates = []
    for attestation in attestations:
        committee_index = spec.get_committee_indices(attestation.committee_bits)[0]
        aggregator_index = get_aggregator_index(spec, state, attestation.data.slot, committee_index)
        network_aggregates.append(
            get_aggregate_and_proof(
                spec, state, aggregator_index, attestation, privkeys[aggregator_index]
            )
        )
    return network_aggregates


@with_pq_and_later
@spec_state_test
@with_presets([MINIMAL], "need multiple committees per slot")
def test_compute_global_aggregate_one_data(spec, state):
    next_slot(spec, state)
    attestations = get_valid_attestations_at_slot(state, spec, state.slot)
    committee_count = spec.get_committee_count_per_slot(state, spec.get_current_epoch(state))
    assert len(attestations) == committee_count >= 2

    global_attestations, proof = spec.compute_global_aggregate(
        get_network_aggregates(spec, state, attestations)
    )

    assert len(global_attestations) == 1
    merged = global_attestations[0]
    assert spec.get_committee_indices(merged.committee_bits) == list(range(committee_count))
    expected_indices = set()
    for attestation in attestations:
        expected_indices |= spec.get_attesting_indices(state, attestation)
    assert spec.get_attesting_indices(state, merged) == expected_indices
    statements = spec.get_attestation_statements(state, merged)
    assert len(statements) == committee_count
    assert spec.stark.VerifyAggregates(statements, proof)


@with_pq_and_later
@spec_state_test
@with_presets([MINIMAL], "need multiple committees per slot")
def test_compute_global_aggregate_two_data(spec, state):
    next_slot(spec, state)
    attestations = get_valid_attestations_at_slot(state, spec, state.slot)
    assert len(attestations) >= 2
    # A second data: committee 1 voted for another head
    attestations[1].data.beacon_block_root = spec.Root(b"\x42" * 32)
    network_aggregates = get_network_aggregates(spec, state, attestations)

    global_attestations, proof = spec.compute_global_aggregate(network_aggregates)

    assert len(global_attestations) == 2
    roots = [spec.hash_tree_root(a.data) for a in global_attestations]
    assert roots == sorted(roots)
    covered = set()
    for attestation in global_attestations:
        covered.update(spec.get_committee_indices(attestation.committee_bits))
    assert covered == set(range(len(attestations)))
    statements = []
    for attestation in global_attestations:
        statements.extend(spec.get_attestation_statements(state, attestation))
    assert spec.stark.VerifyAggregates(statements, proof)

from eth_consensus_specs.test.context import (
    single_phase,
    spec_test,
    with_pq_and_later,
)


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

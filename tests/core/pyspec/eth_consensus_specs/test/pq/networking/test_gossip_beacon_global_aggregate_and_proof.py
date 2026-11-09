from eth_consensus_specs.test.context import (
    spec_state_test,
    with_pq_and_later,
    with_presets,
)
from eth_consensus_specs.test.helpers.attestations import (
    get_aggregate_and_proof,
    get_aggregator_index,
    get_valid_attestations_at_slot,
)
from eth_consensus_specs.test.helpers.constants import MINIMAL
from eth_consensus_specs.test.helpers.fork_choice import (
    get_genesis_forkchoice_store_and_block,
)
from eth_consensus_specs.test.helpers.gossip import (
    get_filename,
    get_seen,
    run_validate_gossip,
    wrap_genesis_block,
)
from eth_consensus_specs.test.helpers.keys import privkeys
from eth_consensus_specs.test.helpers.state import next_slot


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


def sign_global_aggregate(spec, state, validator_index, attestations, proof):
    message = spec.GlobalAggregateAndProof(
        validator_index=validator_index,
        attestations=attestations,
        proof=proof,
    )
    signature = spec.get_global_aggregate_and_proof_signature(
        state, message, privkeys[validator_index]
    )
    return spec.SignedGlobalAggregateAndProof(message=message, signature=signature)


def create_signed_global_aggregate(spec, state, attestations, validator_index=0):
    attestations, proof = spec.compute_global_aggregate(
        get_network_aggregates(spec, state, attestations)
    )
    return sign_global_aggregate(spec, state, validator_index, attestations, proof)


def prepare(spec, state):
    """
    A store at genesis, its anchor block, and the per-committee attestations
    of the next slot voting for the anchor.
    """
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)
    anchor_root = anchor_block.hash_tree_root()
    next_slot(spec, state)
    attestations = get_valid_attestations_at_slot(
        state, spec, state.slot, beacon_block_root=anchor_root
    )
    return store, signed_anchor, attestations


def run(spec, store, seen, signed, current_time_ms):
    return run_validate_gossip(
        spec,
        seen=seen,
        store=store,
        signed_global_aggregate_and_proof=signed,
        current_time_ms=current_time_ms,
        block_payload_statuses={},
    )


def time_for(spec, store, attestations):
    slot = attestations[0].data.slot
    return spec.compute_time_at_slot_ms(store.genesis_time_ms, slot) + 500


def message_meta(current_time_ms, signed, expected):
    return {
        "current_time_ms": int(current_time_ms),
        "message": get_filename(signed),
        "expected": expected,
    }


@with_pq_and_later
@spec_state_test
@with_presets([MINIMAL], "need multiple committees per slot")
def test_gossip_global_aggregate__valid_full_coverage(spec, state):
    """A global aggregate over every committee of the slot is accepted."""
    anchor_state = state.copy()
    yield "topic", "meta", "beacon_global_aggregate_and_proof"
    yield "state", anchor_state

    store, signed_anchor, attestations = prepare(spec, state)
    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]
    assert len(attestations) >= 2

    signed = create_signed_global_aggregate(spec, state, attestations)
    yield get_filename(signed), signed

    seen = get_seen(spec)
    current_time_ms = time_for(spec, store, attestations)
    result, reason = run(spec, store, seen, signed, current_time_ms)
    assert result == "valid", reason
    assert (attestations[0].data.slot, spec.ValidatorIndex(0)) in seen.global_aggregator_slots

    yield "messages", "meta", [message_meta(current_time_ms, signed, "valid")]

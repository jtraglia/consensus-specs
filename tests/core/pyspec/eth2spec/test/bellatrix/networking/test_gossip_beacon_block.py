from eth2spec.test.context import (
    spec_state_test,
    with_bellatrix_and_later,
)
from eth2spec.test.helpers.block import (
    build_empty_block_for_next_slot,
    sign_block,
)
from eth2spec.test.helpers.execution_payload import (
    build_state_with_complete_transition,
)
from eth2spec.test.helpers.fork_choice import (
    get_genesis_forkchoice_store_and_block,
)
from eth2spec.test.helpers.gossip import get_filename, get_seen
from eth2spec.test.helpers.state import (
    state_transition_and_sign_block,
)


def wrap_genesis_block(spec, block):
    """Wrap an unsigned genesis block in a SignedBeaconBlock with empty signature."""
    return spec.SignedBeaconBlock(message=block)


def run_validate_beacon_block_gossip(spec, seen, store, state, signed_block, current_time_ms):
    """
    Run validate_beacon_block_gossip and return the result.
    Returns: tuple of (result, reason) where result is "valid", "ignore", or "reject"
             and reason is the exception message (or None for valid).
    """
    try:
        spec.validate_beacon_block_gossip(seen, store, state, signed_block, current_time_ms)
        return "valid", None
    except spec.GossipIgnore as e:
        return "ignore", str(e)
    except spec.GossipReject as e:
        return "reject", str(e)


@with_bellatrix_and_later
@spec_state_test
def test_gossip_beacon_block__reject_wrong_execution_payload_timestamp(spec, state):
    """
    Test that a post-merge block with wrong execution_payload.timestamp is rejected.
    """
    yield "topic", "meta", "beacon_block"

    # Transition to post-merge state
    state = build_state_with_complete_transition(spec, state)

    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    # Build a valid block for the next slot
    block = build_empty_block_for_next_slot(spec, state)

    # Tamper with execution payload timestamp
    block.body.execution_payload.timestamp = block.body.execution_payload.timestamp + 1

    # Sign without state transition (since block is invalid)
    signed_block = sign_block(spec, state, block)

    yield get_filename(signed_block), signed_block

    block_time_ms = spec.compute_time_at_slot_ms(store, signed_block.message.slot)

    yield "current_time_ms", "meta", int(block_time_ms)

    result, reason = run_validate_beacon_block_gossip(
        spec, seen, store, state, signed_block, block_time_ms + 500
    )
    assert result == "reject"
    assert reason == "incorrect execution payload timestamp"

    yield (
        "messages",
        "meta",
        [
            {
                "offset_ms": 500,
                "message": get_filename(signed_block),
                "expected": "reject",
                "reason": reason,
            }
        ],
    )


@with_bellatrix_and_later
@spec_state_test
def test_gossip_beacon_block__valid_post_merge(spec, state):
    """
    Test that a valid post-merge block passes gossip validation.
    """
    yield "topic", "meta", "beacon_block"

    # Transition to post-merge state
    state = build_state_with_complete_transition(spec, state)

    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    block = build_empty_block_for_next_slot(spec, state)
    signed_block = state_transition_and_sign_block(spec, state, block)

    yield get_filename(signed_block), signed_block

    block_time_ms = spec.compute_time_at_slot_ms(store, signed_block.message.slot)

    yield "current_time_ms", "meta", int(block_time_ms)

    result, reason = run_validate_beacon_block_gossip(
        spec, seen, store, state, signed_block, block_time_ms + 500
    )
    assert result == "valid"
    assert reason is None

    yield (
        "messages",
        "meta",
        [{"offset_ms": 500, "message": get_filename(signed_block), "expected": "valid"}],
    )

from eth2spec.test.context import (
    spec_state_test,
    with_phases,
)
from eth2spec.test.helpers.block import (
    build_empty_block_for_next_slot,
)
from eth2spec.test.helpers.constants import ALTAIR
from eth2spec.test.helpers.fork_choice import (
    get_genesis_forkchoice_store_and_block,
)
from eth2spec.test.helpers.gossip import get_filename, get_seen
from eth2spec.test.helpers.keys import privkeys
from eth2spec.test.helpers.sync_committee import (
    compute_committee_indices,
)
from eth2spec.utils import bls


def wrap_genesis_block(spec, block):
    """Wrap an unsigned genesis block in a SignedBeaconBlock with empty signature."""
    return spec.SignedBeaconBlock(message=block)


def get_valid_sync_committee_message(spec, state, slot, validator_index, block_root=None):
    """Create a valid SyncCommitteeMessage for the given validator and slot."""
    if block_root is None:
        block_root = build_empty_block_for_next_slot(spec, state).parent_root

    privkey = privkeys[validator_index]
    domain = spec.get_domain(state, spec.DOMAIN_SYNC_COMMITTEE, spec.compute_epoch_at_slot(slot))
    signing_root = spec.compute_signing_root(block_root, domain)
    signature = bls.Sign(privkey, signing_root)

    return spec.SyncCommitteeMessage(
        slot=slot,
        beacon_block_root=block_root,
        validator_index=validator_index,
        signature=signature,
    )


def get_sync_committee_member_and_subnet(spec, state):
    """Find a validator in the current sync committee and a valid subnet for them."""
    committee_indices = compute_committee_indices(state)
    for validator_index in committee_indices:
        subnets = spec.compute_subnets_for_sync_committee(state, validator_index)
        if len(subnets) > 0:
            subnet_id = sorted(subnets)[0]
            return validator_index, subnet_id
    raise Exception("No sync committee member found")


def run_validate_sync_committee_message_gossip(
    spec, seen, store, state, sync_committee_message, subnet_id, current_time_ms
):
    """
    Run validate_sync_committee_message_gossip and return the result.
    Returns: tuple of (result, reason) where result is "valid", "ignore", or "reject"
             and reason is the exception message (or None for valid).
    """
    try:
        spec.validate_sync_committee_message_gossip(
            seen, store, state, sync_committee_message, subnet_id, current_time_ms
        )
        return "valid", None
    except spec.GossipIgnore as e:
        return "ignore", str(e)
    except spec.GossipReject as e:
        return "reject", str(e)


@with_phases([ALTAIR])
@spec_state_test
def test_gossip_sync_committee_message__valid(spec, state):
    """
    Test that a valid sync committee message passes gossip validation.
    """
    yield "topic", "meta", "sync_committee"
    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    validator_index, subnet_id = get_sync_committee_member_and_subnet(spec, state)
    message = get_valid_sync_committee_message(spec, state, state.slot, validator_index)

    yield get_filename(message), message

    slot_time_ms = spec.compute_time_at_slot_ms(state, state.slot)

    yield "current_time_ms", "meta", int(slot_time_ms)

    result, reason = run_validate_sync_committee_message_gossip(
        spec, seen, store, state, message, subnet_id, slot_time_ms + 500
    )
    assert result == "valid", f"Expected valid but got {result}: {reason}"
    assert reason is None

    yield (
        "messages",
        "meta",
        [
            {
                "offset_ms": 500,
                "subnet_id": int(subnet_id),
                "message": get_filename(message),
                "expected": "valid",
            }
        ],
    )


@with_phases([ALTAIR])
@spec_state_test
def test_gossip_sync_committee_message__ignore_future_slot(spec, state):
    """
    Test that a sync committee message from a future slot is ignored.
    """
    yield "topic", "meta", "sync_committee"
    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    validator_index, subnet_id = get_sync_committee_member_and_subnet(spec, state)
    # Create message for a future slot
    future_slot = state.slot + 10
    message = get_valid_sync_committee_message(spec, state, future_slot, validator_index)

    yield get_filename(message), message

    slot_time_ms = spec.compute_time_at_slot_ms(state, state.slot)
    current_time_ms = slot_time_ms

    yield "current_time_ms", "meta", int(current_time_ms)

    result, reason = run_validate_sync_committee_message_gossip(
        spec, seen, store, state, message, subnet_id, current_time_ms
    )
    assert result == "ignore"
    assert reason == "sync committee message slot is not the current slot"

    yield (
        "messages",
        "meta",
        [
            {
                "offset_ms": 0,
                "subnet_id": int(subnet_id),
                "message": get_filename(message),
                "expected": "ignore",
            }
        ],
    )


@with_phases([ALTAIR])
@spec_state_test
def test_gossip_sync_committee_message__ignore_past_slot(spec, state):
    """
    Test that a sync committee message from a past slot is ignored.
    """
    yield "topic", "meta", "sync_committee"
    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    validator_index, subnet_id = get_sync_committee_member_and_subnet(spec, state)
    message = get_valid_sync_committee_message(spec, state, state.slot, validator_index)

    yield get_filename(message), message

    # Current time is well past the next slot
    slot_time_ms = spec.compute_time_at_slot_ms(state, state.slot)
    current_time_ms = slot_time_ms + 2 * spec.config.SLOT_DURATION_MS

    yield "current_time_ms", "meta", int(current_time_ms)

    result, reason = run_validate_sync_committee_message_gossip(
        spec, seen, store, state, message, subnet_id, current_time_ms
    )
    assert result == "ignore"
    assert reason == "sync committee message slot is not the current slot"

    yield (
        "messages",
        "meta",
        [
            {
                "offset_ms": int(2 * spec.config.SLOT_DURATION_MS),
                "subnet_id": int(subnet_id),
                "message": get_filename(message),
                "expected": "ignore",
            }
        ],
    )


@with_phases([ALTAIR])
@spec_state_test
def test_gossip_sync_committee_message__reject_wrong_subnet(spec, state):
    """
    Test that a sync committee message on the wrong subnet is rejected.
    """
    yield "topic", "meta", "sync_committee"
    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    validator_index, correct_subnet_id = get_sync_committee_member_and_subnet(spec, state)
    message = get_valid_sync_committee_message(spec, state, state.slot, validator_index)

    yield get_filename(message), message

    # Use a wrong subnet
    wrong_subnet_id = (correct_subnet_id + 1) % spec.SYNC_COMMITTEE_SUBNET_COUNT
    valid_subnets = spec.compute_subnets_for_sync_committee(state, validator_index)
    # Make sure it's actually wrong
    if wrong_subnet_id in valid_subnets:
        wrong_subnet_id = (correct_subnet_id + 2) % spec.SYNC_COMMITTEE_SUBNET_COUNT

    slot_time_ms = spec.compute_time_at_slot_ms(state, state.slot)

    yield "current_time_ms", "meta", int(slot_time_ms)

    result, reason = run_validate_sync_committee_message_gossip(
        spec, seen, store, state, message, wrong_subnet_id, slot_time_ms + 500
    )
    assert result == "reject"
    assert reason == "subnet_id is not valid for the given validator"

    yield (
        "messages",
        "meta",
        [
            {
                "offset_ms": 500,
                "subnet_id": int(wrong_subnet_id),
                "message": get_filename(message),
                "expected": "reject",
            }
        ],
    )


@with_phases([ALTAIR])
@spec_state_test
def test_gossip_sync_committee_message__ignore_duplicate(spec, state):
    """
    Test that a duplicate sync committee message is ignored.
    """
    yield "topic", "meta", "sync_committee"
    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    validator_index, subnet_id = get_sync_committee_member_and_subnet(spec, state)
    message = get_valid_sync_committee_message(spec, state, state.slot, validator_index)

    yield get_filename(message), message

    slot_time_ms = spec.compute_time_at_slot_ms(state, state.slot)

    yield "current_time_ms", "meta", int(slot_time_ms)

    # First message should be valid
    result, reason = run_validate_sync_committee_message_gossip(
        spec, seen, store, state, message, subnet_id, slot_time_ms + 500
    )
    assert result == "valid"
    assert reason is None

    # Second identical message should be ignored
    result, reason = run_validate_sync_committee_message_gossip(
        spec, seen, store, state, message, subnet_id, slot_time_ms + 600
    )
    assert result == "ignore"
    assert (
        reason == "already seen sync committee message from this validator for this slot and subnet"
    )

    yield (
        "messages",
        "meta",
        [
            {
                "offset_ms": 500,
                "subnet_id": int(subnet_id),
                "message": get_filename(message),
                "expected": "valid",
            },
            {
                "offset_ms": 600,
                "subnet_id": int(subnet_id),
                "message": get_filename(message),
                "expected": "ignore",
            },
        ],
    )


@with_phases([ALTAIR])
@spec_state_test
def test_gossip_sync_committee_message__reject_invalid_signature(spec, state):
    """
    Test that a sync committee message with an invalid signature is rejected.
    """
    yield "topic", "meta", "sync_committee"
    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    validator_index, subnet_id = get_sync_committee_member_and_subnet(spec, state)
    block_root = build_empty_block_for_next_slot(spec, state).parent_root

    # Create message with wrong signature (sign with wrong key)
    wrong_privkey = privkeys[(validator_index + 1) % len(privkeys)]
    domain = spec.get_domain(
        state, spec.DOMAIN_SYNC_COMMITTEE, spec.compute_epoch_at_slot(state.slot)
    )
    signing_root = spec.compute_signing_root(block_root, domain)
    bad_signature = bls.Sign(wrong_privkey, signing_root)

    message = spec.SyncCommitteeMessage(
        slot=state.slot,
        beacon_block_root=block_root,
        validator_index=validator_index,
        signature=bad_signature,
    )

    yield get_filename(message), message

    slot_time_ms = spec.compute_time_at_slot_ms(state, state.slot)

    yield "current_time_ms", "meta", int(slot_time_ms)

    result, reason = run_validate_sync_committee_message_gossip(
        spec, seen, store, state, message, subnet_id, slot_time_ms + 500
    )
    assert result == "reject"
    assert reason == "invalid sync committee message signature"

    yield (
        "messages",
        "meta",
        [
            {
                "offset_ms": 500,
                "subnet_id": int(subnet_id),
                "message": get_filename(message),
                "expected": "reject",
            }
        ],
    )

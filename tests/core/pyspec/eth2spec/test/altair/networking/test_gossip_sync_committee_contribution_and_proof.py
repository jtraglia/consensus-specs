from eth2spec.test.context import (
    spec_state_test,
    with_phases,
)
from eth2spec.test.helpers.block import (
    build_empty_block_for_next_slot,
)
from eth2spec.test.helpers.constants import ALTAIR, BELLATRIX, CAPELLA, DENEB
from eth2spec.test.helpers.fork_choice import (
    get_genesis_forkchoice_store_and_block,
)
from eth2spec.test.helpers.gossip import get_filename, get_seen
from eth2spec.test.helpers.keys import privkeys
from eth2spec.test.helpers.sync_committee import (
    compute_committee_indices,
    compute_sync_committee_signature,
)
from eth2spec.utils import bls


def wrap_genesis_block(spec, block):
    """Wrap an unsigned genesis block in a SignedBeaconBlock with empty signature."""
    return spec.SignedBeaconBlock(message=block)


def get_sync_committee_member_info(spec, state):
    """
    Find a validator in the current sync committee, determine which subcommittee they are in,
    and return (validator_index, subcommittee_index).
    """
    committee_indices = compute_committee_indices(state)
    sync_subcommittee_size = spec.SYNC_COMMITTEE_SIZE // spec.SYNC_COMMITTEE_SUBNET_COUNT

    for subcommittee_index in range(spec.SYNC_COMMITTEE_SUBNET_COUNT):
        start = subcommittee_index * sync_subcommittee_size
        end = start + sync_subcommittee_size
        subcommittee_validator_indices = committee_indices[start:end]
        for validator_index in subcommittee_validator_indices:
            return validator_index, subcommittee_index

    raise Exception("No sync committee member found")


def find_aggregator_in_subcommittee(spec, state, slot, subcommittee_index):
    """
    Find a validator in the given subcommittee that is selected as an aggregator.
    Returns (validator_index, selection_proof) or raises if none found.
    """
    committee_indices = compute_committee_indices(state)
    sync_subcommittee_size = spec.SYNC_COMMITTEE_SIZE // spec.SYNC_COMMITTEE_SUBNET_COUNT
    start = subcommittee_index * sync_subcommittee_size
    end = start + sync_subcommittee_size
    subcommittee_validator_indices = committee_indices[start:end]

    for validator_index in subcommittee_validator_indices:
        privkey = privkeys[validator_index]
        selection_proof = spec.get_sync_committee_selection_proof(
            state, slot, subcommittee_index, privkey
        )
        if spec.is_sync_committee_aggregator(selection_proof):
            return validator_index, selection_proof

    # If no natural aggregator found, return first member anyway (test will handle)
    validator_index = subcommittee_validator_indices[0]
    privkey = privkeys[validator_index]
    selection_proof = spec.get_sync_committee_selection_proof(
        state, slot, subcommittee_index, privkey
    )
    return validator_index, selection_proof


def create_valid_signed_contribution_and_proof(
    spec, state, slot, subcommittee_index=None, aggregator_index=None, block_root=None
):
    """
    Create a valid SignedContributionAndProof.
    """
    if block_root is None:
        block_root = build_empty_block_for_next_slot(spec, state).parent_root

    if subcommittee_index is None:
        subcommittee_index = 0

    # Find an aggregator if not specified
    if aggregator_index is None:
        aggregator_index, _ = find_aggregator_in_subcommittee(spec, state, slot, subcommittee_index)
    else:
        pass

    # Build aggregate signature from subcommittee members
    committee_indices = compute_committee_indices(state)
    sync_subcommittee_size = spec.SYNC_COMMITTEE_SIZE // spec.SYNC_COMMITTEE_SUBNET_COUNT
    start = subcommittee_index * sync_subcommittee_size
    end = start + sync_subcommittee_size
    subcommittee_validator_indices = committee_indices[start:end]

    # Set all bits (all subcommittee members participate)
    aggregation_bits = [True] * sync_subcommittee_size

    # Build aggregate signature
    signatures = []
    for vi in subcommittee_validator_indices:
        privkey = privkeys[vi]
        signatures.append(
            compute_sync_committee_signature(spec, state, slot, privkey, block_root=block_root)
        )
    aggregate_signature = bls.Aggregate(signatures)

    contribution = spec.SyncCommitteeContribution(
        slot=slot,
        beacon_block_root=block_root,
        subcommittee_index=subcommittee_index,
        aggregation_bits=aggregation_bits,
        signature=aggregate_signature,
    )

    contribution_and_proof = spec.get_contribution_and_proof(
        state, aggregator_index, contribution, privkeys[aggregator_index]
    )

    signature = spec.get_contribution_and_proof_signature(
        state, contribution_and_proof, privkeys[aggregator_index]
    )

    return spec.SignedContributionAndProof(
        message=contribution_and_proof,
        signature=signature,
    )


def run_validate_sync_committee_contribution_and_proof_gossip(
    spec, seen, store, state, signed_contribution_and_proof, current_time_ms
):
    """
    Run validate_sync_committee_contribution_and_proof_gossip and return the result.
    Returns: tuple of (result, reason) where result is "valid", "ignore", or "reject"
             and reason is the exception message (or None for valid).
    """
    try:
        spec.validate_sync_committee_contribution_and_proof_gossip(
            seen, store, state, signed_contribution_and_proof, current_time_ms
        )
        return "valid", None
    except spec.GossipIgnore as e:
        return "ignore", str(e)
    except spec.GossipReject as e:
        return "reject", str(e)


@with_phases([ALTAIR, BELLATRIX, CAPELLA, DENEB])
@spec_state_test
def test_gossip_sync_committee_contribution_and_proof__valid(spec, state):
    """
    Test that a valid sync committee contribution and proof passes gossip validation.
    """
    yield "topic", "meta", "sync_committee_contribution_and_proof"
    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    signed_cap = create_valid_signed_contribution_and_proof(spec, state, state.slot)

    # Check that the aggregator is actually selected
    selection_proof = signed_cap.message.selection_proof
    if not spec.is_sync_committee_aggregator(selection_proof):
        # Skip test if we can't find an aggregator
        return

    yield get_filename(signed_cap), signed_cap

    slot_time_ms = spec.compute_time_at_slot_ms(state, state.slot)

    yield "current_time_ms", "meta", int(slot_time_ms)

    result, reason = run_validate_sync_committee_contribution_and_proof_gossip(
        spec, seen, store, state, signed_cap, slot_time_ms + 500
    )
    assert result == "valid", f"Expected valid but got {result}: {reason}"
    assert reason is None

    yield (
        "messages",
        "meta",
        [{"offset_ms": 500, "message": get_filename(signed_cap), "expected": "valid"}],
    )


@with_phases([ALTAIR, BELLATRIX, CAPELLA, DENEB])
@spec_state_test
def test_gossip_sync_committee_contribution_and_proof__ignore_future_slot(spec, state):
    """
    Test that a contribution from a future slot is ignored.
    """
    yield "topic", "meta", "sync_committee_contribution_and_proof"
    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    # Create contribution for a future slot
    future_slot = state.slot + 10
    signed_cap = create_valid_signed_contribution_and_proof(spec, state, future_slot)

    yield get_filename(signed_cap), signed_cap

    slot_time_ms = spec.compute_time_at_slot_ms(state, state.slot)

    yield "current_time_ms", "meta", int(slot_time_ms)

    result, reason = run_validate_sync_committee_contribution_and_proof_gossip(
        spec, seen, store, state, signed_cap, slot_time_ms
    )
    assert result == "ignore"
    assert reason == "contribution slot is not the current slot"

    yield (
        "messages",
        "meta",
        [{"offset_ms": 0, "message": get_filename(signed_cap), "expected": "ignore"}],
    )


@with_phases([ALTAIR, BELLATRIX, CAPELLA, DENEB])
@spec_state_test
def test_gossip_sync_committee_contribution_and_proof__ignore_past_slot(spec, state):
    """
    Test that a contribution from a past slot is ignored.
    """
    yield "topic", "meta", "sync_committee_contribution_and_proof"
    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    signed_cap = create_valid_signed_contribution_and_proof(spec, state, state.slot)

    yield get_filename(signed_cap), signed_cap

    # Current time is well past the next slot
    slot_time_ms = spec.compute_time_at_slot_ms(state, state.slot)
    current_time_ms = slot_time_ms + 2 * spec.config.SLOT_DURATION_MS

    yield "current_time_ms", "meta", int(current_time_ms)

    result, reason = run_validate_sync_committee_contribution_and_proof_gossip(
        spec, seen, store, state, signed_cap, current_time_ms
    )
    assert result == "ignore"
    assert reason == "contribution slot is not the current slot"

    yield (
        "messages",
        "meta",
        [
            {
                "offset_ms": int(2 * spec.config.SLOT_DURATION_MS),
                "message": get_filename(signed_cap),
                "expected": "ignore",
            }
        ],
    )


@with_phases([ALTAIR, BELLATRIX, CAPELLA, DENEB])
@spec_state_test
def test_gossip_sync_committee_contribution_and_proof__reject_invalid_subcommittee_index(
    spec, state
):
    """
    Test that a contribution with an invalid subcommittee index is rejected.
    """
    yield "topic", "meta", "sync_committee_contribution_and_proof"
    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    signed_cap = create_valid_signed_contribution_and_proof(spec, state, state.slot)

    # Tamper with the subcommittee index
    signed_cap.message.contribution.subcommittee_index = spec.SYNC_COMMITTEE_SUBNET_COUNT

    yield get_filename(signed_cap), signed_cap

    slot_time_ms = spec.compute_time_at_slot_ms(state, state.slot)

    yield "current_time_ms", "meta", int(slot_time_ms)

    result, reason = run_validate_sync_committee_contribution_and_proof_gossip(
        spec, seen, store, state, signed_cap, slot_time_ms + 500
    )
    assert result == "reject"
    assert reason == "subcommittee index out of range"

    yield (
        "messages",
        "meta",
        [{"offset_ms": 500, "message": get_filename(signed_cap), "expected": "reject"}],
    )


@with_phases([ALTAIR, BELLATRIX, CAPELLA, DENEB])
@spec_state_test
def test_gossip_sync_committee_contribution_and_proof__reject_no_participants(spec, state):
    """
    Test that a contribution with no participants is rejected.
    """
    yield "topic", "meta", "sync_committee_contribution_and_proof"
    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    signed_cap = create_valid_signed_contribution_and_proof(spec, state, state.slot)

    # Clear all aggregation bits
    sync_subcommittee_size = spec.SYNC_COMMITTEE_SIZE // spec.SYNC_COMMITTEE_SUBNET_COUNT
    signed_cap.message.contribution.aggregation_bits = [False] * sync_subcommittee_size

    yield get_filename(signed_cap), signed_cap

    slot_time_ms = spec.compute_time_at_slot_ms(state, state.slot)

    yield "current_time_ms", "meta", int(slot_time_ms)

    result, reason = run_validate_sync_committee_contribution_and_proof_gossip(
        spec, seen, store, state, signed_cap, slot_time_ms + 500
    )
    assert result == "reject"
    assert reason == "contribution has no participants"

    yield (
        "messages",
        "meta",
        [{"offset_ms": 500, "message": get_filename(signed_cap), "expected": "reject"}],
    )


@with_phases([ALTAIR, BELLATRIX, CAPELLA, DENEB])
@spec_state_test
def test_gossip_sync_committee_contribution_and_proof__reject_not_aggregator(spec, state):
    """
    Test that a contribution from a non-aggregator is rejected.
    """
    yield "topic", "meta", "sync_committee_contribution_and_proof"
    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    # Find a non-aggregator in a subcommittee
    committee_indices = compute_committee_indices(state)
    sync_subcommittee_size = spec.SYNC_COMMITTEE_SIZE // spec.SYNC_COMMITTEE_SUBNET_COUNT

    found = False
    for subcommittee_index in range(spec.SYNC_COMMITTEE_SUBNET_COUNT):
        start = subcommittee_index * sync_subcommittee_size
        end = start + sync_subcommittee_size
        subcommittee_validator_indices = committee_indices[start:end]
        for vi in subcommittee_validator_indices:
            privkey = privkeys[vi]
            selection_proof = spec.get_sync_committee_selection_proof(
                state, state.slot, subcommittee_index, privkey
            )
            if not spec.is_sync_committee_aggregator(selection_proof):
                # Found a non-aggregator, create contribution with them
                signed_cap = create_valid_signed_contribution_and_proof(
                    spec,
                    state,
                    state.slot,
                    subcommittee_index=subcommittee_index,
                    aggregator_index=vi,
                )
                found = True
                break
        if found:
            break

    if not found:
        # All members are aggregators, skip test
        return

    yield get_filename(signed_cap), signed_cap

    slot_time_ms = spec.compute_time_at_slot_ms(state, state.slot)

    yield "current_time_ms", "meta", int(slot_time_ms)

    result, reason = run_validate_sync_committee_contribution_and_proof_gossip(
        spec, seen, store, state, signed_cap, slot_time_ms + 500
    )
    assert result == "reject"
    assert reason == "validator is not selected as sync committee aggregator"

    yield (
        "messages",
        "meta",
        [{"offset_ms": 500, "message": get_filename(signed_cap), "expected": "reject"}],
    )


@with_phases([ALTAIR, BELLATRIX, CAPELLA, DENEB])
@spec_state_test
def test_gossip_sync_committee_contribution_and_proof__reject_aggregator_not_in_subcommittee(
    spec, state
):
    """
    Test that a contribution from an aggregator not in the declared subcommittee is rejected.
    """
    yield "topic", "meta", "sync_committee_contribution_and_proof"
    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    # Create a valid contribution for subcommittee 0
    signed_cap = create_valid_signed_contribution_and_proof(
        spec, state, state.slot, subcommittee_index=0
    )

    if not spec.is_sync_committee_aggregator(signed_cap.message.selection_proof):
        return

    # Point it to a different subcommittee where the aggregator isn't a member
    # We change the subcommittee index to an invalid one (the aggregator is in subcommittee 0)
    original_aggregator = signed_cap.message.aggregator_index

    # Find a subcommittee where this aggregator is NOT a member
    committee_indices = compute_committee_indices(state)
    sync_subcommittee_size = spec.SYNC_COMMITTEE_SIZE // spec.SYNC_COMMITTEE_SUBNET_COUNT
    for wrong_sub in range(spec.SYNC_COMMITTEE_SUBNET_COUNT):
        start = wrong_sub * sync_subcommittee_size
        end = start + sync_subcommittee_size
        sub_validators = committee_indices[start:end]
        if original_aggregator not in sub_validators:
            signed_cap.message.contribution.subcommittee_index = wrong_sub
            break

    yield get_filename(signed_cap), signed_cap

    slot_time_ms = spec.compute_time_at_slot_ms(state, state.slot)

    yield "current_time_ms", "meta", int(slot_time_ms)

    result, reason = run_validate_sync_committee_contribution_and_proof_gossip(
        spec, seen, store, state, signed_cap, slot_time_ms + 500
    )
    assert result == "reject"
    assert reason == "aggregator not in declared subcommittee"

    yield (
        "messages",
        "meta",
        [{"offset_ms": 500, "message": get_filename(signed_cap), "expected": "reject"}],
    )


@with_phases([ALTAIR, BELLATRIX, CAPELLA, DENEB])
@spec_state_test
def test_gossip_sync_committee_contribution_and_proof__ignore_duplicate_aggregator(spec, state):
    """
    Test that a duplicate contribution from the same aggregator is ignored.
    """
    yield "topic", "meta", "sync_committee_contribution_and_proof"
    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    signed_cap = create_valid_signed_contribution_and_proof(spec, state, state.slot)

    if not spec.is_sync_committee_aggregator(signed_cap.message.selection_proof):
        return

    yield get_filename(signed_cap), signed_cap

    slot_time_ms = spec.compute_time_at_slot_ms(state, state.slot)

    yield "current_time_ms", "meta", int(slot_time_ms)

    # First should be valid
    result, reason = run_validate_sync_committee_contribution_and_proof_gossip(
        spec, seen, store, state, signed_cap, slot_time_ms + 500
    )
    assert result == "valid", f"Expected valid but got {result}: {reason}"
    assert reason is None

    # Second should be ignored (same aggregator/slot/subcommittee)
    result, reason = run_validate_sync_committee_contribution_and_proof_gossip(
        spec, seen, store, state, signed_cap, slot_time_ms + 600
    )
    assert result == "ignore"
    assert reason == "already seen contribution with superset aggregation_bits"

    yield (
        "messages",
        "meta",
        [
            {"offset_ms": 500, "message": get_filename(signed_cap), "expected": "valid"},
            {"offset_ms": 600, "message": get_filename(signed_cap), "expected": "ignore"},
        ],
    )


@with_phases([ALTAIR, BELLATRIX, CAPELLA, DENEB])
@spec_state_test
def test_gossip_sync_committee_contribution_and_proof__reject_invalid_selection_proof(spec, state):
    """
    Test that a contribution with an invalid selection proof is rejected.
    """
    yield "topic", "meta", "sync_committee_contribution_and_proof"
    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    signed_cap = create_valid_signed_contribution_and_proof(spec, state, state.slot)

    if not spec.is_sync_committee_aggregator(signed_cap.message.selection_proof):
        return

    # Tamper with the selection proof (use wrong key)
    aggregator_index = signed_cap.message.aggregator_index
    wrong_privkey = privkeys[(aggregator_index + 1) % len(privkeys)]
    bad_selection_proof = spec.get_sync_committee_selection_proof(
        state, state.slot, signed_cap.message.contribution.subcommittee_index, wrong_privkey
    )
    # Only proceed if the bad proof also passes the aggregator check
    if not spec.is_sync_committee_aggregator(bad_selection_proof):
        return

    signed_cap.message.selection_proof = bad_selection_proof

    yield get_filename(signed_cap), signed_cap

    slot_time_ms = spec.compute_time_at_slot_ms(state, state.slot)

    yield "current_time_ms", "meta", int(slot_time_ms)

    result, reason = run_validate_sync_committee_contribution_and_proof_gossip(
        spec, seen, store, state, signed_cap, slot_time_ms + 500
    )
    assert result == "reject"
    assert reason == "invalid selection proof signature"

    yield (
        "messages",
        "meta",
        [{"offset_ms": 500, "message": get_filename(signed_cap), "expected": "reject"}],
    )


@with_phases([ALTAIR, BELLATRIX, CAPELLA, DENEB])
@spec_state_test
def test_gossip_sync_committee_contribution_and_proof__reject_invalid_aggregator_signature(
    spec, state
):
    """
    Test that a contribution with an invalid aggregator signature is rejected.
    """
    yield "topic", "meta", "sync_committee_contribution_and_proof"
    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    signed_cap = create_valid_signed_contribution_and_proof(spec, state, state.slot)

    if not spec.is_sync_committee_aggregator(signed_cap.message.selection_proof):
        return

    # Tamper with the outer signature
    aggregator_index = signed_cap.message.aggregator_index
    wrong_privkey = privkeys[(aggregator_index + 1) % len(privkeys)]
    bad_signature = spec.get_contribution_and_proof_signature(
        state, signed_cap.message, wrong_privkey
    )
    signed_cap.signature = bad_signature

    yield get_filename(signed_cap), signed_cap

    slot_time_ms = spec.compute_time_at_slot_ms(state, state.slot)

    yield "current_time_ms", "meta", int(slot_time_ms)

    result, reason = run_validate_sync_committee_contribution_and_proof_gossip(
        spec, seen, store, state, signed_cap, slot_time_ms + 500
    )
    assert result == "reject"
    assert reason == "invalid aggregator signature"

    yield (
        "messages",
        "meta",
        [{"offset_ms": 500, "message": get_filename(signed_cap), "expected": "reject"}],
    )


@with_phases([ALTAIR, BELLATRIX, CAPELLA, DENEB])
@spec_state_test
def test_gossip_sync_committee_contribution_and_proof__reject_invalid_aggregate_signature(
    spec, state
):
    """
    Test that a contribution with an invalid aggregate signature is rejected.
    """
    yield "topic", "meta", "sync_committee_contribution_and_proof"
    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    signed_cap = create_valid_signed_contribution_and_proof(spec, state, state.slot)

    if not spec.is_sync_committee_aggregator(signed_cap.message.selection_proof):
        return

    # Tamper with the aggregate signature by using wrong block root
    wrong_block_root = spec.Root(b"\x42" * 32)
    committee_indices = compute_committee_indices(state)
    sync_subcommittee_size = spec.SYNC_COMMITTEE_SIZE // spec.SYNC_COMMITTEE_SUBNET_COUNT
    subcommittee_index = signed_cap.message.contribution.subcommittee_index
    start = subcommittee_index * sync_subcommittee_size
    end = start + sync_subcommittee_size
    subcommittee_validator_indices = committee_indices[start:end]

    # Build bad aggregate signature with wrong block root
    bad_signatures = []
    for vi in subcommittee_validator_indices:
        privkey = privkeys[vi]
        bad_signatures.append(
            compute_sync_committee_signature(
                spec, state, state.slot, privkey, block_root=wrong_block_root
            )
        )
    signed_cap.message.contribution.signature = bls.Aggregate(bad_signatures)

    # Re-sign the outer signature so the aggregator signature check passes
    aggregator_index = signed_cap.message.aggregator_index
    signed_cap.signature = spec.get_contribution_and_proof_signature(
        state, signed_cap.message, privkeys[aggregator_index]
    )

    yield get_filename(signed_cap), signed_cap

    slot_time_ms = spec.compute_time_at_slot_ms(state, state.slot)

    yield "current_time_ms", "meta", int(slot_time_ms)

    result, reason = run_validate_sync_committee_contribution_and_proof_gossip(
        spec, seen, store, state, signed_cap, slot_time_ms + 500
    )
    assert result == "reject"
    assert reason == "invalid aggregate signature"

    yield (
        "messages",
        "meta",
        [{"offset_ms": 500, "message": get_filename(signed_cap), "expected": "reject"}],
    )

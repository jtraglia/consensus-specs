from eth2spec.test.context import (
    spec_state_test_with_matching_config,
    with_deneb_and_later,
)
from eth2spec.test.helpers.blob import (
    get_block_with_blob,
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


def run_validate_blob_sidecar_gossip(
    spec, seen, store, state, blob_sidecar, subnet_id, current_time_ms
):
    """
    Run validate_blob_sidecar_gossip and return the result.
    Returns: tuple of (result, reason) where result is "valid", "ignore", or "reject"
             and reason is the exception message (or None for valid).
    """
    try:
        spec.validate_blob_sidecar_gossip(
            seen, store, state, blob_sidecar, subnet_id, current_time_ms
        )
        return "valid", None
    except spec.GossipIgnore as e:
        return "ignore", str(e)
    except spec.GossipReject as e:
        return "reject", str(e)


def get_valid_blob_sidecar(spec, state, store):
    """
    Build a valid block with blob, transition state, and return the first blob sidecar.
    Returns: (blob_sidecar, signed_block, state)
    """
    block, blobs, blob_kzg_commitments, blob_kzg_proofs = get_block_with_blob(
        spec, state, blob_count=1
    )
    signed_block = state_transition_and_sign_block(spec, state, block)

    blob_sidecars = spec.get_blob_sidecars(signed_block, blobs, blob_kzg_proofs)
    return blob_sidecars[0], signed_block, state


@with_deneb_and_later
@spec_state_test_with_matching_config
def test_gossip_blob_sidecar__valid(spec, state):
    """
    Test that a valid blob sidecar passes gossip validation.
    """
    yield "topic", "meta", "blob_sidecar"

    # Transition to post-merge state
    state = build_state_with_complete_transition(spec, state)

    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    blob_sidecar, signed_block, state = get_valid_blob_sidecar(spec, state, store)

    yield get_filename(blob_sidecar), blob_sidecar

    block_time_ms = spec.compute_time_at_slot_ms(
        store, blob_sidecar.signed_block_header.message.slot
    )
    subnet_id = spec.compute_subnet_for_blob_sidecar(blob_sidecar.index)

    yield "current_time_ms", "meta", int(block_time_ms)

    result, reason = run_validate_blob_sidecar_gossip(
        spec, seen, store, state, blob_sidecar, subnet_id, block_time_ms + 500
    )
    assert result == "valid", f"Expected valid but got {result}: {reason}"
    assert reason is None

    yield (
        "messages",
        "meta",
        [
            {
                "subnet_id": int(subnet_id),
                "offset_ms": 500,
                "message": get_filename(blob_sidecar),
                "expected": "valid",
            }
        ],
    )


@with_deneb_and_later
@spec_state_test_with_matching_config
def test_gossip_blob_sidecar__ignore_already_seen(spec, state):
    """
    Test that a duplicate blob sidecar (same slot, proposer, index) is ignored.
    """
    yield "topic", "meta", "blob_sidecar"

    # Transition to post-merge state
    state = build_state_with_complete_transition(spec, state)

    yield "state", state

    messages = []
    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    blob_sidecar, signed_block, state = get_valid_blob_sidecar(spec, state, store)

    yield get_filename(blob_sidecar), blob_sidecar

    block_time_ms = spec.compute_time_at_slot_ms(
        store, blob_sidecar.signed_block_header.message.slot
    )
    subnet_id = spec.compute_subnet_for_blob_sidecar(blob_sidecar.index)

    yield "current_time_ms", "meta", int(block_time_ms)

    # First validation should pass
    result, reason = run_validate_blob_sidecar_gossip(
        spec, seen, store, state, blob_sidecar, subnet_id, block_time_ms + 500
    )
    assert result == "valid"
    messages.append(
        {
            "subnet_id": int(subnet_id),
            "offset_ms": 500,
            "message": get_filename(blob_sidecar),
            "expected": "valid",
        }
    )

    # Second validation should be ignored (already seen)
    result, reason = run_validate_blob_sidecar_gossip(
        spec, seen, store, state, blob_sidecar, subnet_id, block_time_ms + 600
    )
    assert result == "ignore"
    assert reason == "already seen blob sidecar for this slot/proposer/index"
    messages.append(
        {
            "subnet_id": int(subnet_id),
            "offset_ms": 600,
            "message": get_filename(blob_sidecar),
            "expected": "ignore",
            "reason": reason,
        }
    )

    yield "messages", "meta", messages


@with_deneb_and_later
@spec_state_test_with_matching_config
def test_gossip_blob_sidecar__reject_index_too_large(spec, state):
    """
    Test that a blob sidecar with index >= MAX_BLOBS_PER_BLOCK is rejected.
    """
    yield "topic", "meta", "blob_sidecar"

    # Transition to post-merge state
    state = build_state_with_complete_transition(spec, state)

    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    blob_sidecar, signed_block, state = get_valid_blob_sidecar(spec, state, store)

    # Set index to MAX_BLOBS_PER_BLOCK (out of range)
    blob_sidecar.index = spec.config.MAX_BLOBS_PER_BLOCK

    yield get_filename(blob_sidecar), blob_sidecar

    block_time_ms = spec.compute_time_at_slot_ms(
        store, blob_sidecar.signed_block_header.message.slot
    )
    subnet_id = spec.uint64(0)

    yield "current_time_ms", "meta", int(block_time_ms)

    result, reason = run_validate_blob_sidecar_gossip(
        spec, seen, store, state, blob_sidecar, subnet_id, block_time_ms + 500
    )
    assert result == "reject"
    assert reason == "blob index too large"

    yield (
        "messages",
        "meta",
        [
            {
                "subnet_id": int(subnet_id),
                "offset_ms": 500,
                "message": get_filename(blob_sidecar),
                "expected": "reject",
                "reason": reason,
            }
        ],
    )


@with_deneb_and_later
@spec_state_test_with_matching_config
def test_gossip_blob_sidecar__reject_wrong_subnet(spec, state):
    """
    Test that a blob sidecar sent to the wrong subnet is rejected.
    """
    yield "topic", "meta", "blob_sidecar"

    # Transition to post-merge state
    state = build_state_with_complete_transition(spec, state)

    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    blob_sidecar, signed_block, state = get_valid_blob_sidecar(spec, state, store)

    yield get_filename(blob_sidecar), blob_sidecar

    block_time_ms = spec.compute_time_at_slot_ms(
        store, blob_sidecar.signed_block_header.message.slot
    )

    # Get correct subnet and use a different one
    correct_subnet = spec.compute_subnet_for_blob_sidecar(blob_sidecar.index)
    wrong_subnet = spec.uint64((correct_subnet + 1) % spec.config.BLOB_SIDECAR_SUBNET_COUNT)

    yield "current_time_ms", "meta", int(block_time_ms)

    result, reason = run_validate_blob_sidecar_gossip(
        spec, seen, store, state, blob_sidecar, wrong_subnet, block_time_ms + 500
    )
    assert result == "reject"
    assert reason == "blob sidecar is for wrong subnet"

    yield (
        "messages",
        "meta",
        [
            {
                "subnet_id": int(wrong_subnet),
                "offset_ms": 500,
                "message": get_filename(blob_sidecar),
                "expected": "reject",
                "reason": reason,
            }
        ],
    )


@with_deneb_and_later
@spec_state_test_with_matching_config
def test_gossip_blob_sidecar__reject_invalid_proposer_signature(spec, state):
    """
    Test that a blob sidecar with an invalid proposer signature is rejected.
    """
    yield "topic", "meta", "blob_sidecar"

    # Transition to post-merge state
    state = build_state_with_complete_transition(spec, state)

    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    blob_sidecar, signed_block, state = get_valid_blob_sidecar(spec, state, store)

    # Corrupt the signature
    blob_sidecar.signed_block_header.signature = b"\x00" * 96

    yield get_filename(blob_sidecar), blob_sidecar

    block_time_ms = spec.compute_time_at_slot_ms(
        store, blob_sidecar.signed_block_header.message.slot
    )
    subnet_id = spec.compute_subnet_for_blob_sidecar(blob_sidecar.index)

    yield "current_time_ms", "meta", int(block_time_ms)

    result, reason = run_validate_blob_sidecar_gossip(
        spec, seen, store, state, blob_sidecar, subnet_id, block_time_ms + 500
    )
    assert result == "reject"
    assert reason == "invalid proposer signature"

    yield (
        "messages",
        "meta",
        [
            {
                "subnet_id": int(subnet_id),
                "offset_ms": 500,
                "message": get_filename(blob_sidecar),
                "expected": "reject",
                "reason": reason,
            }
        ],
    )


@with_deneb_and_later
@spec_state_test_with_matching_config
def test_gossip_blob_sidecar__reject_invalid_inclusion_proof(spec, state):
    """
    Test that a blob sidecar with an invalid inclusion proof is rejected.
    """
    yield "topic", "meta", "blob_sidecar"

    # Transition to post-merge state
    state = build_state_with_complete_transition(spec, state)

    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    blob_sidecar, signed_block, state = get_valid_blob_sidecar(spec, state, store)

    # Tamper with the inclusion proof
    blob_sidecar.kzg_commitment_inclusion_proof[0] = spec.Bytes32(b"\xab" * 32)

    yield get_filename(blob_sidecar), blob_sidecar

    block_time_ms = spec.compute_time_at_slot_ms(
        store, blob_sidecar.signed_block_header.message.slot
    )
    subnet_id = spec.compute_subnet_for_blob_sidecar(blob_sidecar.index)

    yield "current_time_ms", "meta", int(block_time_ms)

    result, reason = run_validate_blob_sidecar_gossip(
        spec, seen, store, state, blob_sidecar, subnet_id, block_time_ms + 500
    )
    assert result == "reject"
    assert reason == "invalid blob sidecar inclusion proof"

    yield (
        "messages",
        "meta",
        [
            {
                "subnet_id": int(subnet_id),
                "offset_ms": 500,
                "message": get_filename(blob_sidecar),
                "expected": "reject",
                "reason": reason,
            }
        ],
    )


@with_deneb_and_later
@spec_state_test_with_matching_config
def test_gossip_blob_sidecar__reject_invalid_kzg_proof(spec, state):
    """
    Test that a blob sidecar with an invalid KZG proof is rejected.
    """
    yield "topic", "meta", "blob_sidecar"

    # Transition to post-merge state
    state = build_state_with_complete_transition(spec, state)

    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    blob_sidecar, signed_block, state = get_valid_blob_sidecar(spec, state, store)

    # Tamper with the KZG proof (use point at infinity, a valid G1 point but wrong proof)
    blob_sidecar.kzg_proof = spec.KZGProof(b"\xc0" + b"\x00" * 47)

    yield get_filename(blob_sidecar), blob_sidecar

    block_time_ms = spec.compute_time_at_slot_ms(
        store, blob_sidecar.signed_block_header.message.slot
    )
    subnet_id = spec.compute_subnet_for_blob_sidecar(blob_sidecar.index)

    yield "current_time_ms", "meta", int(block_time_ms)

    result, reason = run_validate_blob_sidecar_gossip(
        spec, seen, store, state, blob_sidecar, subnet_id, block_time_ms + 500
    )
    assert result == "reject"
    assert reason == "invalid blob KZG proof"

    yield (
        "messages",
        "meta",
        [
            {
                "subnet_id": int(subnet_id),
                "offset_ms": 500,
                "message": get_filename(blob_sidecar),
                "expected": "reject",
                "reason": reason,
            }
        ],
    )


@with_deneb_and_later
@spec_state_test_with_matching_config
def test_gossip_blob_sidecar__reject_wrong_proposer(spec, state):
    """
    Test that a blob sidecar with wrong proposer_index is rejected.
    """
    yield "topic", "meta", "blob_sidecar"

    # Transition to post-merge state
    state = build_state_with_complete_transition(spec, state)

    yield "state", state

    seen = get_seen(spec)
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    signed_anchor = wrap_genesis_block(spec, anchor_block)

    yield get_filename(signed_anchor), signed_anchor
    yield "blocks", "meta", [{"block": get_filename(signed_anchor)}]

    blob_sidecar, signed_block, state = get_valid_blob_sidecar(spec, state, store)

    # Change the proposer_index in the block header to a wrong value
    correct_proposer = blob_sidecar.signed_block_header.message.proposer_index
    wrong_proposer = (correct_proposer + 1) % len(state.validators)
    blob_sidecar.signed_block_header.message.proposer_index = wrong_proposer

    yield get_filename(blob_sidecar), blob_sidecar

    block_time_ms = spec.compute_time_at_slot_ms(
        store, blob_sidecar.signed_block_header.message.slot
    )
    subnet_id = spec.compute_subnet_for_blob_sidecar(blob_sidecar.index)

    yield "current_time_ms", "meta", int(block_time_ms)

    result, reason = run_validate_blob_sidecar_gossip(
        spec, seen, store, state, blob_sidecar, subnet_id, block_time_ms + 500
    )
    assert result == "reject"
    # Changing proposer_index invalidates the signature, so signature check fails first
    assert reason == "invalid proposer signature"

    yield (
        "messages",
        "meta",
        [
            {
                "subnet_id": int(subnet_id),
                "offset_ms": 500,
                "message": get_filename(blob_sidecar),
                "expected": "reject",
                "reason": reason,
            }
        ],
    )

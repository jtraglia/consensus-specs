from eth_consensus_specs.test.context import (
    always_bls,
    spec_state_test,
    with_capella_and_later,
)
from eth_consensus_specs.test.helpers.bls_to_execution_changes import (
    get_signed_address_change as get_signed_bls_to_execution_change,
)
from eth_consensus_specs.test.helpers.gossip import get_filename, get_seen
from eth_consensus_specs.test.helpers.keys import pubkeys


def run_validate_bls_to_execution_change_gossip(spec, seen, state, signed_bls_to_execution_change):
    """
    Run validate_bls_to_execution_change_gossip and return the result.
    Returns: tuple of (result, reason) where result is "valid", "ignore", or "reject"
             and reason is the exception message (or None for valid).
    """
    try:
        spec.validate_bls_to_execution_change_gossip(seen, state, signed_bls_to_execution_change)
        return "valid", None
    except spec.GossipIgnore as e:
        return "ignore", str(e)
    except spec.GossipReject as e:
        return "reject", str(e)


@with_capella_and_later
@spec_state_test
def test_gossip_bls_to_execution_change__valid(spec, state):
    """
    Test that a valid `bls_to_execution_change` passes gossip validation.
    """
    yield "topic", "meta", "bls_to_execution_change"
    yield "state", state

    seen = get_seen(spec)
    signed_bls_to_execution_change = get_signed_bls_to_execution_change(spec, state)

    yield get_filename(signed_bls_to_execution_change), signed_bls_to_execution_change

    result, reason = run_validate_bls_to_execution_change_gossip(
        spec, seen, state, signed_bls_to_execution_change
    )
    assert result == "valid"
    assert reason is None

    yield (
        "messages",
        "meta",
        [
            {
                "offset_ms": 0,
                "message": get_filename(signed_bls_to_execution_change),
                "expected": "valid",
            }
        ],
    )


@with_capella_and_later
@spec_state_test
def test_gossip_bls_to_execution_change__ignore_already_seen(spec, state):
    """
    Test that a duplicate `bls_to_execution_change` is ignored.
    """
    yield "topic", "meta", "bls_to_execution_change"
    yield "state", state

    messages = []
    seen = get_seen(spec)
    signed_bls_to_execution_change = get_signed_bls_to_execution_change(spec, state)

    yield get_filename(signed_bls_to_execution_change), signed_bls_to_execution_change

    result, reason = run_validate_bls_to_execution_change_gossip(
        spec, seen, state, signed_bls_to_execution_change
    )
    assert result == "valid"
    assert reason is None
    messages.append(
        {
            "offset_ms": 0,
            "message": get_filename(signed_bls_to_execution_change),
            "expected": "valid",
        }
    )

    result, reason = run_validate_bls_to_execution_change_gossip(
        spec, seen, state, signed_bls_to_execution_change
    )
    assert result == "ignore"
    assert reason == "already seen BLS to execution change for this validator"
    messages.append(
        {
            "offset_ms": 0,
            "message": get_filename(signed_bls_to_execution_change),
            "expected": "ignore",
            "reason": reason,
        }
    )

    yield "messages", "meta", messages


@with_capella_and_later
@spec_state_test
def test_gossip_bls_to_execution_change__reject_validator_index_out_of_range(spec, state):
    """
    Test that a `bls_to_execution_change` with validator index out of range is rejected.
    """
    yield "topic", "meta", "bls_to_execution_change"
    yield "state", state

    seen = get_seen(spec)
    signed_bls_to_execution_change = get_signed_bls_to_execution_change(
        spec, state, validator_index=len(state.validators)
    )

    yield get_filename(signed_bls_to_execution_change), signed_bls_to_execution_change

    result, reason = run_validate_bls_to_execution_change_gossip(
        spec, seen, state, signed_bls_to_execution_change
    )
    assert result == "reject"
    assert reason == "validator index out of range"

    yield (
        "messages",
        "meta",
        [
            {
                "offset_ms": 0,
                "message": get_filename(signed_bls_to_execution_change),
                "expected": "reject",
                "reason": reason,
            }
        ],
    )


@with_capella_and_later
@spec_state_test
def test_gossip_bls_to_execution_change__reject_not_bls_credentials(spec, state):
    """
    Test that a `bls_to_execution_change` for a validator without BLS credentials is rejected.
    """
    yield "topic", "meta", "bls_to_execution_change"

    seen = get_seen(spec)
    validator_index = len(state.validators) // 2
    state.validators[validator_index].withdrawal_credentials = b"\x01" + b"\x00" * 11 + b"\x23" * 20
    yield "state", state

    signed_bls_to_execution_change = get_signed_bls_to_execution_change(
        spec, state, validator_index=validator_index
    )

    yield get_filename(signed_bls_to_execution_change), signed_bls_to_execution_change

    result, reason = run_validate_bls_to_execution_change_gossip(
        spec, seen, state, signed_bls_to_execution_change
    )
    assert result == "reject"
    assert reason == "validator does not have BLS withdrawal credentials"

    yield (
        "messages",
        "meta",
        [
            {
                "offset_ms": 0,
                "message": get_filename(signed_bls_to_execution_change),
                "expected": "reject",
                "reason": reason,
            }
        ],
    )


@with_capella_and_later
@spec_state_test
def test_gossip_bls_to_execution_change__reject_pubkey_mismatch(spec, state):
    """
    Test that a `bls_to_execution_change` with the wrong withdrawal pubkey is rejected.
    """
    yield "topic", "meta", "bls_to_execution_change"
    yield "state", state

    seen = get_seen(spec)
    validator_index = 2
    signed_bls_to_execution_change = get_signed_bls_to_execution_change(
        spec,
        state,
        validator_index=validator_index,
        withdrawal_pubkey=pubkeys[0],
    )

    yield get_filename(signed_bls_to_execution_change), signed_bls_to_execution_change

    result, reason = run_validate_bls_to_execution_change_gossip(
        spec, seen, state, signed_bls_to_execution_change
    )
    assert result == "reject"
    assert reason == "pubkey does not match validator withdrawal credentials"

    yield (
        "messages",
        "meta",
        [
            {
                "offset_ms": 0,
                "message": get_filename(signed_bls_to_execution_change),
                "expected": "reject",
                "reason": reason,
            }
        ],
    )


@with_capella_and_later
@spec_state_test
@always_bls
def test_gossip_bls_to_execution_change__reject_bad_signature(spec, state):
    """
    Test that a `bls_to_execution_change` with an invalid signature is rejected.
    """
    yield "topic", "meta", "bls_to_execution_change"
    yield "state", state

    seen = get_seen(spec)
    signed_bls_to_execution_change = get_signed_bls_to_execution_change(spec, state)
    signed_bls_to_execution_change.signature = spec.BLSSignature(b"\x42" * 96)

    yield get_filename(signed_bls_to_execution_change), signed_bls_to_execution_change

    result, reason = run_validate_bls_to_execution_change_gossip(
        spec, seen, state, signed_bls_to_execution_change
    )
    assert result == "reject"
    assert reason == "invalid BLS to execution change signature"

    yield (
        "messages",
        "meta",
        [
            {
                "offset_ms": 0,
                "message": get_filename(signed_bls_to_execution_change),
                "expected": "reject",
                "reason": reason,
            }
        ],
    )

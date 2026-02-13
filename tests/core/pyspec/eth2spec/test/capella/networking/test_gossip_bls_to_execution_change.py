from eth2spec.test.context import (
    spec_state_test_with_matching_config,
    with_capella_and_later,
)
from eth2spec.test.helpers.bls_to_execution_changes import (
    get_signed_address_change,
)
from eth2spec.test.helpers.gossip import get_filename, get_seen
from eth2spec.test.helpers.keys import pubkeys


def compute_current_time_ms(spec, state):
    """Compute current_time_ms from state's current slot."""
    return state.genesis_time * 1000 + state.slot * spec.config.SECONDS_PER_SLOT * 1000


def run_validate_bls_to_execution_change_gossip(
    spec, seen, state, signed_address_change, current_time_ms
):
    """
    Run validate_bls_to_execution_change_gossip and return the result.
    Returns: tuple of (result, reason) where result is "valid", "ignore", or "reject"
             and reason is the exception message (or None for valid).
    """
    try:
        spec.validate_bls_to_execution_change_gossip(
            seen, state, signed_address_change, current_time_ms
        )
        return "valid", None
    except spec.GossipIgnore as e:
        return "ignore", str(e)
    except spec.GossipReject as e:
        return "reject", str(e)


@with_capella_and_later
@spec_state_test_with_matching_config
def test_gossip_bls_to_execution_change__valid(spec, state):
    """
    Test that a valid BLS to execution change passes gossip validation.
    """
    yield "topic", "meta", "bls_to_execution_change"
    yield "state", state

    seen = get_seen(spec)
    current_time_ms = compute_current_time_ms(spec, state)

    signed_address_change = get_signed_address_change(spec, state, validator_index=0)

    yield get_filename(signed_address_change.message), signed_address_change

    result, reason = run_validate_bls_to_execution_change_gossip(
        spec, seen, state, signed_address_change, current_time_ms
    )
    assert result == "valid", f"Expected valid but got {result}: {reason}"
    assert reason is None

    yield (
        "messages",
        "meta",
        [{"message": get_filename(signed_address_change.message), "expected": "valid"}],
    )


@with_capella_and_later
@spec_state_test_with_matching_config
def test_gossip_bls_to_execution_change__ignore_already_seen(spec, state):
    """
    Test that a duplicate BLS to execution change is ignored.
    """
    yield "topic", "meta", "bls_to_execution_change"
    yield "state", state

    messages = []
    seen = get_seen(spec)
    current_time_ms = compute_current_time_ms(spec, state)

    signed_address_change = get_signed_address_change(spec, state, validator_index=0)

    yield get_filename(signed_address_change.message), signed_address_change

    # First validation should pass
    result, reason = run_validate_bls_to_execution_change_gossip(
        spec, seen, state, signed_address_change, current_time_ms
    )
    assert result == "valid"
    messages.append({"message": get_filename(signed_address_change.message), "expected": "valid"})

    # Second validation should be ignored
    result, reason = run_validate_bls_to_execution_change_gossip(
        spec, seen, state, signed_address_change, current_time_ms
    )
    assert result == "ignore"
    assert reason == "already seen bls to execution change for this validator"
    messages.append(
        {
            "message": get_filename(signed_address_change.message),
            "expected": "ignore",
            "reason": reason,
        }
    )

    yield "messages", "meta", messages


@with_capella_and_later
@spec_state_test_with_matching_config
def test_gossip_bls_to_execution_change__reject_validator_index_out_of_range(spec, state):
    """
    Test that a BLS to execution change with validator index out of range is rejected.
    """
    yield "topic", "meta", "bls_to_execution_change"
    yield "state", state

    seen = get_seen(spec)
    current_time_ms = compute_current_time_ms(spec, state)

    # Create address change with invalid validator index
    invalid_index = len(state.validators) + 100
    signed_address_change = get_signed_address_change(spec, state, validator_index=invalid_index)

    yield get_filename(signed_address_change.message), signed_address_change

    result, reason = run_validate_bls_to_execution_change_gossip(
        spec, seen, state, signed_address_change, current_time_ms
    )
    assert result == "reject"
    assert reason == "validator index out of range"

    yield (
        "messages",
        "meta",
        [
            {
                "message": get_filename(signed_address_change.message),
                "expected": "reject",
                "reason": reason,
            }
        ],
    )


@with_capella_and_later
@spec_state_test_with_matching_config
def test_gossip_bls_to_execution_change__reject_not_bls_withdrawal_prefix(spec, state):
    """
    Test that a BLS to execution change for a validator with ETH1 withdrawal credentials is rejected.
    """
    yield "topic", "meta", "bls_to_execution_change"

    # Change validator 0's withdrawal credentials to ETH1 prefix
    validator_index = 0
    state.validators[validator_index].withdrawal_credentials = (
        spec.ETH1_ADDRESS_WITHDRAWAL_PREFIX + b"\x00" * 11 + b"\x42" * 20
    )

    yield "state", state

    seen = get_seen(spec)
    current_time_ms = compute_current_time_ms(spec, state)

    signed_address_change = get_signed_address_change(spec, state, validator_index=validator_index)

    yield get_filename(signed_address_change.message), signed_address_change

    result, reason = run_validate_bls_to_execution_change_gossip(
        spec, seen, state, signed_address_change, current_time_ms
    )
    assert result == "reject"
    assert reason == "validator does not have BLS withdrawal credentials"

    yield (
        "messages",
        "meta",
        [
            {
                "message": get_filename(signed_address_change.message),
                "expected": "reject",
                "reason": reason,
            }
        ],
    )


@with_capella_and_later
@spec_state_test_with_matching_config
def test_gossip_bls_to_execution_change__reject_wrong_withdrawal_pubkey(spec, state):
    """
    Test that a BLS to execution change with mismatched from_bls_pubkey is rejected.
    """
    yield "topic", "meta", "bls_to_execution_change"
    yield "state", state

    seen = get_seen(spec)
    current_time_ms = compute_current_time_ms(spec, state)

    # Use a wrong withdrawal pubkey (use pubkey[0] which doesn't match validator 0's withdrawal key)
    wrong_pubkey = pubkeys[0]
    signed_address_change = get_signed_address_change(
        spec, state, validator_index=0, withdrawal_pubkey=wrong_pubkey
    )

    yield get_filename(signed_address_change.message), signed_address_change

    result, reason = run_validate_bls_to_execution_change_gossip(
        spec, seen, state, signed_address_change, current_time_ms
    )
    assert result == "reject"
    assert reason == "from_bls_pubkey does not match withdrawal credentials"

    yield (
        "messages",
        "meta",
        [
            {
                "message": get_filename(signed_address_change.message),
                "expected": "reject",
                "reason": reason,
            }
        ],
    )


@with_capella_and_later
@spec_state_test_with_matching_config
def test_gossip_bls_to_execution_change__reject_invalid_signature(spec, state):
    """
    Test that a BLS to execution change with invalid signature is rejected.
    """
    yield "topic", "meta", "bls_to_execution_change"
    yield "state", state

    seen = get_seen(spec)
    current_time_ms = compute_current_time_ms(spec, state)

    # Create a valid address change but corrupt the signature
    signed_address_change = get_signed_address_change(spec, state, validator_index=0)
    signed_address_change = spec.SignedBLSToExecutionChange(
        message=signed_address_change.message,
        signature=b"\x00" * 96,
    )

    yield get_filename(signed_address_change.message), signed_address_change

    result, reason = run_validate_bls_to_execution_change_gossip(
        spec, seen, state, signed_address_change, current_time_ms
    )
    assert result == "reject"
    assert reason == "invalid bls to execution change signature"

    yield (
        "messages",
        "meta",
        [
            {
                "message": get_filename(signed_address_change.message),
                "expected": "reject",
                "reason": reason,
            }
        ],
    )

from eth_consensus_specs.test.context import spec_state_test, with_phases
from eth_consensus_specs.test.helpers.builder_deposit_requests import (
    run_builder_deposit_request_processing,
)
from eth_consensus_specs.test.helpers.constants import PQ
from eth_consensus_specs.test.helpers.keys import builder_pubkeys, xmss_builder_pubkeys


def prepare_builder_deposit_request(spec, pubkey, amount, suffix=bytes(16), signature=bytes(96)):
    """
    A builder deposit request naming ``pubkey``, followed by ``suffix``.
    """
    return spec.BuilderDepositRequest(
        pubkey=spec.Bytes48(pubkey + suffix),
        withdrawal_credentials=spec.BUILDER_WITHDRAWAL_PREFIX + b"\x00" * 11 + b"\x33" * 20,
        amount=amount,
        signature=spec.Bytes96(signature),
    )


def get_builder_index(state, pubkey):
    return [builder.pubkey for builder in state.builders].index(pubkey)


@with_phases([PQ])
@spec_state_test
def test_new_builder_deposit(spec, state):
    pubkey = xmss_builder_pubkeys[len(state.builders)]
    amount = spec.MIN_DEPOSIT_AMOUNT
    request = prepare_builder_deposit_request(spec, pubkey, amount)

    yield from run_builder_deposit_request_processing(spec, state, request)

    builder = state.builders[get_builder_index(state, pubkey)]
    assert builder.balance == amount
    assert builder.execution_address == request.withdrawal_credentials[12:]


@with_phases([PQ])
@spec_state_test
def test_new_builder_deposit_ignores_signature(spec, state):
    pubkey = xmss_builder_pubkeys[len(state.builders)]
    amount = spec.MIN_DEPOSIT_AMOUNT
    request = prepare_builder_deposit_request(spec, pubkey, amount, signature=b"\xee" * 96)

    yield from run_builder_deposit_request_processing(spec, state, request)

    builder = state.builders[get_builder_index(state, pubkey)]
    assert builder.balance == amount
    assert builder.withdrawable_epoch == spec.FAR_FUTURE_EPOCH


@with_phases([PQ])
@spec_state_test
def test_legacy_builder_deposit_initiates_exit(spec, state):
    bls_pubkey = builder_pubkeys[len(state.builders)]
    amount = spec.MIN_DEPOSIT_AMOUNT
    request = prepare_builder_deposit_request(spec, bls_pubkey[:32], amount, suffix=bls_pubkey[32:])
    assert spec.is_legacy_pubkey(request.pubkey)
    current_epoch = spec.get_current_epoch(state)

    yield from run_builder_deposit_request_processing(spec, state, request)

    builder = state.builders[get_builder_index(state, spec.sha256(bls_pubkey + b"\x00"))]
    assert builder.balance == amount
    expected_withdrawable = current_epoch + spec.config.MIN_BUILDER_WITHDRAWABILITY_DELAY
    assert builder.withdrawable_epoch == expected_withdrawable


@with_phases([PQ])
@spec_state_test
def test_builder_top_up(spec, state):
    builder_index = 0
    pre_balance = state.builders[builder_index].balance
    amount = spec.MIN_DEPOSIT_AMOUNT
    request = prepare_builder_deposit_request(spec, state.builders[builder_index].pubkey, amount)

    yield from run_builder_deposit_request_processing(spec, state, request)

    assert state.builders[builder_index].balance == pre_balance + amount

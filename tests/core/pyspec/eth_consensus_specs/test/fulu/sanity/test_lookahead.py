from eth_consensus_specs.test.context import (
    spec_state_test,
    with_phases,
)
from eth_consensus_specs.test.helpers.attestations import (
    state_transition_with_full_block,
)
from eth_consensus_specs.test.helpers.constants import ELECTRA, FULU
from eth_consensus_specs.test.helpers.state import (
    next_epoch,
    simulate_lookahead,
)
from eth_consensus_specs.test.helpers.withdrawals import (
    set_compounding_withdrawal_credential,
)


def run_test_effective_balance_increase_changes_lookahead(
    spec, state, randao_setup_epochs, expect_lookahead_changed
):
    # Advance few epochs to adjust the RANDAO
    for _ in range(randao_setup_epochs):
        next_epoch(spec, state)

    # Set all active validators to have balance close to the hysteresis threshold
    current_epoch = spec.get_current_epoch(state)
    active_validator_indices = spec.get_active_validator_indices(state, current_epoch)
    for validator_index in active_validator_indices:
        # Set compounding withdrawal credentials for the validator
        set_compounding_withdrawal_credential(spec, state, validator_index)
        state.validators[validator_index].effective_balance = 32000000000
        # Set balance to close the next hysteresis threshold
        state.balances[validator_index] = 33250000000 - 1

    # Calculate the lookahead of next epoch
    next_epoch_lookahead = simulate_lookahead(spec, state)[spec.SLOTS_PER_EPOCH :]

    blocks = []
    yield "pre", state

    # Process 1-epoch worth of blocks with attestations
    for _ in range(spec.SLOTS_PER_EPOCH):
        block = state_transition_with_full_block(
            spec, state, fill_cur_epoch=True, fill_prev_epoch=True
        )
        blocks.append(block)

    yield "blocks", blocks
    yield "post", state

    # Calculate the actual lookahead
    actual_lookahead = simulate_lookahead(spec, state)[: spec.SLOTS_PER_EPOCH]

    if expect_lookahead_changed:
        assert next_epoch_lookahead != actual_lookahead
    else:
        assert next_epoch_lookahead == actual_lookahead


def run_test_with_randao_setup_epochs(spec, state, randao_setup_epochs):
    if spec.fork == ELECTRA:
        # Pre-EIP-7917, effective balance changes due to attestation rewards
        # changes the next epoch's lookahead
        expect_lookahead_changed = True
    else:
        # Post-EIP-7917, effective balance changes due to attestation rewards
        # do not change the next epoch's lookahead
        expect_lookahead_changed = False

    yield from run_test_effective_balance_increase_changes_lookahead(
        spec, state, randao_setup_epochs, expect_lookahead_changed=expect_lookahead_changed
    )


@with_phases(phases=[ELECTRA, FULU])
@spec_state_test
def test_effective_balance_increase_changes_lookahead(spec, state):
    # Since this test relies on the RANDAO, we find the right number of next_epoch
    # transitions before entering the generator (to avoid yield/try-except conflicts).
    # We start with 4 epochs because the test is known to pass with 4 epochs.
    randao_setup_epochs = _find_randao_setup_epochs(spec, state)
    if randao_setup_epochs is None:
        return  # RANDAO conditions not met for this fork at this genesis epoch; skip
    yield from run_test_with_randao_setup_epochs(spec, state, randao_setup_epochs)


def _find_randao_setup_epochs(spec, state):
    """Pre-compute the right randao_setup_epochs by running the test logic without yields."""
    if spec.fork == ELECTRA:
        expect_lookahead_changed = True
    else:
        expect_lookahead_changed = False

    for n in range(0, 20):
        s = state.copy()
        for _ in range(n):
            next_epoch(spec, s)
        current_epoch = spec.get_current_epoch(s)
        active = spec.get_active_validator_indices(s, current_epoch)
        for vi in active:
            set_compounding_withdrawal_credential(spec, s, vi)
            s.validators[vi].effective_balance = 32000000000
            s.balances[vi] = 33250000000 - 1
        next_look = simulate_lookahead(spec, s)[spec.SLOTS_PER_EPOCH :]
        s2 = s.copy()
        for _ in range(spec.SLOTS_PER_EPOCH):
            state_transition_with_full_block(spec, s2, True, True)
        actual = simulate_lookahead(spec, s2)[: spec.SLOTS_PER_EPOCH]
        if expect_lookahead_changed:
            if next_look != actual:
                return n
        elif next_look == actual:
            return n
    return None

from eth_consensus_specs.test.context import (
    always_bls,
    expect_assertion_error,
    spec_test,
    with_config_overrides,
    with_phases,
    with_state,
)
from eth_consensus_specs.test.helpers.attestations import sign_indexed_attestation
from eth_consensus_specs.test.helpers.attester_slashings import (
    get_valid_attester_slashing,
)
from eth_consensus_specs.test.helpers.constants import (
    ALL_PHASES,
    FULU,
    GLOAS,
    HEZE,
    PHASE0,
    POST_FORK_OF,
)
from eth_consensus_specs.test.helpers.fork_choice import (
    get_genesis_forkchoice_store_and_block,
)
from eth_consensus_specs.test.helpers.fork_transition import get_upgrade_fn
from eth_consensus_specs.test.helpers.forks import is_post_fork
from eth_consensus_specs.test.helpers.state import next_slots

FORK_EPOCH = 1


def with_scheduled_fork(fn):
    """
    Schedule the fork after ``spec.fork`` at ``FORK_EPOCH`` and the earlier ones at genesis.
    """

    def wrapper(*args, spec, **kw):
        overrides = {
            f"{fork.upper()}_FORK_EPOCH": 0
            for fork in ALL_PHASES
            if fork != PHASE0 and is_post_fork(spec.fork, fork)
        }
        overrides[f"{POST_FORK_OF[spec.fork].upper()}_FORK_EPOCH"] = FORK_EPOCH
        return with_config_overrides(overrides)(fn)(*args, spec=spec, **kw)

    return wrapper


def get_post_fork_state(spec, post_spec, state):
    """
    Return ``state`` advanced through the fork, two slots into ``FORK_EPOCH``.
    """
    post_state = state.copy()
    spec.process_slots(post_state, spec.compute_start_slot_at_epoch(FORK_EPOCH))
    post_state = get_upgrade_fn(post_spec, post_spec.fork)(post_state)
    assert post_state.fork.current_version != state.fork.current_version
    next_slots(post_spec, post_state, 2)
    return post_state


@with_phases(phases=[FULU, GLOAS], other_phases=[GLOAS, HEZE])
@spec_test
@with_state
@with_scheduled_fork
@always_bls
def test_on_attester_slashing__pre_fork_justified_state(spec, phases, state):
    post_spec = phases[POST_FORK_OF[spec.fork]]
    post_state = get_post_fork_state(spec, post_spec, state)

    # The store of a node in the fork epoch whose justified checkpoint is still the pre-fork anchor
    _, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    store = post_spec.get_forkchoice_store(state, anchor_block)
    post_spec.on_tick(
        store, post_spec.compute_time_at_slot_ms(store.genesis_time_ms, post_state.slot)
    )
    assert store.block_states[store.justified_checkpoint.root].fork == state.fork

    # Double votes from before and after the fork, respectively
    for slot in (post_state.slot - 3, post_state.slot - 1):
        attester_slashing = get_valid_attester_slashing(
            post_spec, post_state, slot=slot, signed_1=True, signed_2=True
        )
        indices = set(attester_slashing.attestation_1.attesting_indices)
        assert store.equivocating_indices.isdisjoint(indices)

        # The slashing is valid in a block, so the fork choice must accept it too
        post_spec.process_attester_slashing(post_state.copy(), attester_slashing)
        post_spec.on_attester_slashing(store, attester_slashing)
        assert store.equivocating_indices.issuperset(indices)


@with_phases(phases=[FULU, GLOAS], other_phases=[GLOAS, HEZE])
@spec_test
@with_state
@with_scheduled_fork
@always_bls
def test_on_attester_slashing__target_epoch_after_upcoming_fork(spec, phases, state):
    post_spec = phases[POST_FORK_OF[spec.fork]]
    post_state = get_post_fork_state(spec, post_spec, state)
    store, _ = get_genesis_forkchoice_store_and_block(spec, state)
    assert spec.get_current_store_epoch(store) < FORK_EPOCH

    attester_slashing = get_valid_attester_slashing(spec, state)
    attestations = (attester_slashing.attestation_1, attester_slashing.attestation_2)
    for attestation in attestations:
        attestation.data.target.epoch = FORK_EPOCH

    # As in a block, the upcoming fork version is not valid yet
    for attestation in attestations:
        sign_indexed_attestation(post_spec, post_state, attestation)
    expect_assertion_error(lambda: spec.process_attester_slashing(state.copy(), attester_slashing))
    expect_assertion_error(lambda: spec.on_attester_slashing(store, attester_slashing))
    assert len(store.equivocating_indices) == 0

    # As in a block, the current fork version is valid
    for attestation in attestations:
        sign_indexed_attestation(spec, state, attestation)
    spec.process_attester_slashing(state.copy(), attester_slashing)
    spec.on_attester_slashing(store, attester_slashing)
    assert len(store.equivocating_indices) > 0

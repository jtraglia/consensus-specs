import copy

from deepdiff import DeepDiff

from eth_consensus_specs.test.context import (
    single_phase,
    spec_test,
    with_fulu_and_later,
)


def make_hash(n):
    """Create a distinct Hash32 from an integer."""
    return n.to_bytes(32, "big")


ZERO_HASH = b"\x00" * 32


def run_update_circuit_breaker(spec, pre, updates):
    """
    Run ``update_circuit_breaker`` for each ForkchoiceState in ``updates``,
    yielding pre state, updates, and post state.
    """
    yield "pre", pre
    yield "updates", updates

    for fc in updates:
        spec.update_circuit_breaker(pre, fc)

    yield "post", pre


# ──────────────────────────────────────────────────────────────────────
# Basic tests
# ──────────────────────────────────────────────────────────────────────


@with_fulu_and_later
@spec_test
@single_phase
def test_circuit_breaker__no_updates(spec):
    """Circuit breaker state is unchanged when no updates are applied."""
    cb = spec.CircuitBreakerState(
        level=0,
        qualifying_finality_changes=0,
        head_updates_since_finalization=0,
        head_block_hash=ZERO_HASH,
        finalized_block_hash=ZERO_HASH,
        recent_head_block_hashes=[],
    )
    yield from run_update_circuit_breaker(spec, cb, [])
    assert cb.level == 0
    assert cb.head_updates_since_finalization == 0


@with_fulu_and_later
@spec_test
@single_phase
def test_circuit_breaker__single_head_update(spec):
    """A single head change increments head_updates_since_finalization."""
    cb = spec.CircuitBreakerState(
        level=0,
        qualifying_finality_changes=0,
        head_updates_since_finalization=0,
        head_block_hash=ZERO_HASH,
        finalized_block_hash=ZERO_HASH,
        recent_head_block_hashes=[],
    )
    updates = [
        spec.ForkchoiceState(
            head_block_hash=make_hash(1),
            safe_block_hash=ZERO_HASH,
            finalized_block_hash=ZERO_HASH,
        )
    ]
    yield from run_update_circuit_breaker(spec, cb, updates)
    assert cb.head_updates_since_finalization == 1
    assert cb.head_block_hash == make_hash(1)
    assert len(cb.recent_head_block_hashes) == 1


@with_fulu_and_later
@spec_test
@single_phase
def test_circuit_breaker__no_change(spec):
    """No effect when head and finalized hashes both match the current state."""
    h = make_hash(1)
    f = make_hash(2)
    cb = spec.CircuitBreakerState(
        level=0,
        qualifying_finality_changes=0,
        head_updates_since_finalization=5,
        head_block_hash=h,
        finalized_block_hash=f,
        recent_head_block_hashes=[],
    )
    cb_before = copy.deepcopy(cb)
    updates = [
        spec.ForkchoiceState(
            head_block_hash=h,
            safe_block_hash=ZERO_HASH,
            finalized_block_hash=f,
        )
    ]
    yield from run_update_circuit_breaker(spec, cb, updates)
    assert not DeepDiff(cb_before, cb)


@with_fulu_and_later
@spec_test
@single_phase
def test_circuit_breaker__head_and_finalized_change_together(spec):
    """When both head and finalized change in the same update, the new head
    should still be tracked in recent_head_block_hashes and head_block_hash
    should be updated."""
    cb = spec.CircuitBreakerState(
        level=0,
        qualifying_finality_changes=0,
        head_updates_since_finalization=0,
        head_block_hash=make_hash(1),
        finalized_block_hash=make_hash(100),
        recent_head_block_hashes=[],
    )
    # Both head and finalized change
    updates = [
        spec.ForkchoiceState(
            head_block_hash=make_hash(2),
            safe_block_hash=ZERO_HASH,
            finalized_block_hash=make_hash(101),
        )
    ]
    yield from run_update_circuit_breaker(spec, cb, updates)
    # head_block_hash should be updated
    assert cb.head_block_hash == make_hash(2)
    # The new head should be in recent_head_block_hashes
    assert make_hash(2) in cb.recent_head_block_hashes


# ──────────────────────────────────────────────────────────────────────
# Step-down tests
# ──────────────────────────────────────────────────────────────────────


@with_fulu_and_later
@spec_test
@single_phase
def test_circuit_breaker__no_step_down_before_threshold(spec):
    """Level stays at 0 with STEP_DOWN_THRESHOLD - 1 head changes."""
    cb = spec.CircuitBreakerState(
        level=0,
        qualifying_finality_changes=0,
        head_updates_since_finalization=0,
        head_block_hash=ZERO_HASH,
        finalized_block_hash=ZERO_HASH,
        recent_head_block_hashes=[],
    )
    updates = [
        spec.ForkchoiceState(
            head_block_hash=make_hash(i),
            safe_block_hash=ZERO_HASH,
            finalized_block_hash=ZERO_HASH,
        )
        for i in range(1, spec.STEP_DOWN_THRESHOLD)
    ]
    yield from run_update_circuit_breaker(spec, cb, updates)
    assert cb.level == 0
    assert cb.head_updates_since_finalization == spec.STEP_DOWN_THRESHOLD - 1


@with_fulu_and_later
@spec_test
@single_phase
def test_circuit_breaker__step_down_after_threshold(spec):
    """Level increases after STEP_DOWN_THRESHOLD head changes without finalization."""
    cb = spec.CircuitBreakerState(
        level=0,
        qualifying_finality_changes=0,
        head_updates_since_finalization=0,
        head_block_hash=ZERO_HASH,
        finalized_block_hash=ZERO_HASH,
        recent_head_block_hashes=[],
    )
    updates = [
        spec.ForkchoiceState(
            head_block_hash=make_hash(i),
            safe_block_hash=ZERO_HASH,
            finalized_block_hash=ZERO_HASH,
        )
        for i in range(1, spec.STEP_DOWN_THRESHOLD + 1)
    ]
    yield from run_update_circuit_breaker(spec, cb, updates)
    assert cb.level == 1
    assert cb.head_updates_since_finalization == 0


@with_fulu_and_later
@spec_test
@single_phase
def test_circuit_breaker__step_down_to_max_level(spec):
    """Level reaches MAXIMUM_LEVEL from one below."""
    cb = spec.CircuitBreakerState(
        level=spec.MAXIMUM_LEVEL - 1,
        qualifying_finality_changes=0,
        head_updates_since_finalization=0,
        head_block_hash=ZERO_HASH,
        finalized_block_hash=ZERO_HASH,
        recent_head_block_hashes=[],
    )
    updates = [
        spec.ForkchoiceState(
            head_block_hash=make_hash(i),
            safe_block_hash=ZERO_HASH,
            finalized_block_hash=ZERO_HASH,
        )
        for i in range(1, spec.STEP_DOWN_THRESHOLD + 1)
    ]
    yield from run_update_circuit_breaker(spec, cb, updates)
    assert cb.level == spec.MAXIMUM_LEVEL


@with_fulu_and_later
@spec_test
@single_phase
def test_circuit_breaker__step_down_does_not_exceed_max_level(spec):
    """A step-down at MAXIMUM_LEVEL does not increase level further."""
    cb = spec.CircuitBreakerState(
        level=spec.MAXIMUM_LEVEL,
        qualifying_finality_changes=0,
        head_updates_since_finalization=0,
        head_block_hash=ZERO_HASH,
        finalized_block_hash=ZERO_HASH,
        recent_head_block_hashes=[],
    )
    updates = [
        spec.ForkchoiceState(
            head_block_hash=make_hash(i),
            safe_block_hash=ZERO_HASH,
            finalized_block_hash=ZERO_HASH,
        )
        for i in range(1, spec.STEP_DOWN_THRESHOLD + 1)
    ]
    yield from run_update_circuit_breaker(spec, cb, updates)
    assert cb.level == spec.MAXIMUM_LEVEL


@with_fulu_and_later
@spec_test
@single_phase
def test_circuit_breaker__multiple_step_downs(spec):
    """Two consecutive rounds of head-only updates cause two step-downs."""
    cb = spec.CircuitBreakerState(
        level=0,
        qualifying_finality_changes=0,
        head_updates_since_finalization=0,
        head_block_hash=ZERO_HASH,
        finalized_block_hash=ZERO_HASH,
        recent_head_block_hashes=[],
    )
    updates = [
        spec.ForkchoiceState(
            head_block_hash=make_hash(i),
            safe_block_hash=ZERO_HASH,
            finalized_block_hash=ZERO_HASH,
        )
        for i in range(1, 2 * spec.STEP_DOWN_THRESHOLD + 1)
    ]
    yield from run_update_circuit_breaker(spec, cb, updates)
    assert cb.level == 2


# ──────────────────────────────────────────────────────────────────────
# Finalization reset tests
# ──────────────────────────────────────────────────────────────────────


@with_fulu_and_later
@spec_test
@single_phase
def test_circuit_breaker__finalization_resets_head_counter(spec):
    """A finalization update resets head_updates_since_finalization to 0."""
    cb = spec.CircuitBreakerState(
        level=0,
        qualifying_finality_changes=0,
        head_updates_since_finalization=0,
        head_block_hash=ZERO_HASH,
        finalized_block_hash=ZERO_HASH,
        recent_head_block_hashes=[],
    )
    updates = [
        spec.ForkchoiceState(
            head_block_hash=make_hash(i),
            safe_block_hash=ZERO_HASH,
            finalized_block_hash=ZERO_HASH,
        )
        for i in range(1, 10)
    ]
    updates.append(
        spec.ForkchoiceState(
            head_block_hash=make_hash(9),
            safe_block_hash=ZERO_HASH,
            finalized_block_hash=make_hash(100),
        )
    )
    yield from run_update_circuit_breaker(spec, cb, updates)
    assert cb.head_updates_since_finalization == 0
    assert cb.finalized_block_hash == make_hash(100)


@with_fulu_and_later
@spec_test
@single_phase
def test_circuit_breaker__finalization_prevents_step_down(spec):
    """Finalization mid-way through resets the counter, preventing step-down."""
    cb = spec.CircuitBreakerState(
        level=0,
        qualifying_finality_changes=0,
        head_updates_since_finalization=0,
        head_block_hash=ZERO_HASH,
        finalized_block_hash=ZERO_HASH,
        recent_head_block_hashes=[],
    )
    half = spec.STEP_DOWN_THRESHOLD // 2
    updates = []
    for i in range(1, half + 1):
        updates.append(
            spec.ForkchoiceState(
                head_block_hash=make_hash(i),
                safe_block_hash=ZERO_HASH,
                finalized_block_hash=ZERO_HASH,
            )
        )
    updates.append(
        spec.ForkchoiceState(
            head_block_hash=make_hash(half),
            safe_block_hash=ZERO_HASH,
            finalized_block_hash=make_hash(500),
        )
    )
    for i in range(half + 1, half + half + 1):
        updates.append(
            spec.ForkchoiceState(
                head_block_hash=make_hash(i),
                safe_block_hash=ZERO_HASH,
                finalized_block_hash=make_hash(500),
            )
        )
    yield from run_update_circuit_breaker(spec, cb, updates)
    assert cb.level == 0


# ──────────────────────────────────────────────────────────────────────
# Step-up tests
# ──────────────────────────────────────────────────────────────────────


@with_fulu_and_later
@spec_test
@single_phase
def test_circuit_breaker__no_step_up_before_threshold(spec):
    """Level stays the same with STEP_UP_THRESHOLD - 1 qualifying finality changes."""
    window = spec.RECENT_HEAD_WINDOW_SIZE
    recent_hashes = [make_hash(i) for i in range(1, window + 1)]
    cb = spec.CircuitBreakerState(
        level=2,
        qualifying_finality_changes=0,
        head_updates_since_finalization=0,
        head_block_hash=make_hash(999),
        finalized_block_hash=ZERO_HASH,
        recent_head_block_hashes=recent_hashes,
    )
    # Cycle through the recent hashes to accumulate qualifying changes
    updates = [
        spec.ForkchoiceState(
            head_block_hash=make_hash(999),
            safe_block_hash=ZERO_HASH,
            finalized_block_hash=make_hash((i % window) + 1),
        )
        for i in range(spec.STEP_UP_THRESHOLD - 1)
    ]
    yield from run_update_circuit_breaker(spec, cb, updates)
    assert cb.level == 2
    assert cb.qualifying_finality_changes == spec.STEP_UP_THRESHOLD - 1


@with_fulu_and_later
@spec_test
@single_phase
def test_circuit_breaker__step_up_with_qualifying_finality_changes(spec):
    """Level decreases after STEP_UP_THRESHOLD qualifying finality changes."""
    window = spec.RECENT_HEAD_WINDOW_SIZE
    recent_hashes = [make_hash(i) for i in range(1, window + 1)]
    cb = spec.CircuitBreakerState(
        level=2,
        qualifying_finality_changes=0,
        head_updates_since_finalization=0,
        head_block_hash=make_hash(999),
        finalized_block_hash=ZERO_HASH,
        recent_head_block_hashes=recent_hashes,
    )
    # Cycle through the recent hashes to accumulate qualifying changes
    updates = [
        spec.ForkchoiceState(
            head_block_hash=make_hash(999),
            safe_block_hash=ZERO_HASH,
            finalized_block_hash=make_hash((i % window) + 1),
        )
        for i in range(spec.STEP_UP_THRESHOLD)
    ]
    yield from run_update_circuit_breaker(spec, cb, updates)
    assert cb.level == 1
    assert cb.qualifying_finality_changes == 0


@with_fulu_and_later
@spec_test
@single_phase
def test_circuit_breaker__step_up_non_qualifying_resets_counter(spec):
    """A non-qualifying finality change resets qualifying_finality_changes."""
    recent_hashes = [make_hash(i) for i in range(1, 5)]
    cb = spec.CircuitBreakerState(
        level=1,
        qualifying_finality_changes=0,
        head_updates_since_finalization=0,
        head_block_hash=make_hash(999),
        finalized_block_hash=ZERO_HASH,
        recent_head_block_hashes=recent_hashes,
    )
    updates = [
        spec.ForkchoiceState(
            head_block_hash=make_hash(999),
            safe_block_hash=ZERO_HASH,
            finalized_block_hash=make_hash(1),
        ),
        spec.ForkchoiceState(
            head_block_hash=make_hash(999),
            safe_block_hash=ZERO_HASH,
            finalized_block_hash=make_hash(9999),
        ),
    ]
    yield from run_update_circuit_breaker(spec, cb, updates)
    assert cb.qualifying_finality_changes == 0
    assert cb.level == 1


@with_fulu_and_later
@spec_test
@single_phase
def test_circuit_breaker__step_up_ignored_at_level_zero(spec):
    """Qualifying finality changes at level 0 do not decrease the level."""
    recent_hashes = [make_hash(i) for i in range(1, 5)]
    cb = spec.CircuitBreakerState(
        level=0,
        qualifying_finality_changes=0,
        head_updates_since_finalization=0,
        head_block_hash=make_hash(999),
        finalized_block_hash=ZERO_HASH,
        recent_head_block_hashes=recent_hashes,
    )
    updates = [
        spec.ForkchoiceState(
            head_block_hash=make_hash(999),
            safe_block_hash=ZERO_HASH,
            finalized_block_hash=make_hash(1),
        )
    ]
    yield from run_update_circuit_breaker(spec, cb, updates)
    assert cb.level == 0
    assert cb.qualifying_finality_changes == 0


# ──────────────────────────────────────────────────────────────────────
# Recent head window tests
# ──────────────────────────────────────────────────────────────────────


@with_fulu_and_later
@spec_test
@single_phase
def test_circuit_breaker__recent_head_window_bounded(spec):
    """The recent_head_block_hashes list does not exceed RECENT_HEAD_WINDOW_SIZE."""
    cb = spec.CircuitBreakerState(
        level=0,
        qualifying_finality_changes=0,
        head_updates_since_finalization=0,
        head_block_hash=ZERO_HASH,
        finalized_block_hash=ZERO_HASH,
        recent_head_block_hashes=[],
    )
    count = spec.RECENT_HEAD_WINDOW_SIZE + 10
    updates = [
        spec.ForkchoiceState(
            head_block_hash=make_hash(i),
            safe_block_hash=ZERO_HASH,
            finalized_block_hash=ZERO_HASH,
        )
        for i in range(1, count + 1)
    ]
    yield from run_update_circuit_breaker(spec, cb, updates)
    assert len(cb.recent_head_block_hashes) == spec.RECENT_HEAD_WINDOW_SIZE
    expected_start = count - spec.RECENT_HEAD_WINDOW_SIZE + 1
    assert cb.recent_head_block_hashes[0] == make_hash(expected_start)
    assert cb.recent_head_block_hashes[spec.RECENT_HEAD_WINDOW_SIZE - 1] == make_hash(count)


# ──────────────────────────────────────────────────────────────────────
# Combined step-down and step-up
# ──────────────────────────────────────────────────────────────────────


@with_fulu_and_later
@spec_test
@single_phase
def test_circuit_breaker__step_down_then_step_up(spec):
    """Step-down via head updates, then recover via qualifying finality changes."""
    cb = spec.CircuitBreakerState(
        level=0,
        qualifying_finality_changes=0,
        head_updates_since_finalization=0,
        head_block_hash=ZERO_HASH,
        finalized_block_hash=ZERO_HASH,
        recent_head_block_hashes=[],
    )
    updates = []

    # Phase 1: STEP_DOWN_THRESHOLD head updates -> level goes to 1
    for i in range(1, spec.STEP_DOWN_THRESHOLD + 1):
        updates.append(
            spec.ForkchoiceState(
                head_block_hash=make_hash(i),
                safe_block_hash=ZERO_HASH,
                finalized_block_hash=ZERO_HASH,
            )
        )

    # Phase 2: STEP_UP_THRESHOLD qualifying finality changes -> level back to 0
    start = spec.STEP_DOWN_THRESHOLD - spec.RECENT_HEAD_WINDOW_SIZE + 1
    for i in range(spec.STEP_UP_THRESHOLD):
        idx = start + (i % spec.RECENT_HEAD_WINDOW_SIZE)
        updates.append(
            spec.ForkchoiceState(
                head_block_hash=make_hash(spec.STEP_DOWN_THRESHOLD),
                safe_block_hash=ZERO_HASH,
                finalized_block_hash=make_hash(idx),
            )
        )

    yield from run_update_circuit_breaker(spec, cb, updates)
    assert cb.level == 0

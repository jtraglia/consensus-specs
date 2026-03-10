# Fulu -- Throughput Circuit Breaker

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Configuration](#configuration)
- [Helpers](#helpers)
  - [New `ForkchoiceState`](#new-forkchoicestate)
  - [New `CircuitBreakerState`](#new-circuitbreakerstate)
  - [New `initialize_circuit_breaker`](#new-initialize_circuit_breaker)
  - [New `update_circuit_breaker`](#new-update_circuit_breaker)
  - [New `get_circuit_breaker_level`](#new-get_circuit_breaker_level)

<!-- mdformat-toc end -->

## Configuration

| Name                      | Value                  | Description                                        |
| :------------------------ | :--------------------- | :------------------------------------------------- |
| `MAXIMUM_LEVEL`           | `2**3` (= 8)           | Maximum level (80% blob throughput reduction)      |
| `STEP_DOWN_THRESHOLD`     | `2**8` (= 256 changes) | Head changes without finalization before step-down |
| `STEP_UP_THRESHOLD`       | `2**8` (= 256 changes) | Qualifying finality changes to recover one level   |
| `RECENT_HEAD_WINDOW_SIZE` | `2**7` (= 128 hashes)  | Window size for qualifying finality change check   |

## Helpers

### New `ForkchoiceState`

```python
class ForkchoiceState(Container):
    head_block_hash: Hash32
    safe_block_hash: Hash32
    finalized_block_hash: Hash32
```

### New `CircuitBreakerState`

```python
class CircuitBreakerState(Container):
    level: uint64
    qualifying_finality_changes: uint64
    head_updates_since_finalization: uint64
    head_block_hash: Hash32
    finalized_block_hash: Hash32
    recent_head_block_hashes: List[Hash32, RECENT_HEAD_WINDOW_SIZE]
```

### New `initialize_circuit_breaker`

```python
def initialize_circuit_breaker(cb: CircuitBreakerState) -> None:
    """
    Initialize the circuit breaker's state.
    """
    cb.level = 0
    cb.qualifying_finality_changes = 0
    cb.head_updates_since_finalization = 0
    cb.head_block_hash = Hash32()
    cb.finalized_block_hash = Hash32()
    cb.recent_head_block_hashes = List([])
```

### New `update_circuit_breaker`

```python
def update_circuit_breaker(cb: CircuitBreakerState, fc: ForkchoiceState) -> None:
    """
    Update the circuit breaker's state given data from engine_forkchoiceUpdated.
    """
    # Check if head/finalized hashes changed
    head_changed = fc.head_block_hash != cb.head_block_hash
    finalized_changed = fc.finalized_block_hash != cb.finalized_block_hash

    if head_changed:
        cb.head_block_hash = fc.head_block_hash

        # Add this hash to the list of recent head block hashes,
        # evicting the oldest entry if the window is full.
        if len(cb.recent_head_block_hashes) >= RECENT_HEAD_WINDOW_SIZE:
            cb.recent_head_block_hashes = cb.recent_head_block_hashes[1:]
        cb.recent_head_block_hashes.append(cb.head_block_hash)

    if finalized_changed:
        cb.finalized_block_hash = fc.finalized_block_hash
        cb.head_updates_since_finalization = 0

        # If the finalized block hash is in the list of recent head block hashes,
        # that means that the finalized state is somewhat recent and the network
        # is operating normally again. If we have encountered the required number
        # of recent finality changes, step-up (raise the blob target/limit).
        if cb.level > 0:
            if fc.finalized_block_hash in cb.recent_head_block_hashes:
                cb.qualifying_finality_changes += 1
                if cb.qualifying_finality_changes >= STEP_UP_THRESHOLD:
                    cb.level -= 1
                    cb.qualifying_finality_changes = 0
            else:
                cb.qualifying_finality_changes = 0

    elif head_changed:
        cb.head_updates_since_finalization += 1

        # If there has been some number of head updates without a finalization
        # update, that means the network has stopped finalizing. Out of caution,
        # step-down (lower the blob target/limit).
        if cb.head_updates_since_finalization >= STEP_DOWN_THRESHOLD:
            cb.head_updates_since_finalization = 0
            cb.qualifying_finality_changes = 0
            if cb.level < MAXIMUM_LEVEL:
                cb.level += 1
```

### New `get_circuit_breaker_level`

```python
def get_circuit_breaker_level(cb: CircuitBreakerState) -> uint64:
    """
    Get the current circuit breaker level.
    """
    return cb.level
```

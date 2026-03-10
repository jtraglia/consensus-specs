# Test format: circuit breaker update

## Test case format

### `pre.yaml`

A YAML-encoded `CircuitBreakerState`, the state before applying updates.

```yaml
level: int
qualifying_finality_changes: int
head_updates_since_finalization: int
head_block_hash: bytes32
finalized_block_hash: bytes32
recent_head_block_hashes: List[bytes32]
```

### `updates.yaml`

A list of YAML-encoded `ForkchoiceState` objects to apply in sequence.

```yaml
- head_block_hash: bytes32
  safe_block_hash: bytes32
  finalized_block_hash: bytes32
- head_block_hash: bytes32
  safe_block_hash: bytes32
  finalized_block_hash: bytes32
...
```

### `post.yaml`

A YAML-encoded `CircuitBreakerState`, the expected state after applying all
updates.

Same format as `pre.yaml`.

## Condition

The `post` state should match the result of calling
`update_circuit_breaker(cb, fc)` for each `ForkchoiceState` in `updates`,
applied in order to the `pre` state. Each level represents a 10% drop in blob
throughput, capped at `MAXIMUM_LEVEL`.

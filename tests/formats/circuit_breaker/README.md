# Circuit breaker tests

A test type for the throughput circuit breaker. Tests the
`update_circuit_breaker` function by applying a sequence of `ForkchoiceState`
updates to a `CircuitBreakerState` and checking the resulting state.

The circuit breaker test suite runner has one handler:

- [`update`](./update.md)

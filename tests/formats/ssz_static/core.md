# Test format: SSZ static types

The goal of this type is to provide clients with a solid reference for how the
known SSZ objects should be encoded. Each object described in the Phase 0 spec
is covered. This is important, as many of the clients aiming to
serialize/deserialize objects directly into structs/classes do not support (or
have alternatives for) generic SSZ encoding/decoding.

This test-format ensures these direct serializations are covered.

Note that this test suite does not cover the invalid-encoding case, with one
exception: the over-limit cases of the `ssz_limit` suite described below. SSZ
implementations should otherwise be hardened against invalid inputs with the
other SSZ tests as guide, along with fuzzing.

## Test case format

Each SSZ type is a `handler`, since the format is semantically different: the
type of the data is different.

One can iterate over the handlers, and select the type based on the handler
name. Suites are then the same format, but each specialized in one randomization
mode. Some randomization modes may only produce a single test case (e.g. the
all-zeroes case).

The output parts are: `roots.yaml`, `serialized.ssz_snappy`, `value.yaml`

### `roots.yaml`

```yaml
root: bytes32         -- string, hash-tree-root of the value, hex encoded, with prefix 0x
```

### `serialized.ssz_snappy`

The SSZ-snappy encoded bytes.

### `value.yaml`

The same value as `serialized.ssz_snappy`, represented as YAML.

## Limit suite

Since Gloas, list types with a declared `LIMIT` are handlers as well, named after
the type (e.g. `Attestations`). These handlers, and every container handler with
a field of such a type, have an `ssz_limit` suite whose cases carry a `meta.yaml`:

```yaml
valid: bool           -- whether a decoder must accept `serialized`
```

- `at_limit`: the list filled to exactly `LIMIT` default elements, `valid: true`,
  with the standard output parts. A limit set too low rejects this encoding.
- `over_limit`: the list filled to `LIMIT + 1` default elements, `valid: false`,
  with `serialized.ssz_snappy` only. Deserialization MUST fail. A limit set too
  high accepts this encoding.

Under a container handler the cases are named `<field>_at_limit` and
`<field>_over_limit`, with the other fields at their defaults. This checks the
limit where the field declares it and not only on the standalone type.

Runners branch on `valid`, a case without `meta.yaml` is valid. Lists whose
encoding at the limit would exceed 16 MiB are not covered.

## Condition

A test-runner can implement the following assertions:

- If YAML decoding of SSZ objects is supported by the implementation:
  - Serialization: After parsing the `value`, SSZ-serialize it: the output
    should match `serialized`
  - Deserialization: SSZ-deserialize the `serialized` value, and see if it
    matches the parsed `value`
- If YAML decoding of SSZ objects is not supported by the implementation:
  - Serialization in 2 steps: deserialize `serialized`, then serialize the
    result, and verify if the bytes match the original `serialized`.
- Hash-tree-root: After parsing the `value` (or deserializing `serialized`),
  Hash-tree-root it: the output should match `root`

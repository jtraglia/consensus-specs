# The Lean specification

A prototype. A function that a specification defines in a `lean` code block is
compiled and called from the generated Python, instead of being executed as
Python. Callers and tests do not change.

## Writing one

Put a `lean` block beside the `python` one, under the same heading. The Lean
definition must have the same name as the function, and a signature that matches
the Python one.

````markdown
#### New `is_active_builder`

```python
def is_active_builder(state: BeaconState, builder_index: BuilderIndex) -> bool:
    builder = state.builders[builder_index]
    return (
        builder.deposit_epoch < state.finalized_checkpoint.epoch
        and builder.withdrawable_epoch == FAR_FUTURE_EPOCH
    )
```

```lean
def is_active_builder (state : BeaconState) (builder_index : BuilderIndex) : Bool :=
  let builder := state.builders[builder_index.toNat]!
  builder.deposit_epoch < state.finalized_checkpoint.epoch
    && builder.withdrawable_epoch == FAR_FUTURE_EPOCH
```
````

Then:

```sh
make lean
```

That regenerates the specifications and builds the shared library the generated
Python calls into. Running the tests afterwards needs nothing else.

The Python block stays. It remains the readable definition of record, and it is
what a reader of the specification sees.

## What you can write against

Everything except the function body is generated from the same markdown the
Python comes from, so the two sides cannot drift:

- an ordinary Lean `structure` for every type, so `state.slot` reads a field and
  `{ state with slot := x }` is a copy with one changed
- `X.empty`, which is what `X.empty()` gives in Python
- an `Ssz.Desc` for every type, under `Descs`, and the conversions either way
- every constant of the preset, spelled as the specification spells it
- `Uint64`, `Bytes32`, `Boolean` and the rest, so a signature reads like the
  Python one

A function that edits its argument is written as one that returns the new value.
The Python signature stays `-> None`, and the caller copies the result back.

A function that asserts returns `SpecM T`, and uses `check`. A refusal reaches
the caller as the `AssertionError` the Python would have raised.

## Three shapes, as they appear in gloas

| function                               | shape                        |
| -------------------------------------- | ---------------------------- |
| `is_builder_index`                     | integers only                |
| `update_next_withdrawal_builder_index` | edits the state              |
| `settle_builder_payment`               | edits the state, and asserts |

## How it fits together

```
specs/**.md  ──┬─► tests/core/pyspec/…/<preset>.py   the wrapper that calls in
               └─► lean/Spec/Generated/…           types, constants, bodies
                                  │
                                  └─► libspec.<so|dylib>
```

Arguments cross as SSZ bytes: a run of frames, each a four-byte little-endian
length and that many bytes. The reply is a status byte, then the encoded result,
or the reason an assertion refused it.

The SSZ codec, merkleization and hashing are the Lean implementation from
[ethereum/ssz-specs#132][ssz], pinned in `lakefile.toml` because that branch is
not merged. It carries proofs that encoding and decoding agree, that no two
values share an encoding, and that a proof built for a node verifies against the
root.

## What it costs

Serializing one minimal-preset `BeaconState` to cross the boundary takes about
1.3 ms, and about 57 ms under the mainnet preset. The cost is per crossing, not
per function, so it falls as more of a call tree moves into Lean and rises while
only its leaves have.

## What it does not do yet

- Only SSZ types cross. A signature holding `Sequence[…]`, `Optional[…]`,
  `Store` or a `Dict` is refused, and the generator says which type stopped it.
- Lean definitions can only call other Lean definitions. A function moves once
  everything it calls has moved, so whole call trees move together rather than
  single leaves.
- Nothing calls back into Python, so `bls` and anything reaching it stay out of
  reach until they are bound to C from the Lean side.
- Once a specification defines something in Lean, running its tests needs the
  Lean toolchain. Install it from <https://lean-lang.org/install/>.

[ssz]: https://github.com/ethereum/ssz-specs/pull/132

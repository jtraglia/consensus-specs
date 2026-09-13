# The Lean specification

A prototype. A function that a specification defines in a `lean` code block is
compiled and called from the generated Python, instead of being executed as
Python. Callers and tests do not change.

## Writing one

Put a `lean` block under the function's heading. Once it is there, the Python
block can go: the signature and docstring the generated module needs are read
off the Lean.

````markdown
#### New `settle_builder_payment`

```lean
def settle_builder_payment (state : BeaconState) (payment_index : Uint64) : Result BeaconState := do
  assert payment_index.toNat < state.builder_pending_payments.size
  let mut state := state
  let payment := state.builder_pending_payments[payment_index.toNat]!
  if payment.withdrawal.amount > 0 then
    state.builder_pending_withdrawals := state.builder_pending_withdrawals.push payment.withdrawal
  state.builder_pending_payments[payment_index.toNat] := BuilderPendingPayment.empty
  return state
```
````

Then:

```sh
make lean
```

That regenerates the specifications and builds the shared library the generated
Python calls into. Running the tests afterwards needs nothing else.

## What you can write against

Everything except the function body is generated from the same markdown, so the
two sides cannot drift:

- an ordinary Lean `structure` for every type, so `state.slot` reads a field
- `X.empty`, which is what `X.empty()` gives in Python
- every constant of the preset, spelled as the specification spells it
- `Uint64`, `Bytes32`, `Boolean` and the rest, so a signature reads like a
  Python one
- an `Ssz.Desc` per type under `Descs`, and the conversions either way

Two pieces of notation cover what Lean does not have. Neither adds a capability:
they are the same terms, spelled the way the specification reads.

| you write                | it means                                    |
| ------------------------ | ------------------------------------------- |
| `assert c`               | reject unless `c`, naming the condition     |
| `state.slot := v`        | `state := { state with slot := v }`         |
| `state.fork.epoch := v`  | the same, nested                            |
| `state.balances[i] := v` | `state.balances := state.balances.set! i v` |

A function that can reject returns `Result T`, which is what lets `assert` work.
A refusal reaches the caller as the `AssertionError` the Python raised, carrying
the condition that failed.

A function that edits its argument is written as one that returns the new value.
Lean updates a structure in place when it holds the only reference, so those
copies are not copies. Because the result is the type of the first argument, the
generated Python declares it `-> None` and copies the result back, so callers
see the in-place edit they saw before.

## Four shapes, as they appear in gloas

| function                               | shape                        |
| -------------------------------------- | ---------------------------- |
| `is_builder_index`                     | integers only                |
| `is_active_builder`                    | reads a `BeaconState`        |
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
  Roughly half of the gloas functions can be bound today.
- A definition whose result is the type of its first argument is taken to edit
  it. A genuinely pure function of that shape would need to say so some other
  way.
- Lean definitions can only call other Lean definitions. A function moves once
  everything it calls has moved, so whole call trees move together rather than
  single leaves.
- Nothing calls back into Python, so `bls` and anything reaching it stay out of
  reach until they are bound to C from the Lean side.
- Once a specification defines something in Lean, running its tests needs the
  Lean toolchain. Install it from <https://lean-lang.org/install/>.

[ssz]: https://github.com/ethereum/ssz-specs/pull/132

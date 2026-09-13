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
def settle_builder_payment
    (state : BeaconState)
    (payment_index : Uint64)
    : Result BeaconState := do
  let mut payments := state.builder_pending_payments
  let mut withdrawals := state.builder_pending_withdrawals

  let payment <- payments[payment_index]
  if payment.withdrawal.amount > 0 then
    withdrawals := withdrawals.append payment.withdrawal
  payments <- payments.set payment_index BuilderPendingPayment.empty

  return { state with
    builder_pending_payments := payments
    builder_pending_withdrawals := withdrawals
  }
```
````

Then:

```sh
make lean
```

That regenerates the specifications and builds the shared library the generated
Python calls into. Running the tests afterwards needs nothing else.

## How it is written

Plain Lean, with no notation of our own: what is in the block is what the
compiler sees. Only the ASCII spellings are used, so `<-` rather than the left
arrow and `->` rather than the function arrow.

A definition is indented two columns and kept inside 90. Its name stands alone
on the first line, however short it is, and every parameter takes a line of its
own, indented four, with the result type under them and the `:=` closing that
line:

```lean
def is_active_builder
    (state : BeaconState)
    (builder_index : BuilderIndex)
    : Result Bool := do
```

So the parameters a definition takes, and the one thing it gives back, each read
down a single column, no matter how many there are.

This is not how Mathlib lays out a declaration, which keeps parameters on the
first line and breaks before the result type. A specification function takes
more parameters than a lemma does, so the column reads better here.

A definition carries no comments at all, of either kind. What is worth saying
about one is said in the prose around it, where the rest of the specification
says things, and where it is not trapped inside a code block.

## Rejecting

A definition that can reject returns `Result`, which is what a `do` block's `<-`
and `return` are written against. A rejection reaches the caller as the
`AssertionError` the Python raised.

There are two ways to reject, and both say what Python says:

- `assert c` rejects unless `c` holds.
- `xs[index]` and `xs.set index value` reject when the index is past the end,
  which is what an `IndexError` does.

Nothing panics, so no definition can take the Python process down with it.

A definition that edits its argument is written as one that returns the new
value. Lean updates a structure in place when it holds the only reference, so
those copies are not copies. Because the result is the type of the first
argument, the generated Python declares it `-> None` and copies the result back,
so callers see the in-place edit they saw before.

## What you can write against

Everything except the definitions is generated from the same markdown, so the
two sides cannot drift:

- an ordinary Lean `structure` for every type, so `state.slot` reads a field
- `X.empty`, which is what `X.empty()` gives in Python
- every constant of the preset, spelled as the specification spells it
- `Uint64`, `Bytes32`, `Boolean` and the rest, so a signature reads like a
  Python one
- an `Ssz.Desc` per type under `Descs`, and the conversions either way

Every unsigned integer is a `Nat`, so nothing has to be widened or converted to
be used as an index or added to something else. Its width is checked where it is
written back, which is where a value too large for the field it belongs to is
refused.

Where Python has a method, so does Lean:

| Python         | Lean                |
| -------------- | ------------------- |
| `len(xs)`      | `xs.size`           |
| `xs[i]`        | `xs[i]`             |
| `xs[i] = v`    | `xs.set i v`        |
| `xs.append(v)` | `xs.append v`       |
| `X.empty()`    | `X.empty`           |
| `x.f = v`      | `{ x with f := v }` |
| `and`, `or`    | `&&`, `\|\|`        |
| `not x`        | `!x`                |
| `a & b`        | `a &&& b`           |

## Four shapes, as they appear in gloas

| function                               | shape                         |
| -------------------------------------- | ----------------------------- |
| `is_builder_index`                     | integers only                 |
| `is_active_builder`                    | reads a `BeaconState`         |
| `update_next_withdrawal_builder_index` | edits the state               |
| `settle_builder_payment`               | edits the state, and can fail |

## How it fits together

```
specs/**.md  --+--> tests/core/pyspec/.../<preset>.py   the wrapper that calls in
               +--> lean/Spec/Generated/...           types, constants, bodies
                                  |
                                  +--> libspec.<so|dylib>
```

Arguments cross as SSZ bytes: a run of frames, each a four-byte little-endian
length and that many bytes. The reply is a status byte, then the encoded result,
or the reason it was rejected.

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

- Only SSZ types cross. A signature holding `Sequence[...]`, `Optional[...]`,
  `Store` or a `Dict` is refused, and the generator says which type stopped it.
  Roughly half of the gloas functions can be bound today.
- Subtracting past zero gives zero, where the Python raises. Every other way out
  of a `Uint64` is caught when the value is written back.
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

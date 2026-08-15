---
name: write-specs
description: >-
  Write specifications. Always load this skill before writing to `specs`.
compatibility: Requires make and uv
---

# Writing specifications

## Building

The markdown files are automatically compiled into executable Python files when
using the project's `make` rules. Run `make help verbose=true` for documentation
on available rules. Generally, only the linting and testing rules are used.

## Work-in-progress banners

Unstable specifications must include a work-in-progress banner at the top of the
document, directly below the title. Remove the banner once the specification is
promoted to the stable section of the project's README.

## Table of contents

Do not manually edit the table of contents. Running `make lint` regenerates it
automatically.

## Code style

Simplicity is a guiding principle of the specs. Code should be concise and
readable, and performant only where that does not sacrifice those qualities.
Implementations will apply optimizations that the specs deliberately omit.

Strive to write code in a generic way that other languages can translate without
difficulty. Avoid Python-specific functional helpers like `map` and `filter`. A
list comprehension or an explicit loop expresses the same logic and maps more
cleanly onto other languages.

Avoid single-letter variable names, except where a single letter is the
conventional notation in a mathematical expression.

Add a comment only when the code alone would leave something important unclear
to the reader. Do not restate what the code already does.

Docstrings and comments must be wrapped at 80 characters. In docstrings, inline
code must use double backticks so it renders correctly on the website. The
linter does not enforce this, so it must be done manually. Only apply these
rules to the docstrings and comments you add or change. Leave those outside the
scope of your change untouched.

The specs make heavy use of SSZ types. Functions that operate on chain data
should accept and return SSZ types, since the chain itself is stored entirely as
SSZ types. Objects that are not part of the consensus data have no such
requirement and may use ordinary Python types and dataclasses instead.

Asserts signal an impossible situation or something that is not allowed.
Implementations are expected to handle these cases with proper error handling.
Do not use assert messages.

## Presets and configs tables

Values under `## Presets` and `## Configs` use a `Name | Mainnet | Minimal`
table. The Minimal column uses the reserved token *same* when it matches
Mainnet. Write an explicit expression only when Minimal differs.

Annotate self-contained arithmetic with `(= N)` so the decimal is obvious, as in
`Uint64(2**6)` (= 64). Do not annotate expressions that name other values: the
result can differ across presets, and the compiler evaluates the formula.

```markdown
| Name                      | Mainnet               | Minimal              |
| ------------------------- | --------------------- | -------------------- |
| `MAX_COMMITTEES_PER_SLOT` | `Uint64(2**6)` (= 64) | `Uint64(2**2)` (= 4) |
| `HYSTERESIS_QUOTIENT`     | `Uint64(4)`           | *same*               |
| `UPDATE_TIMEOUT`          | `Slot(SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD)` | *same* |
```

Constants keep the two-column `Name | Value` form.

## Aliases, types, and containers

The heading is how the compiler classifies a class. Do not put an item under the
wrong section and expect the compiler to guess from its base class.

- **`## Aliases`** — named scalar or fixed-byte wrappers with no `LIMIT`,
  `LENGTH`, or fields. They are emitted before constants so table values can use
  them (`Slot(0)`, `Gwei(32 * 10**9)`).
- **`## Types`** — collections and other SSZ types whose bound or element type
  needs an alias, constant, or preset.
- **`## Containers`** — SSZ containers (and progressive containers).
- **`## Dataclasses`** / **`## Exceptions`** — optional; leftover helper classes
  are classified as dataclasses or exceptions from their definition.

```python
class Slot(Uint64):
    """A slot number."""

class Blob(ByteVector):
    LENGTH = BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB

class BeaconBlock(Container):
    slot: Slot
    parent_root: Root
    state_root: Root
    body: BeaconBlockBody
```

Protocol methods are free functions annotated `self: ExecutionEngine`. Function
names must be unique across a spec; if two protocols would share a name, prefix
it (`execution_engine__notify_new_payload`, `proof_engine__notify_new_payload`).
The compiler emits a `Protocol` class whose methods are those functions.
Test-only stubs such as `NoopExecutionEngine` live in the test helpers, not in
the spec markdown.

## Documenting changes

Changes in functionality between upgrades must be properly documented. Only
document changes made directly to an item, not changes that ripple in from its
dependencies. For example, if `foo()` calls `bar()` and `bar()` changes, `foo()`
should not annotate that `bar()` changed.

### Section prefixes

When an item such as a container or function has its own section, prefix the
section name with "New" or "Modified" accordingly. Phase0 specifications do not
use "New" prefixes, since everything there is considered new.

### Annotations

Annotations such as `# [New in Deneb]` and `# [Modified in Deneb]` indicate that
a line or block of code has changed, where the name is the upgrade that
introduced the change. If a change is associated with a particular EIP, the
comment must include its number, as in `# [New in Deneb:EIP4844]`. For multiple
EIPs, list them like `# [New in Deneb:EIP4844:EIP4788]`. These must be
standalone comments on their own line. Only "New" and "Modified" are allowed
keywords. `# [Removed in Deneb]` is not allowed. Removed code within functions
is not typically documented, but removed structure fields or function parameters
are, as shown below:

```python
# [Modified in Deneb]
# Removed `parameter`
```

If a function is refactored so heavily that annotations within the function body
would be impractical, omit them and add a note instead.

### Notes

Notes are paragraphs placed above a code block to give the reader insight that
comments cannot. A note should not simply restate how the item now behaves,
since that is clear from reading the item itself. Use a note only to call out a
subtle change the reader might otherwise miss.

### Deprecations

If an existing spec item is no longer needed in a newer spec, add its name to
that fork's `removed.md` under the matching heading (`Functions`, `Containers`,
`Constants`, `Presets`, `Aliases`, `Types`, `Dataclasses`, or `Exceptions`).
Define a removal only in the spec where the item is first dropped. Later specs
inherit it automatically.

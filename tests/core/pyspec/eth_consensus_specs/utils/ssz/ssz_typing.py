"""Thin shim over the ``ssz`` package for compatibility with existing callers.

The SSZ type system lives in the sibling ``ssz-specs`` project. This module
re-exports its public API under the historical name used throughout the
codebase, so that test helpers and tooling that import from
``eth_consensus_specs.utils.ssz.ssz_typing`` keep working during the
transition off ``remerkleable``.
"""

# ruff: noqa: F401

from ssz import (
    bit,
    Bitlist,
    Bitvector,
    boolean,
    byte,
    ByteList,
    Bytes1,
    Bytes4,
    Bytes8,
    Bytes20,
    Bytes31,
    Bytes32,
    Bytes48,
    Bytes96,
    ByteVector,
    Container,
    List,
    Path,
    SszObject,
    uint8,
    uint16,
    uint32,
    uint64,
    uint128,
    uint256,
    uintN,
    Vector,
)

# Historical alias: remerkleable used "View" as the base class name.
View = SszObject
uint = uintN

# `Path` is provided by remerkleable for gindex/proof machinery. Our ssz
# package does not yet implement it. Callers that need generalized-index or
# proof helpers (altair light client) should import the missing bits from a
# dedicated module once implemented. For now, reference ``Path`` raises.


# BasicView was an internal remerkleable name. Preserved as an alias for any
# external caller still referencing it.
BasicView = SszObject


# --- Stubs for SSZ features not yet implemented in the ssz package. ---
# These allow `from ssz_typing import ...` to succeed even for types we
# haven't ported yet. Any actual use will raise NotImplementedError.


def _stub_factory(name: str, *, allow_call: bool = False):
    """Lazy stub for SSZ features not yet ported to the ``ssz`` package.

    Inherits from SszObject so it passes type-annotation checks on Container
    fields. Subscript (``Foo[T]``) and factory-call (``Foo(args=...)``) return
    a new subclass (so class-level declarations succeed at import time).
    Actual instantiation of a concrete stub value raises NotImplementedError.
    """

    class _Stub(SszObject):
        FIXED_SIZE = None
        _is_stub_base = True

        def __class_getitem__(cls, item):
            return cls

        def __init__(self, *args, **kwargs):
            if getattr(type(self), "_is_stub_base", False):
                raise NotImplementedError(
                    f"{name} has not been ported to the ssz package yet"
                )
            raise NotImplementedError(
                f"{name} has not been ported to the ssz package yet"
            )

    _Stub.__name__ = name
    _Stub.__qualname__ = name

    if allow_call:
        # Support ``ProgressiveContainer(active_fields=[...])`` factory-call
        # pattern used as a class base: returns a subclass so ``class X(Foo(...))``
        # succeeds at import time.
        def _call_factory(*args, **kwargs):
            sub = type(name, (_Stub,), {"_is_stub_base": False})
            return sub

        return _call_factory

    return _Stub


Union = _stub_factory("Union")
CompatibleUnion = _stub_factory("CompatibleUnion", allow_call=True)
ProgressiveList = _stub_factory("ProgressiveList")
ProgressiveBitlist = _stub_factory("ProgressiveBitlist")
ProgressiveContainer = _stub_factory("ProgressiveContainer", allow_call=True)

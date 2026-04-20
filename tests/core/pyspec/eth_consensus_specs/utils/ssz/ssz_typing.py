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
    SszObject,
    uint8,
    uint16,
    uint32,
    uint64,
    uint128,
    uint256,
    Vector,
)

# ``uintN`` is the abstract base in the ssz package but is not part of its
# public surface; the shim re-exports it here for the historical ``uint``
# alias remerkleable exposed.
from ssz.basic import uintN  # noqa: E402

# Historical alias: remerkleable used "View" as the base class name.
View = SszObject
uint = uintN

# BasicView was an internal remerkleable name. Preserved as an alias for any
# external caller still referencing it.
BasicView = SszObject


# --- Stubs for SSZ features not yet implemented in the ssz package. ---
# These allow `from ssz_typing import ...` to succeed even for types we
# haven't ported yet. Any actual use will raise NotImplementedError.


def _stub_factory(name: str, *, allow_call: bool = False):
    """Lazy stub for SSZ features not yet ported to the ``ssz`` package.

    Inherits from SszObject so it passes type-annotation and ``issubclass`` /
    ``|``-union checks on Container fields. Subscript (``Foo[T]``) returns
    the class itself; when ``allow_call`` is set, ``Foo(kwargs=...)`` also
    returns a fresh subclass (so ``class X(Foo(active_fields=[...]))``
    succeeds at import time). Actual instantiation of a concrete stub value
    always raises NotImplementedError.
    """

    class _StubMeta(type):
        def __call__(cls, *args, **kwargs):
            if allow_call and cls is _Stub:
                # Factory-call pattern: produce a subclass usable as a base.
                return type(name, (cls,), {"_is_stub_base": False})
            raise NotImplementedError(
                f"{name} has not been ported to the ssz package yet"
            )

    class _Stub(SszObject, metaclass=_StubMeta):
        FIXED_SIZE = None
        _is_stub_base = True

        def __class_getitem__(cls, item):
            return cls

    _Stub.__name__ = name
    _Stub.__qualname__ = name
    return _Stub


Union = _stub_factory("Union")
CompatibleUnion = _stub_factory("CompatibleUnion", allow_call=True)
ProgressiveList = _stub_factory("ProgressiveList")
ProgressiveBitlist = _stub_factory("ProgressiveBitlist")
ProgressiveContainer = _stub_factory("ProgressiveContainer", allow_call=True)

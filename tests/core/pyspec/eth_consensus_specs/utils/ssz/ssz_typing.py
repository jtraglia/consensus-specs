# ruff: noqa: F401
"""
The SSZ type system used by the executable specifications.

Every type here comes from ``eth-ssz-specs`` (the ``ssz`` package), under the
library's own names.

This module adds two things. The fixed-width byte arrays the consensus specs
need, since the library ships no application-specific widths. And a container
that accepts a plain sequence for a collection field, so a spec can write out
the contents of a list without naming its type twice.
"""

from typing import Any, TYPE_CHECKING

from pydantic import model_validator
from ssz.ssz_base import SSZCollection
from ssz.uint import BaseUint as Uint

from ssz import (
    active_fields,
    BitList,
    BitVector,
    Boolean,
    Byte,
    ByteList,
    ByteVector,
    CompatibleUnion,
    Container as _LibContainer,
    List,
    ProgressiveBitList,
    ProgressiveContainer as _LibProgressiveContainer,
    ProgressiveList,
    SSZType,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Uint128,
    Uint256,
    Vector,
)

View = SSZType
"""The library's name for what the specs' test tooling calls a view."""

BasicView = SSZType
"""Likewise, for the shapes that hold a single value rather than a collection."""


class Container(_LibContainer):
    """
    Let a collection field be given its contents directly.

    The library validates strictly, so a field declared as a ``Validators`` is
    given a ``Validators`` and nothing else. Written out longhand that means
    naming the type twice, once in the field declaration and again at every
    site that fills it:

        state.randao_mixes = RandaoMixes(data=[block_hash] * EPOCHS_PER_HISTORICAL_VECTOR)

    The type is not in doubt at that call site -- the field declaration already
    fixed it. So a plain sequence is converted to the declared type on the way
    in, and the spec reads as it did before:

        state.randao_mixes = [block_hash] * EPOCHS_PER_HISTORICAL_VECTOR

    Only the wrapping is inferred. The declared bound is still checked, so a
    sequence of the wrong length is still an error, and the resulting value is
    the same one the longhand builds, with the same hash tree root.
    """

    @classmethod
    def _as_declared(cls, name: str, value: Any) -> Any:
        """The value a field should hold, wrapping a plain sequence in its own type."""
        field = cls.model_fields.get(name)
        if field is None:
            return value
        annotation = field.annotation
        if not isinstance(annotation, type) or not issubclass(annotation, SSZCollection):
            return value
        if isinstance(value, annotation) or not isinstance(value, (list, tuple, bytes, bytearray)):
            return value
        return annotation(data=value)

    @model_validator(mode="before")
    @classmethod
    def _wrap_plain_sequences(cls, data: Any) -> Any:
        """Give each collection field its declared type before validation runs."""
        if not isinstance(data, dict):
            return data
        wrapped = None
        for name, value in data.items():
            settled = cls._as_declared(name, value)
            if settled is not value:
                # Copied rather than mutated: the caller's dictionary is theirs.
                if wrapped is None:
                    wrapped = dict(data)
                wrapped[name] = settled
        return wrapped if wrapped is not None else data

    # Hidden from type checkers for the reason the library gives on its own
    # __setattr__: a visible one typed to accept Any would exempt every field
    # assignment from being checked against its declared type.
    if not TYPE_CHECKING:

        def __setattr__(self, name: str, value: Any) -> None:
            """Assignment reads a plain sequence the same way construction does."""
            super().__setattr__(name, type(self)._as_declared(name, value))


# The progressive layout is left as the library declares it. Every subclass of it
# must state its own ACTIVE_FIELDS, so an intermediate class cannot sit in between.
ProgressiveContainer = _LibProgressiveContainer


class BytesN(ByteVector):
    """
    Base for the specs' fixed-width byte arrays.

    These compare by content, across every name declared here.

    The library relates two byte arrays only by inheritance, so two names for
    the same width are siblings and refuse each other. That reading is right
    for a library, where a ``Root`` and a ``Hash32`` are different ideas. It is
    wrong for the specs, where the same 32 bytes are called a ``Root`` in one
    container, a ``Bytes32`` in another, and are compared across the two
    constantly -- an ancestor lookup weighs a block root against a stored
    ``Bytes32``, and both spell the same value.

    Content is therefore the whole of it, and the hash agrees, so a value found
    under one name is found under the other.
    """

    def __eq__(self, other: object) -> bool:
        """Equal when the bytes are equal, whatever each side is called."""
        if isinstance(other, (ByteVector, bytes, bytearray)):
            return bytes(self) == bytes(other)
        return super().__eq__(other)

    def __ne__(self, other: object) -> bool:
        """The negation of the above, so both directions agree."""
        if isinstance(other, (ByteVector, bytes, bytearray)):
            return bytes(self) != bytes(other)
        return super().__ne__(other)

    def __hash__(self) -> int:
        """Hash by content, so equal byte arrays of any width hash alike."""
        return hash(bytes(self))


class Bytes1(BytesN):
    LENGTH = 1


class Bytes4(BytesN):
    LENGTH = 4


class Bytes8(BytesN):
    LENGTH = 8


class Bytes20(BytesN):
    LENGTH = 20


class Bytes31(BytesN):
    LENGTH = 31


class Bytes32(BytesN):
    LENGTH = 32


class Bytes48(BytesN):
    LENGTH = 48


class Bytes96(BytesN):
    LENGTH = 96

# ruff: noqa: F401
"""
The SSZ type system used by the executable specifications.

Every type here comes from ``eth-ssz-specs`` (the ``ssz`` package). This module
only does two things on top of it:

1. Re-exports the library's collection bases under the names the SSZ
   specification itself uses (``Bitlist``, ``Bitvector``, ``ByteList``,
   ``ByteVector``).
2. Declares the fixed-width byte arrays the consensus specs need. The library
   ships no application-specific byte-array classes, so each application
   declares the widths it uses.
"""

from pydantic import model_validator
from ssz.uint import BaseUint as Uint

import ssz
from ssz import (
    BaseBytes as ByteVector,
    Boolean,
    Byte,
    CompatibleUnion,
    Container,
    ProgressiveContainer,
    SSZType,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Uint128,
    Uint256,
)

# TODO: drop this once eth-ssz-specs coerces a bare sequence itself.
# A collection keeps its contents in a `data` field, so a plain list handed to
# a collection-typed field is rejected. remerkleable accepted one, and the
# specs and their tests pass sequences around constantly, so the bare form is
# wrapped back up here.


class _AcceptsBareSequence:
    @model_validator(mode="before")
    @classmethod
    def _wrap_bare_sequence(cls, value: object) -> object:
        if isinstance(value, (list, tuple, bytes, bytearray)):
            return {"data": value}
        return value


class List[T: SSZType](_AcceptsBareSequence, ssz.List[T]):
    pass


class Vector[T: SSZType](_AcceptsBareSequence, ssz.Vector[T]):
    pass


class ProgressiveList[T: SSZType](_AcceptsBareSequence, ssz.ProgressiveList[T]):
    pass


class Bitlist(_AcceptsBareSequence, ssz.BaseBitlist):
    pass


class Bitvector(_AcceptsBareSequence, ssz.BaseBitvector):
    pass


class ProgressiveBitlist(_AcceptsBareSequence, ssz.ProgressiveBitlist):
    pass


class ByteList(_AcceptsBareSequence, ssz.BaseByteList):
    pass


class Bytes1(ByteVector):
    LENGTH = 1


class Bytes4(ByteVector):
    LENGTH = 4


class Bytes8(ByteVector):
    LENGTH = 8


class Bytes20(ByteVector):
    LENGTH = 20


class Bytes31(ByteVector):
    LENGTH = 31


class Bytes32(ByteVector):
    LENGTH = 32


class Bytes48(ByteVector):
    LENGTH = 48


class Bytes96(ByteVector):
    LENGTH = 96

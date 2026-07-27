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

from ssz.uint import BaseUint as Uint

from ssz import (
    BaseBitlist as Bitlist,
    BaseBitvector as Bitvector,
    BaseByteList as ByteList,
    BaseBytes as ByteVector,
    Boolean,
    Byte,
    CompatibleUnion,
    Container,
    List,
    ProgressiveBitlist,
    ProgressiveContainer,
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

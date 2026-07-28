# ruff: noqa: F401
"""
The SSZ type system used by the executable specifications.

Every type here comes from ``eth-ssz-specs`` (the ``ssz`` package), under the
library's own names.

The one thing this module adds is the fixed-width byte arrays the consensus
specs need. The library ships no application-specific byte-array classes, so
each application declares the widths it uses.
"""

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
    Container,
    List,
    ProgressiveBitList,
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

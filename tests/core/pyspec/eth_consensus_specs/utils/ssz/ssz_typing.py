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


class BytesN(ByteVector):
    """
    Base for the specs' fixed-width byte arrays.

    The widths below are the only thing this adds. The library hashes a byte
    array by content, matching how it compares them, so a ``Root`` and the
    ``Bytes32`` a hash tree root comes back as land in the same bucket.
    """


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

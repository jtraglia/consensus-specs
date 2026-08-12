"""Prelude imported by every compiled spec module.

Generated modules do ``from eth_consensus_specs.runtime import *``. Keep this
the union of names the specs need so the compiler has no import tables.
"""

from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import (
    Any,
    DefaultDict,
    Dict,
    Final,
    NamedTuple,
    NewType,
    Optional,
    Protocol,
    Set,
    Tuple,
    TypeAlias,
    TypeVar,
    Union as PyUnion,
)

from frozendict import frozendict
from ssz.bitfields import BitList, BitVector, ProgressiveBitList
from ssz.boolean import Boolean
from ssz.byte_arrays import ByteList, ByteVector
from ssz.collections import List, ProgressiveList, Vector
from ssz.container import active_fields, Container, ProgressiveContainer
from ssz.ssz_base import SSZType
from ssz.uint import Byte, Uint8, Uint32, Uint64, Uint256

from eth_consensus_specs.test.helpers.merkle import build_proof, get_generalized_index
from eth_consensus_specs.utils import bls
from eth_consensus_specs.utils.hash_function import hash
from eth_consensus_specs.utils.ssz.bytes import (
    Bytes1,
    Bytes4,
    Bytes8,
    Bytes20,
    Bytes31,
    Bytes32,
    Bytes48,
    Bytes96,
)
from eth_consensus_specs.utils.ssz.ssz_impl import (
    copy,
    hash_tree_root,
    ssz_deserialize,
    ssz_serialize,
    uint_to_bytes,
)

try:
    from eth_consensus_specs.utils import kzg
except ImportError:
    kzg = None  # type: ignore[misc, assignment]

SSZObject = TypeVar("SSZObject", bound=SSZType)
SSZVariableName = str
GeneralizedIndex = int
ExecutionState = Any

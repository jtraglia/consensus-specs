from pysetup.constants import PHASE0

from .base import BaseSpecBuilder


class Phase0SpecBuilder(BaseSpecBuilder):
    fork: str = PHASE0

    @classmethod
    def classes(cls) -> str:
        return """
class GossipIgnore(Exception):
    pass


class GossipReject(Exception):
    pass
"""

    @classmethod
    def imports(cls, preset_name: str) -> str:
        return """from collections import defaultdict
from dataclasses import (
    dataclass,
    field,
)
from hashlib import sha256 as sha256_hash
from typing import (
    Any, Callable, Dict, DefaultDict, Set, Sequence, Tuple, Optional, TypeAlias, TypeVar, NamedTuple, Final
)

from ssz.bitfields import BitList, BitVector
from ssz.boolean import Boolean
from ssz.collections import List, ProgressiveList, Vector
from ssz.container import Container
from ssz.ssz_base import SSZType
from ssz.uint import BaseUint as Uint, Byte, Uint8, Uint16, Uint32, Uint64, Uint256
from eth_consensus_specs.utils.ssz.bytes import (
    Bytes1, Bytes4, Bytes20, Bytes32, Bytes48, Bytes96)
from eth_consensus_specs.utils.ssz.ssz_impl import ssz_deserialize, ssz_serialize
from eth_consensus_specs.utils import bls
"""

    @classmethod
    def preparations(cls) -> str:
        return """
SSZObject = TypeVar('SSZObject', bound=SSZType)
"""

    @classmethod
    def sundry_functions(cls) -> str:
        return '''
def get_eth1_data(block: Eth1Block) -> Eth1Data:
    """
    A stub function return mocking Eth1Data.
    """
    return Eth1Data(
        deposit_root=block.deposit_root,
        deposit_count=block.deposit_count,
        block_hash=Hash32(hash_tree_root(block)))'''

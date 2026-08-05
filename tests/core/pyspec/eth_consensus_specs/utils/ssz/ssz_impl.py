from ssz.merkleization import hash_tree_root as ssz_hash_tree_root
from ssz.proofs import build_proof
from ssz.ssz_base import SSZModel

from eth_consensus_specs.utils.ssz.ssz_typing import Bytes32, SSZType, Uint
from ssz import get_generalized_index

# The generated specifications reach the library through this module. Importing
# `ssz` directly from one of them resolves against the repository's own
# top-level `ssz` directory instead of the installed package.
__all__ = [
    "build_proof",
    "copy",
    "deserialize",
    "get_generalized_index",
    "hash_tree_root",
    "serialize",
    "ssz_deserialize",
    "ssz_serialize",
    "uint_to_bytes",
]


def ssz_serialize(obj: SSZType) -> bytes:
    return obj.encode_bytes()


def serialize(obj: SSZType) -> bytes:
    return ssz_serialize(obj)


def ssz_deserialize(typ: type[SSZType], data: bytes) -> SSZType:
    return typ.decode_bytes(data)


def deserialize(typ: type[SSZType], data: bytes) -> SSZType:
    return ssz_deserialize(typ, data)


def hash_tree_root(obj: SSZType) -> Bytes32:
    return Bytes32(ssz_hash_tree_root(obj))


def uint_to_bytes(n: Uint) -> bytes:
    return serialize(n)


# Helper method for typing copies, and avoiding a example_input.copy() method call, instead of copy(example_input)
def copy[V: SSZType](obj: V) -> V:
    # Containers and collections are mutable models, so they need a deep copy.
    # Uints, booleans, and byte vectors are immutable and can be shared.
    if isinstance(obj, SSZModel):
        return obj.model_copy(deep=True)
    return obj

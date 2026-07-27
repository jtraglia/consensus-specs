from ssz.merkleization import hash_tree_root as ssz_hash_tree_root
from ssz.ssz_base import SSZModel

from eth_consensus_specs.utils.ssz.ssz_typing import Bytes32, SSZType, Uint


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

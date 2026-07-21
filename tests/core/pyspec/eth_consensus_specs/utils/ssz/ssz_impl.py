from ssz.merkleization import hash_tree_root as _hash_tree_root
from ssz.ssz_base import SSZModel, SSZType

from eth_consensus_specs.utils.hash_function import Bytes32


def hash_tree_root(obj: SSZType) -> Bytes32:
    return bytes.__new__(Bytes32, _hash_tree_root(obj))


def ssz_serialize(obj: SSZType) -> bytes:
    return obj.encode_bytes()


def serialize(obj: SSZType) -> bytes:
    return ssz_serialize(obj)


def ssz_deserialize[V: SSZType](typ: type[V], data: bytes) -> V:
    return typ.decode_bytes(data)


def deserialize[V: SSZType](typ: type[V], data: bytes) -> V:
    return ssz_deserialize(typ, data)


def uint_to_bytes(n: SSZType) -> bytes:
    return serialize(n)


def copy[V: SSZType](obj: V) -> V:
    # Models copy deeply; leaf values (uints, bytes, booleans) are immutable.
    if isinstance(obj, SSZModel):
        return obj.copy()
    return obj

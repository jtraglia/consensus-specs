from typing import TypeVar

from ssz.merkleization import hash_tree_root as hash_tree_root
from ssz.ssz_base import SSZModel, SSZType

V = TypeVar("V", bound=SSZType)


def ssz_serialize(obj: SSZType) -> bytes:
    return obj.encode_bytes()


def serialize(obj: SSZType) -> bytes:
    return ssz_serialize(obj)


def ssz_deserialize(typ: type[V], data: bytes) -> V:
    return typ.decode_bytes(data)


def deserialize(typ: type[V], data: bytes) -> V:
    return ssz_deserialize(typ, data)


def uint_to_bytes(n: SSZType) -> bytes:
    return serialize(n)


def copy(obj: V) -> V:
    # Models copy deeply; leaf values (uints, bytes, booleans) are immutable.
    if isinstance(obj, SSZModel):
        return obj.copy()
    return obj

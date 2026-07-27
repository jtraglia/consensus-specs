from ssz.merkleization import hash_tree_root as ssz_hash_tree_root
from ssz.ssz_base import SSZCollection, SSZModel

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
    # Only containers and collections are mutable, so only they need rebuilding.
    # Uints, booleans, and byte vectors are immutable and are shared instead of
    # copied, which is what keeps this cheap on a state full of roots.
    #
    # The source is already valid, so the rebuild skips validation.
    if isinstance(obj, SSZCollection):
        data = obj.data
        # A byte list stores plain bytes, which are immutable already.
        if not isinstance(data, bytes):
            data = [copy(element) for element in data]
        return type(obj).model_construct(data=data)
    if isinstance(obj, SSZModel):
        return type(obj).model_construct(
            **{name: copy(getattr(obj, name)) for name in type(obj).model_fields}
        )
    return obj

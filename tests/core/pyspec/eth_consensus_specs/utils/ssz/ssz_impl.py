from typing import TypeVar

from .ssz_typing import Bytes32, View, uint


def ssz_serialize(obj: View) -> bytes:
    return obj.encode_bytes()


def serialize(obj: View) -> bytes:
    return ssz_serialize(obj)


def ssz_deserialize(typ: type[View], data: bytes) -> View:
    return typ.decode_bytes(data)


def deserialize(typ: type[View], data: bytes) -> View:
    return ssz_deserialize(typ, data)


def hash_tree_root(obj: View) -> Bytes32:
    return obj.hash_tree_root()


def uint_to_bytes(n: uint) -> bytes:
    if isinstance(n, uint):
        return serialize(n)
    # Handle plain int from arithmetic (infer byte length from value)
    byte_length = max(1, (n.bit_length() + 7) // 8)
    # Round up to valid SSZ uint sizes
    for size in (1, 2, 4, 8, 16, 32):
        if byte_length <= size:
            byte_length = size
            break
    return n.to_bytes(byte_length, "little")


V = TypeVar("V", bound=View)


# Helper method for typing copies, and avoiding a example_input.copy() method call, instead of copy(example_input)
def copy(obj: V) -> V:
    return obj.copy()

from typing import TypeVar

from ssz.bitfields import BaseBitlist, BaseBitvector
from ssz.byte_arrays import BaseByteList
from ssz.collections import List as _List, Vector as _Vector
from ssz.merkleization import hash_tree_root as _hash_tree_root

from eth_consensus_specs.utils.ssz.ssz_typing import Bytes32, View

_COLLECTION_BASES = (_List, _Vector, BaseBitlist, BaseBitvector, BaseByteList)


def ssz_serialize(obj: View) -> bytes:
    return obj.encode_bytes()


def serialize(obj: View) -> bytes:
    return ssz_serialize(obj)


def ssz_deserialize(typ: type[View], data: bytes) -> View:
    return typ.decode_bytes(data)


def deserialize(typ: type[View], data: bytes) -> View:
    return ssz_deserialize(typ, data)


def hash_tree_root(obj: View) -> Bytes32:
    # Wrap in the local Bytes32 so the result compares by value against raw bytes.
    return Bytes32(_hash_tree_root(obj))


def uint_to_bytes(n: View) -> bytes:
    return serialize(n)


V = TypeVar("V", bound=View)


def replace(obj: V, **changes: object) -> V:
    """Return a copy of an SSZ container with the given fields replaced.

    Each replacement value is coerced into its field's declared SSZ type, so raw
    lists/ints/bytes may be passed directly. This is the functional counterpart to
    in-place field assignment (`obj.field = value`).
    """
    fields = type(obj).model_fields
    coerced: dict[str, object] = {}
    for name, value in changes.items():
        annotation = fields[name].annotation
        if isinstance(value, annotation):
            coerced[name] = value
        elif issubclass(annotation, _COLLECTION_BASES):
            coerced[name] = annotation(data=value)
        else:
            coerced[name] = annotation(value)
    return obj.model_copy(update=coerced)


def copy(obj: V) -> V:
    # SSZ values are immutable. Containers and collections are Pydantic models and
    # expose model_copy; leaf values (uints, bytes, booleans) are returned as-is.
    model_copy = getattr(obj, "model_copy", None)
    if model_copy is not None:
        return model_copy(deep=True)
    return obj

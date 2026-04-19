"""Thin shim over the ``ssz`` package for compatibility with existing callers."""

from copy import deepcopy
from typing import TypeVar

from ssz import (
    deserialize as _deserialize,
    hash_tree_root as _hash_tree_root,
    serialize as _serialize,
    SszObject,
    uintN,
)

T = TypeVar("T", bound=SszObject)


def ssz_serialize(obj: SszObject) -> bytes:
    return _serialize(obj)


def serialize(obj: SszObject) -> bytes:
    return _serialize(obj)


def ssz_deserialize(typ: type[T], data: bytes) -> T:
    return _deserialize(typ, data)


def deserialize(typ: type[T], data: bytes) -> T:
    return _deserialize(typ, data)


def hash_tree_root(obj: SszObject) -> bytes:
    return _hash_tree_root(obj)


def uint_to_bytes(n: uintN) -> bytes:
    return _serialize(n)


def copy(obj: T) -> T:
    return deepcopy(obj)

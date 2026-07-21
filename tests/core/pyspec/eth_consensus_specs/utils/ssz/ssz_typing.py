
"""
SSZ type layer for the consensus specs, built on the `eth-ssz-specs` package.

The upstream `ssz` package provides immutable, Pydantic-backed SSZ types. This
module adapts them to the ergonomics the specs and tests rely on:

- Every leaf type (uints, booleans, byte vectors) supports zero-argument
  construction that yields its SSZ default (zero) value.
- Containers fill any unspecified field with its SSZ default value.
- The legacy `List[T, N]` / `Vector[T, N]` / `Bitlist[N]` subscription syntax is
  supported alongside the named-subclass form (`class Foo(List[T]): LIMIT = N`).
- Values are mutable: tests assign container fields and collection elements in
  place, while the spec itself only uses the library's immutable/functional API.
"""

from typing import Any

from pydantic import ConfigDict, model_validator
from ssz.bitfields import BaseBitlist, BaseBitvector
from ssz.boolean import Boolean as _Boolean
from ssz.byte_arrays import BaseByteList, BaseBytes
from ssz.merkleization import hash_tree_root as _lib_hash_tree_root
from ssz.ssz_base import SSZType
from ssz.uint import BaseUint

from ssz import (
    Container as _Container,
    List as _List,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Uint128,
    Uint256,
    Vector as _Vector,
)

# `View` is remerkleable's root SSZ type. The upstream equivalent is `SSZType`.
View = SSZType
BasicView = SSZType


class _MutableData:
    """Mixin: in-place element mutation for collections.

    The upstream types are frozen and the spec uses them functionally. Tests mutate
    values in place (remerkleable ergonomics), so the shim re-enables assignment and
    provides element-level mutation. Every mutation revalidates the whole collection,
    so limits and element coercion behave exactly as they do at construction.

    Pydantic reads `model_config` only from model bases, not plain mixins, so each
    collection class using this mixin must set `frozen=False` in its own body.
    """

    def __setitem__(self, index: Any, value: Any) -> None:
        elements = list(self.data)
        elements[index] = value
        self.data = type(self)(data=elements).data

    def append(self, value: Any) -> None:
        self.data = type(self)(data=[*self.data, value]).data

    def pop(self) -> Any:
        *rest, last = self.data
        self.data = type(self)(data=rest).data
        return last


#
# Boolean
#


class Boolean(_Boolean):
    """Boolean that defaults to False and compares against plain bools/ints."""

    def __new__(cls, value: Any = False) -> Any:
        return super().__new__(cls, value)

    __eq__ = int.__eq__
    __ne__ = int.__ne__
    __hash__ = int.__hash__


#
# Byte vectors
#


class _Bytes(BaseBytes):
    """Fixed-size byte vector that defaults to all-zero bytes when empty.

    Equality and hashing follow plain `bytes` semantics (value-based, type-agnostic)
    to match remerkleable, so typed byte values compare equal to raw `bytes`.
    """

    def __new__(cls, value: Any = b"") -> Any:
        if value is None or (isinstance(value, (bytes, bytearray, str)) and len(value) == 0):
            value = b"\x00" * cls.LENGTH
        return super().__new__(cls, value)

    __eq__ = bytes.__eq__
    __ne__ = bytes.__ne__
    __hash__ = bytes.__hash__


class Bytes1(_Bytes):
    LENGTH = 1


class Bytes4(_Bytes):
    LENGTH = 4


class Bytes8(_Bytes):
    LENGTH = 8


class Bytes20(_Bytes):
    LENGTH = 20


class Bytes31(_Bytes):
    LENGTH = 31


class Bytes32(_Bytes):
    LENGTH = 32


class Bytes48(_Bytes):
    LENGTH = 48


class Bytes96(_Bytes):
    LENGTH = 96


_legacy_subscriptions: dict[Any, type] = {}
"""Cache of classes synthesized by legacy `T[N]` subscriptions.

Subscribing twice must return the same class, so `isinstance` checks hold between
values built in tests and fields annotated in the compiled specs."""


class ByteVector(_Bytes):
    """Legacy `ByteVector[N]` subscription that synthesizes a fixed byte vector."""

    def __class_getitem__(cls, length: Any) -> type["_Bytes"]:
        key = (cls, int(length))
        if key not in _legacy_subscriptions:
            name = f"ByteVector{int(length)}"
            _legacy_subscriptions[key] = type(name, (_Bytes,), {"LENGTH": int(length)})
        return _legacy_subscriptions[key]


#
# Byte list
#


class ByteList(_MutableData, BaseByteList):
    """Variable-length byte array. Use `class T(ByteList): LIMIT = N` or `ByteList[N]`."""

    model_config = ConfigDict(frozen=False)

    def __class_getitem__(cls, limit: Any) -> type["ByteList"]:
        key = (cls, int(limit))
        if key not in _legacy_subscriptions:
            name = f"ByteList{int(limit)}"
            _legacy_subscriptions[key] = type(name, (cls,), {"LIMIT": Uint64(limit)})
        return _legacy_subscriptions[key]


#
# Collections
#


class List(_MutableData, _List):
    """SSZ list. Use `class T(List[E]): LIMIT = N` or the legacy `List[E, N]`."""

    model_config = ConfigDict(frozen=False)

    def __class_getitem__(cls, params: Any) -> Any:
        if isinstance(params, tuple):
            element_type, limit = params
            key = (cls, element_type, int(limit))
            if key not in _legacy_subscriptions:
                base = super().__class_getitem__(element_type)
                name = f"List_{getattr(element_type, '__name__', element_type)}_{limit}"
                _legacy_subscriptions[key] = type(name, (base,), {"LIMIT": Uint64(limit)})
            return _legacy_subscriptions[key]
        return super().__class_getitem__(params)


class Vector(_MutableData, _Vector):
    """SSZ vector. Use `class T(Vector[E]): LENGTH = N` or the legacy `Vector[E, N]`."""

    model_config = ConfigDict(frozen=False)

    def __class_getitem__(cls, params: Any) -> Any:
        if isinstance(params, tuple):
            element_type, length = params
            key = (cls, element_type, int(length))
            if key not in _legacy_subscriptions:
                base = super().__class_getitem__(element_type)
                name = f"Vector_{getattr(element_type, '__name__', element_type)}_{length}"
                _legacy_subscriptions[key] = type(name, (base,), {"LENGTH": Uint64(length)})
            return _legacy_subscriptions[key]
        return super().__class_getitem__(params)


#
# Bitfields
#


class Bitlist(_MutableData, BaseBitlist):
    """SSZ bitlist. Use `class T(Bitlist): LIMIT = N` or the legacy `Bitlist[N]`."""

    model_config = ConfigDict(frozen=False)

    def __class_getitem__(cls, limit: Any) -> type["Bitlist"]:
        key = (cls, int(limit))
        if key not in _legacy_subscriptions:
            name = f"Bitlist{int(limit)}"
            _legacy_subscriptions[key] = type(name, (cls,), {"LIMIT": Uint64(limit)})
        return _legacy_subscriptions[key]


class Bitvector(_MutableData, BaseBitvector):
    """SSZ bitvector. Use `class T(Bitvector): LENGTH = N` or the legacy `Bitvector[N]`."""

    model_config = ConfigDict(frozen=False)

    def __class_getitem__(cls, length: Any) -> type["Bitvector"]:
        key = (cls, int(length))
        if key not in _legacy_subscriptions:
            name = f"Bitvector{int(length)}"
            _legacy_subscriptions[key] = type(name, (cls,), {"LENGTH": Uint64(length)})
        return _legacy_subscriptions[key]


#
# Container with SSZ default-filling
#


def default_value(type_: type[SSZType]) -> Any:
    """Return the SSZ default (zero) value for an SSZ type."""
    if isinstance(type_, type) and issubclass(type_, _Container):
        return type_()
    if issubclass(type_, BaseUint):
        return type_(0)
    if issubclass(type_, _Boolean):
        return type_()
    if issubclass(type_, BaseBytes):
        return type_()
    if issubclass(type_, BaseByteList):
        return type_()
    if issubclass(type_, _Vector):
        return type_(data=[default_value(type_.ELEMENT_TYPE)] * int(type_.LENGTH))
    if issubclass(type_, _List):
        return type_()
    if issubclass(type_, BaseBitvector):
        return type_(data=[False] * int(type_.LENGTH))
    if issubclass(type_, BaseBitlist):
        return type_()
    raise TypeError(f"no SSZ default for type {type_!r}")


_COLLECTION_MODEL_BASES = (_List, _Vector, BaseBitlist, BaseBitvector, BaseByteList)


class Container(_Container):
    """SSZ container that fills defaults and coerces raw values into typed fields.

    - Any unspecified field is filled with its SSZ default value.
    - A raw list/tuple/bytes given for a collection field is coerced into that field's
      SSZ collection type, matching remerkleable's implicit coercion.
    - Fields are assignable (the upstream container is frozen); assigned values go
      through the same coercion as construction.
    """

    model_config = ConfigDict(frozen=False)

    @model_validator(mode="before")
    @classmethod
    def _prepare_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        filled = dict(data)
        for name, field in cls.model_fields.items():
            annotation = field.annotation
            if name not in filled:
                filled[name] = default_value(annotation)
                continue
            value = filled[name]
            if (
                isinstance(annotation, type)
                and issubclass(annotation, _COLLECTION_MODEL_BASES)
                and not isinstance(value, annotation)
            ):
                filled[name] = annotation(data=value)
        return filled

    def __setattr__(self, name: str, value: Any) -> None:
        field = type(self).model_fields.get(name)
        if field is not None:
            annotation = field.annotation
            if isinstance(annotation, type) and not isinstance(value, annotation):
                if issubclass(annotation, _COLLECTION_MODEL_BASES):
                    value = annotation(data=value)
                elif issubclass(annotation, View):
                    value = annotation(value)
        super().__setattr__(name, value)


def _hash_tree_root_method(self: Any) -> "Bytes32":
    """Method form of hash_tree_root, kept for remerkleable compatibility."""
    return Bytes32(_lib_hash_tree_root(self))


# Restore the `value.hash_tree_root()` method form used across the specs and tests.
for _ssz_cls in (BaseUint, Boolean, _Bytes, ByteList, List, Vector, Bitlist, Bitvector, Container):
    _ssz_cls.hash_tree_root = _hash_tree_root_method  # type: ignore[attr-defined]


def _copy_method(self: Any) -> Any:
    """Method form of copy. SSZ values are immutable, so this returns an equal copy."""
    return self.model_copy(deep=True)


# Restore the `value.copy()` method form used across the specs and tests.
for _ssz_model_cls in (ByteList, List, Vector, Bitlist, Bitvector, Container):
    _ssz_model_cls.copy = _copy_method  # type: ignore[attr-defined]


#
# Placeholders for SSZ features not present in eth-ssz-specs.
#
# Phase0 does not use unions or progressive types. These names exist only so that
# modules referencing them (the generic SSZ debug helpers and not-yet-migrated forks)
# still import. They are NOT functional implementations.
#

uint = BaseUint


class Path:
    """Placeholder for remerkleable's generalized-index Path (unused by phase0)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass


class Union:
    def __class_getitem__(cls, params: Any) -> Any:
        return cls


class CompatibleUnion:
    def __class_getitem__(cls, params: Any) -> Any:
        return cls


# Progressive collections behave like their non-progressive counterparts for the
# purpose of importing not-yet-migrated forks.
ProgressiveList = List
ProgressiveBitlist = Bitlist


class _ProgressiveContainerMeta(type):
    def __call__(cls, *args: Any, **kwargs: Any) -> Any:
        # `class X(ProgressiveContainer(active_fields=[...]))` uses this as a base factory.
        return Container


class ProgressiveContainer(metaclass=_ProgressiveContainerMeta):
    pass


#
# Lowercase aliases for specs and forks not yet migrated to the new names.
#

boolean = Boolean
bit = Boolean
byte = Uint8
uint8 = Uint8
uint16 = Uint16
uint32 = Uint32
uint64 = Uint64
uint128 = Uint128
uint256 = Uint256

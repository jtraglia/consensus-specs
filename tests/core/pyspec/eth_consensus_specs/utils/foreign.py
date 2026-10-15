"""
Calls into specification functions compiled from another language.

The compiler builds each fork's definitions into a shared library next to its
generated module, ``build/specs/<fork>/<preset>.<language>.so``. A call sends
frames, each a four-byte little-endian length and that many bytes: the configs
the library reads, then every argument. The reply starts with a status byte: 0
carries one frame per result, 1 a failure, and 2 an unknown function. A failure
reading ``Kind: message`` raises the exception class ``Kind`` of the calling
specification module, and any other failure raises an ``AssertionError``.

A value of an SSZ type travels as its SSZ encoding, and plain bytes as they are.
Sequences, sets, dicts, tuples, dataclasses and optional values travel as frames
of their parts: a dict as one pair per entry, a tuple nesting from the right as
pairs do, a dataclass as its fields in order, and an optional value as zero or
one frame. A value of any SSZ type travels as its type name and its encoding.

A dataclass edited by a function is updated in place, and a dataclass returned
holding a dataclass argument holds that argument itself, as Python would.

The library calls back through ``HOST`` for what the specification imports,
which is the ``bls`` module, so its backend and switch stay in Python.
"""

import ctypes
from collections.abc import Sequence
from dataclasses import fields, is_dataclass
from functools import cache
from pathlib import Path
from types import NoneType, UnionType
from typing import get_args, get_origin, get_type_hints, Union

from ssz import Boolean, Container, ProgressiveContainer, SSZType, Uint256

from eth_consensus_specs.utils import bls
from eth_consensus_specs.utils.ssz.ssz_impl import ssz_deserialize, ssz_serialize

SPECS = Path(__file__).resolve().parents[5] / "build" / "specs"
CONTAINERS = (Container, ProgressiveContainer)
HOST = ctypes.CFUNCTYPE(
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
)
HOST_FUNCTIONS = {
    "bls.Sign": lambda privkey, message: bytes(
        bls.Sign(int.from_bytes(privkey, "little"), message)
    ),
    "bls.Verify": lambda pubkey, message, signature: bytes(
        [bls.Verify(pubkey, message, signature)]
    ),
    "bls.Aggregate": lambda signatures: bytes(bls.Aggregate(_unframe(signatures))),
    "bls.FastAggregateVerify": lambda pubkeys, message, signature: bytes(
        [bls.FastAggregateVerify(_unframe(pubkeys), message, signature)]
    ),
    "bls.AggregateVerify": lambda pubkeys, messages, signature: bytes(
        [bls.AggregateVerify(_unframe(pubkeys), _unframe(messages), signature)]
    ),
    "bls.KeyValidate": lambda pubkey: bytes([bls.KeyValidate(pubkey)]),
}
_answer = ctypes.create_string_buffer(0)


@HOST
def _host(name, data, size, answer_size):
    global _answer
    try:
        frames = _unframe(ctypes.string_at(data, size))
        payload = b"\x00" + HOST_FUNCTIONS[name.decode()](*frames)
    except Exception as error:
        payload = b"\x01" + f"{type(error).__name__}: {error}".encode()
    _answer = ctypes.create_string_buffer(payload, len(payload))
    answer_size[0] = len(payload)
    return ctypes.addressof(_answer)


class _Library:
    def __init__(self, path: Path) -> None:
        self.handle = ctypes.CDLL(str(path))
        self.handle.spec_call.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
        self.handle.spec_call.restype = ctypes.c_void_p
        self.handle.spec_configs.argtypes = []
        self.handle.spec_configs.restype = ctypes.c_void_p
        self.handle.spec_size.argtypes = [ctypes.c_void_p]
        self.handle.spec_size.restype = ctypes.c_size_t
        self.handle.spec_data.argtypes = [ctypes.c_void_p]
        self.handle.spec_data.restype = ctypes.c_void_p
        self.handle.spec_release.argtypes = [ctypes.c_void_p]
        self.handle.spec_set_host.argtypes = [HOST]
        self.handle.spec_set_host(_host)
        names = self._take(self.handle.spec_configs()).decode()
        self.configs = tuple(names.split(",")) if names else ()

    def _take(self, reply: int) -> bytes:
        try:
            return ctypes.string_at(self.handle.spec_data(reply), self.handle.spec_size(reply))
        finally:
            self.handle.spec_release(reply)

    def call(self, name: str, data: bytes) -> bytes:
        return self._take(self.handle.spec_call(name.encode(), data, len(data)))


@cache
def _library(path: Path) -> _Library:
    return _Library(path)


def _ssz(declared):
    return {bool: Boolean, int: Uint256}.get(declared, declared)


def _optional(declared):
    if get_origin(declared) in (Union, UnionType):
        arguments = [argument for argument in get_args(declared) if argument is not NoneType]
        if len(arguments) == 1:
            return arguments[0]
    return None


def _encode(value, declared) -> bytes:
    origin, arguments = get_origin(declared), get_args(declared)
    if origin in (Sequence, set):
        return _frame([_encode(element, arguments[0]) for element in value])
    if origin is dict:
        pair = tuple[*arguments]
        return _frame([_encode(item, pair) for item in value.items()])
    if is_dataclass(declared):
        hints = get_type_hints(declared)
        return _frame(
            [_encode(getattr(value, field.name), hints[field.name]) for field in fields(declared)]
        )
    if origin is tuple and arguments[1:] == (Ellipsis,):
        return _frame([_encode(element, arguments[0]) for element in value])
    if origin is tuple:
        first, *rest = arguments
        tail, remainder = (rest[0], value[1]) if len(rest) == 1 else (tuple[*rest], value[1:])
        return _frame([_encode(value[0], first), _encode(remainder, tail)])
    if (inner := _optional(declared)) is not None:
        return _frame([] if value is None else [_encode(value, inner)])
    if declared is bytes:
        return bytes(value)
    if declared is SSZType:
        return _frame([type(value).__name__.encode(), ssz_serialize(value)])
    typed = _ssz(declared)
    return ssz_serialize(value if isinstance(value, typed) else typed(value))


def _hashable(value):
    return tuple(_hashable(element) for element in value) if isinstance(value, list) else value


def _decode(declared, data: bytes):
    origin, arguments = get_origin(declared), get_args(declared)
    if origin is Sequence:
        return [_decode(arguments[0], frame) for frame in _unframe(data)]
    if origin is set:
        return {_hashable(_decode(arguments[0], frame)) for frame in _unframe(data)}
    if origin is dict:
        pair = tuple[*arguments]
        return {
            _hashable(key): value
            for key, value in (_decode(pair, frame) for frame in _unframe(data))
        }
    if origin is tuple and arguments[1:] == (Ellipsis,):
        return tuple(_decode(arguments[0], frame) for frame in _unframe(data))
    if is_dataclass(declared):
        hints = get_type_hints(declared)
        frames = _unframe(data)
        return declared(
            **{
                field.name: _decode(hints[field.name], frame)
                for field, frame in zip(fields(declared), frames, strict=True)
            }
        )
    if origin is tuple:
        first, *rest = arguments
        head, remainder = _unframe(data)
        if len(rest) == 1:
            return _decode(first, head), _decode(rest[0], remainder)
        return _decode(first, head), *_decode(tuple[*rest], remainder)
    if (inner := _optional(declared)) is not None:
        frames = _unframe(data)
        return None if not frames else _decode(inner, frames[0])
    if declared is bytes:
        return data
    value = ssz_deserialize(_ssz(declared), data)
    return declared(value) if declared in (bool, int) else value


def _frame(frames: list[bytes]) -> bytes:
    return b"".join(len(frame).to_bytes(4, "little") + frame for frame in frames)


def _unframe(data: bytes) -> list[bytes]:
    frames = []
    while data:
        size = int.from_bytes(data[:4], "little")
        frames.append(data[4 : 4 + size])
        data = data[4 + size :]
    return frames


def _error(namespace, message: str) -> Exception:
    kind, separator, detail = message.partition(": ")
    error = namespace.get(kind) if separator else None
    if isinstance(error, type) and issubclass(error, Exception):
        return error(detail)
    return AssertionError(message)


def call_foreign(language, location, name, namespace, arguments, results):
    library = _library(SPECS / f"{location}.{language}.so")
    config = namespace["config"]
    frames = [b"".join(ssz_serialize(getattr(config, key)) for key in library.configs)]
    frames += [_encode(value, declared) for value, declared in arguments]
    reply = library.call(name, _frame(frames))
    status, body = reply[0], reply[1:]
    if status == 1:
        raise _error(namespace, body.decode())
    if status == 2:
        raise KeyError(f"{language} library {location} has no function `{body.decode()}`")
    decoded = [
        _decode(declared, data) for declared, data in zip(results, _unframe(body), strict=True)
    ]
    for result in decoded:
        _embed(result, [value for value, _ in arguments if is_dataclass(value)])
    return decoded


def _embed(result, objects) -> None:
    if not is_dataclass(result):
        return
    for field in fields(result):
        value = getattr(result, field.name)
        same = [candidate for candidate in objects if type(candidate) is type(value)]
        if len(same) == 1:
            copy_into(same[0], value)
            setattr(result, field.name, same[0])


def copy_into(target, source) -> None:
    if is_dataclass(target):
        for field in fields(target):
            before, after = getattr(target, field.name), getattr(source, field.name)
            if is_dataclass(before) and type(before) is type(after):
                copy_into(before, after)
            else:
                setattr(target, field.name, after)
        return
    for name in type(target).model_fields:
        before, after = getattr(target, name), getattr(source, name)
        if before == after:
            continue
        if isinstance(before, CONTAINERS):
            copy_into(before, after)
        elif isinstance(getattr(type(before), "ELEMENT_TYPE", None), type) and issubclass(
            type(before).ELEMENT_TYPE, CONTAINERS
        ):
            for index in range(min(len(before), len(after))):
                if before[index] != after[index]:
                    copy_into(before[index], after[index])
            while len(before) > len(after):
                before.pop()
            for element in after[len(before) :]:
                before.append(element)
        else:
            setattr(target, name, after)

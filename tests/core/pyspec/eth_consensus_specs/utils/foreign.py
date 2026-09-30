"""
Calls into specification functions compiled from another language.

The compiler builds each fork's definitions into a shared library next to its
generated module, ``build/specs/<fork>/<preset>.<language>.so``. A call sends
frames, each a four-byte little-endian length and that many bytes of SSZ: the
configs the library reads, then every argument. The reply starts with a status
byte: 0 carries one frame per result, 1 an assertion failure, and 2 an unknown
function.
"""

import ctypes
from collections.abc import Sequence
from functools import cache
from pathlib import Path
from typing import get_args, get_origin

from ssz import Boolean, Container, ProgressiveContainer, ProgressiveList, Uint64

from eth_consensus_specs.utils.ssz.ssz_impl import ssz_deserialize, ssz_serialize

SPECS = Path(__file__).resolve().parents[5] / "build" / "specs"
CONTAINERS = (Container, ProgressiveContainer)


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
    return {bool: Boolean, int: Uint64}.get(declared, declared)


@cache
def _sequence(element):
    return type(f"{element.__name__}Sequence", (ProgressiveList[_ssz(element)],), {})


def _encode(value, declared) -> bytes:
    if get_origin(declared) is Sequence:
        (element,) = get_args(declared)
        return ssz_serialize(_sequence(element)(data=list(value)))
    typed = _ssz(declared)
    return ssz_serialize(value if isinstance(value, typed) else typed(value))


def _decode(declared, data: bytes):
    if get_origin(declared) is Sequence:
        (element,) = get_args(declared)
        return [_plain(element, value) for value in ssz_deserialize(_sequence(element), data)]
    return _plain(declared, ssz_deserialize(_ssz(declared), data))


def _plain(declared, value):
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


def call_foreign(language, location, name, config, arguments, results):
    library = _library(SPECS / f"{location}.{language}.so")
    frames = [b"".join(ssz_serialize(getattr(config, key)) for key in library.configs)]
    frames += [_encode(value, declared) for value, declared in arguments]
    reply = library.call(name, _frame(frames))
    status, body = reply[0], reply[1:]
    if status == 1:
        raise AssertionError(body.decode())
    if status == 2:
        raise KeyError(f"{language} library {location} has no function `{body.decode()}`")
    return [_decode(declared, data) for declared, data in zip(results, _unframe(body), strict=True)]


def copy_into(target, source) -> None:
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

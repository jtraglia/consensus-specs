"""
Calls into specification functions compiled from another language.

The compiler builds a fork's definitions into a shared library next to its
generated module, ``build/specs/<fork>/<preset>.<language>.so``. Arguments and
results cross as their SSZ serialization. A reply starts with a status byte: 0
carries the result, 1 an assertion failure, and 2 an unknown function.
"""

import ctypes
from pathlib import Path

from eth_consensus_specs.utils.ssz.ssz_impl import ssz_deserialize, ssz_serialize

SPECS = Path(__file__).resolve().parents[5] / "build" / "specs"

_libraries: dict[str, ctypes.CDLL] = {}


def _library(name: str) -> ctypes.CDLL:
    if name not in _libraries:
        library = ctypes.CDLL(str(SPECS / name))
        library.spec_call.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
        library.spec_call.restype = ctypes.c_void_p
        library.spec_size.argtypes = [ctypes.c_void_p]
        library.spec_size.restype = ctypes.c_size_t
        library.spec_data.argtypes = [ctypes.c_void_p]
        library.spec_data.restype = ctypes.c_void_p
        library.spec_release.argtypes = [ctypes.c_void_p]
        _libraries[name] = library
    return _libraries[name]


def call_foreign(language, location, name, result, *args):
    library = _library(f"{location}.{language}.so")
    data = b"".join(ssz_serialize(argument) for argument in args)
    reply = library.spec_call(name.encode(), data, len(data))
    try:
        payload = ctypes.string_at(library.spec_data(reply), library.spec_size(reply))
    finally:
        library.spec_release(reply)
    status, body = payload[0], payload[1:]
    if status == 0:
        return ssz_deserialize(result, body)
    if status == 1:
        raise AssertionError(body.decode())
    raise KeyError(f"{language} library {location} has no function `{body.decode()}`")

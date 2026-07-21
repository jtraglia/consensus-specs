from hashlib import sha256

from ssz import BaseBytes


class Bytes32(BaseBytes):
    LENGTH = 32


ZERO_BYTES32 = b"\x00" * 32


def hash(x: bytes | bytearray | memoryview) -> Bytes32:
    return bytes.__new__(Bytes32, sha256(x).digest())

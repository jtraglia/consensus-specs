from hashlib import sha256

ZERO_BYTES32 = b"\x00" * 32


def hash(x: bytes | bytearray | memoryview) -> bytes:
    return sha256(x).digest()

# ruff: noqa: F401, N801, N802, N816, PLW1641
"""
SSZ type system compatibility layer.

Provides remerkleable-compatible API on top of py-ssz's serialization and hashing engine.
"""
from __future__ import annotations

import copy as _copy
import hashlib
from typing import Any, TypeVar

import ssz as _ssz
from ssz.sedes import (
    Bitlist as _PySszBitlist,
    Bitvector as _PySszBitvector,
    ByteList as _PySszByteList,
    ByteVector as _PySszByteVector,
    Container as _PySszContainer,
    List as _PySszList,
    UInt as _PySszUInt,
    Vector as _PySszVector,
    boolean as _pyssz_boolean,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ZERO_HASHES: list[bytes] = [b"\x00" * 32]


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _init_zero_hashes(depth: int = 64) -> None:
    while len(ZERO_HASHES) <= depth:
        ZERO_HASHES.append(_sha256(ZERO_HASHES[-1] + ZERO_HASHES[-1]))


_init_zero_hashes()

# Type cache for parameterized types (__class_getitem__)
_type_cache: dict[tuple, type] = {}

# Sedes cache
_sedes_cache: dict[Any, Any] = {}


def _next_power_of_two(x: int) -> int:
    if x <= 0:
        return 1
    return 1 << (x - 1).bit_length()


def _merkleize(chunks: list[bytes], limit: int | None = None) -> bytes:
    """Merkleize chunks into a single root hash."""
    count = len(chunks)
    if limit is None:
        limit = count
    depth = (max(limit, 1) - 1).bit_length() if limit > 0 else 0
    padded = 1 << depth if depth > 0 else 1

    layer = list(chunks) + [ZERO_HASHES[0]] * (padded - count)

    d = 0
    while len(layer) > 1:
        new_layer = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else ZERO_HASHES[d]
            new_layer.append(_sha256(left + right))
        layer = new_layer
        d += 1
    return layer[0] if layer else ZERO_HASHES[0]


def _mix_in_length(root: bytes, length: int) -> bytes:
    length_bytes = length.to_bytes(32, "little")
    return _sha256(root + length_bytes)


def _pack_bits(bits: list[bool]) -> list[bytes]:
    """Pack bits into 32-byte chunks."""
    if not bits:
        return []
    byte_length = (len(bits) + 7) // 8
    data = bytearray(byte_length)
    for i, b in enumerate(bits):
        if b:
            data[i // 8] |= 1 << (i % 8)
    chunks = []
    for i in range(0, len(data), 32):
        chunk = bytes(data[i : i + 32])
        if len(chunk) < 32:
            chunk = chunk + b"\x00" * (32 - len(chunk))
        chunks.append(chunk)
    return chunks


def _pack_uints(values: list, byte_len: int) -> list[bytes]:
    """Pack uint values into 32-byte chunks."""
    if not values:
        return []
    items_per_chunk = 32 // byte_len
    chunks = []
    for i in range(0, len(values), items_per_chunk):
        chunk = b""
        for v in values[i : i + items_per_chunk]:
            chunk += int(v).to_bytes(byte_len, "little")
        if len(chunk) < 32:
            chunk += b"\x00" * (32 - len(chunk))
        chunks.append(chunk)
    return chunks


# ---------------------------------------------------------------------------
# Convert our types to py-ssz compatible values
# ---------------------------------------------------------------------------


def _to_pyssz(val: Any) -> Any:
    """Convert our SSZ types to what py-ssz expects."""
    if isinstance(val, boolean):
        return bool(val)
    if isinstance(val, uint):
        return int(val)
    if isinstance(val, (ByteVector, ByteList)):
        return bytes(val)
    if isinstance(val, Container):
        return tuple(
            _to_pyssz(val.__dict__["_values"][f]) for f in val._field_names
        )
    if isinstance(val, (SSZList, SSZVector)):
        return tuple(_to_pyssz(v) for v in val)
    if isinstance(val, (SSZBitlist, SSZBitvector)):
        return tuple(bool(b) for b in val)
    return val


def _from_pyssz(raw: Any, typ: type) -> Any:
    """Convert py-ssz output back to our types."""
    if issubclass(typ, boolean):
        return typ(raw)
    if issubclass(typ, uint):
        return typ(raw)
    if issubclass(typ, ByteVector):
        return typ(raw)
    if issubclass(typ, ByteList):
        return typ(raw)
    if issubclass(typ, Container):
        field_names = typ._field_names
        field_types = typ._field_types
        kwargs = {}
        for i, fname in enumerate(field_names):
            kwargs[fname] = _from_pyssz(raw[i], field_types[fname])
        return typ(**kwargs)
    if issubclass(typ, SSZList):
        elem_type = typ._element_type
        return typ(_from_pyssz(v, elem_type) for v in raw)
    if issubclass(typ, SSZVector):
        elem_type = typ._element_type
        return typ(_from_pyssz(v, elem_type) for v in raw)
    if issubclass(typ, SSZBitlist):
        return typ(bool(b) for b in raw)
    if issubclass(typ, SSZBitvector):
        return typ(bool(b) for b in raw)
    return raw


# ---------------------------------------------------------------------------
# View / BasicView base
# ---------------------------------------------------------------------------


class View:
    """Base class for all SSZ types."""

    def hash_tree_root(self) -> Bytes32:
        raise NotImplementedError

    def encode_bytes(self) -> bytes:
        raise NotImplementedError

    @classmethod
    def decode_bytes(cls, data: bytes) -> View:
        raise NotImplementedError

    def copy(self) -> View:
        return _copy.deepcopy(self)

    def get_backing(self) -> Backing:
        return Backing(self.encode_bytes(), bytes(self.hash_tree_root()), type(self))

    @classmethod
    def type_repr(cls) -> str:
        return cls.__name__

    @classmethod
    def _get_sedes(cls) -> Any:
        raise NotImplementedError

    @classmethod
    def type_byte_length(cls) -> int:
        raise NotImplementedError


BasicView = View


# ---------------------------------------------------------------------------
# Backing (for get_backing/set_backing/Container(backing=...) pattern)
# ---------------------------------------------------------------------------


class Backing:
    """Wraps serialized bytes and hash root for caching and Merkle proof building."""

    __slots__ = ("_serialized", "_hash_root", "_typ", "_tree")

    def __init__(self, serialized: bytes, hash_root: bytes, typ: type):
        self._serialized = serialized
        self._hash_root = hash_root
        self._typ = typ
        self._tree: TreeNode | None = None

    def merkle_root(self) -> bytes:
        return self._hash_root

    def _ensure_tree(self) -> TreeNode:
        if self._tree is None:
            self._tree = _build_tree_from_type(self._typ, self._serialized)
        return self._tree

    def get_left(self) -> TreeNode:
        return self._ensure_tree().get_left()

    def get_right(self) -> TreeNode:
        return self._ensure_tree().get_right()


class TreeNode:
    """Simple binary Merkle tree node for proof generation."""

    __slots__ = ("_root", "_left", "_right")

    def __init__(self, root: bytes, left: TreeNode | None = None, right: TreeNode | None = None):
        self._root = root
        self._left = left
        self._right = right

    def merkle_root(self) -> bytes:
        return self._root

    def get_left(self) -> TreeNode:
        if self._left is None:
            return TreeNode(ZERO_HASHES[0])
        return self._left

    def get_right(self) -> TreeNode:
        if self._right is None:
            return TreeNode(ZERO_HASHES[0])
        return self._right


def _build_tree_from_chunks(chunks: list[bytes], limit: int | None = None) -> TreeNode:
    """Build a binary Merkle tree from 32-byte chunks."""
    count = len(chunks)
    if limit is None:
        limit = count
    depth = (max(limit, 1) - 1).bit_length() if limit > 0 else 0
    padded = 1 << depth if depth > 0 else 1

    # Leaf nodes
    nodes: list[TreeNode] = []
    for i in range(padded):
        if i < count:
            nodes.append(TreeNode(chunks[i]))
        else:
            nodes.append(TreeNode(ZERO_HASHES[0]))

    # Build tree bottom-up
    d = 0
    while len(nodes) > 1:
        new_nodes = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1] if i + 1 < len(nodes) else TreeNode(ZERO_HASHES[d])
            root = _sha256(left.merkle_root() + right.merkle_root())
            new_nodes.append(TreeNode(root, left, right))
        nodes = new_nodes
        d += 1

    return nodes[0] if nodes else TreeNode(ZERO_HASHES[0])


def _chunks_for_value(val: Any, typ: type) -> list[bytes]:
    """Get the hash tree root chunks for a value (for building tree nodes)."""
    if issubclass(typ, boolean):
        data = int(val).to_bytes(1, "little")
        return [data + b"\x00" * 31]
    if issubclass(typ, uint):
        byte_len = typ.type_byte_length()
        data = int(val).to_bytes(byte_len, "little")
        if len(data) < 32:
            data = data + b"\x00" * (32 - len(data))
        elif len(data) > 32:
            # uint256 is exactly 32 bytes
            chunks = [data[i : i + 32] for i in range(0, len(data), 32)]
            return chunks
        return [data]
    if issubclass(typ, ByteVector):
        data = bytes(val)
        chunks = []
        for i in range(0, len(data), 32):
            chunk = data[i : i + 32]
            if len(chunk) < 32:
                chunk = chunk + b"\x00" * (32 - len(chunk))
            chunks.append(chunk)
        return chunks if chunks else [ZERO_HASHES[0]]
    if issubclass(typ, ByteList):
        data = bytes(val)
        chunks = []
        for i in range(0, len(data), 32):
            chunk = data[i : i + 32]
            if len(chunk) < 32:
                chunk = chunk + b"\x00" * (32 - len(chunk))
            chunks.append(chunk)
        return chunks if chunks else []
    # For composite types, return their hash_tree_root as a single chunk
    return [bytes(val.hash_tree_root())]


def _build_tree_for_value(val: Any) -> TreeNode:
    """Recursively build a full Merkle tree for any SSZ value."""
    if isinstance(val, Container):
        return _build_tree_for_container(val)
    if isinstance(val, (SSZList, ProgressiveList)):
        return _build_tree_for_list(val)
    if isinstance(val, SSZVector):
        return _build_tree_for_vector(val)
    if isinstance(val, (SSZBitlist, ProgressiveBitlist)):
        bits = list(val)
        chunks = _pack_bits(bits)
        limit = val.limit() if hasattr(val, "limit") else _next_power_of_two(len(chunks))
        chunk_limit = (limit + 255) // 256
        data_tree = _build_tree_from_chunks(chunks, limit=chunk_limit)
        length_node = TreeNode(len(bits).to_bytes(32, "little"))
        root = _sha256(data_tree.merkle_root() + length_node.merkle_root())
        return TreeNode(root, data_tree, length_node)
    if isinstance(val, SSZBitvector):
        bits = list(val)
        chunks = _pack_bits(bits)
        return _build_tree_from_chunks(chunks)
    if isinstance(val, ByteList):
        data = bytes(val)
        chunks = []
        for i in range(0, max(len(data), 1), 32):
            chunk = data[i : i + 32]
            if len(chunk) < 32:
                chunk = chunk + b"\x00" * (32 - len(chunk))
            chunks.append(chunk)
        if not chunks:
            chunks = []
        limit = val.limit()
        chunk_limit = (limit + 31) // 32
        data_tree = _build_tree_from_chunks(chunks, limit=chunk_limit)
        length_node = TreeNode(len(data).to_bytes(32, "little"))
        root = _sha256(data_tree.merkle_root() + length_node.merkle_root())
        return TreeNode(root, data_tree, length_node)
    if isinstance(val, ByteVector):
        data = bytes(val)
        chunks = []
        for i in range(0, max(len(data), 1), 32):
            chunk = data[i : i + 32]
            if len(chunk) < 32:
                chunk = chunk + b"\x00" * (32 - len(chunk))
            chunks.append(chunk)
        return _build_tree_from_chunks(chunks) if chunks else TreeNode(ZERO_HASHES[0])
    if isinstance(val, boolean):
        data = int(val).to_bytes(1, "little") + b"\x00" * 31
        return TreeNode(data)
    if isinstance(val, uint):
        byte_len = val.type_byte_length()
        data = int(val).to_bytes(byte_len, "little")
        if len(data) <= 32:
            data = data + b"\x00" * (32 - len(data))
            return TreeNode(data)
        chunks = [data[i : i + 32] for i in range(0, len(data), 32)]
        return _build_tree_from_chunks(chunks)
    # Fallback
    return TreeNode(ZERO_HASHES[0])


def _build_tree_for_container(val: Container) -> TreeNode:
    """Build a full Merkle tree for a Container."""
    field_subtrees = []
    for fname in val._field_names:
        fval = val.__dict__["_values"][fname]
        field_subtrees.append(_build_tree_for_value(fval))

    n = len(field_subtrees)
    padded = _next_power_of_two(n)
    while len(field_subtrees) < padded:
        field_subtrees.append(TreeNode(ZERO_HASHES[0]))

    nodes = field_subtrees
    while len(nodes) > 1:
        new_nodes = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1] if i + 1 < len(nodes) else TreeNode(ZERO_HASHES[0])
            root = _sha256(left.merkle_root() + right.merkle_root())
            new_nodes.append(TreeNode(root, left, right))
        nodes = new_nodes

    return nodes[0] if nodes else TreeNode(ZERO_HASHES[0])


def _build_tree_for_list(val: Any) -> TreeNode:
    """Build a Merkle tree for a List (data tree + length mix-in)."""
    elem_type = val._element_type if hasattr(val, "_element_type") else None

    if elem_type is not None and issubclass(elem_type, (uint, boolean)):
        byte_len = elem_type.type_byte_length()
        chunks = _pack_uints(list(val), byte_len)
    elif elem_type is not None and issubclass(elem_type, ByteVector):
        # Each element is a subtree
        chunks = None  # use subtrees instead
    else:
        chunks = None

    if chunks is not None:
        limit = val._limit if hasattr(val, "_limit") else _next_power_of_two(len(chunks))
        items_per_chunk = 32 // (elem_type.type_byte_length()) if elem_type else 1
        chunk_limit = (limit + items_per_chunk - 1) // items_per_chunk
        data_tree = _build_tree_from_chunks(chunks, limit=chunk_limit)
    else:
        subtrees = [_build_tree_for_value(elem) for elem in val]
        limit = val._limit if hasattr(val, "_limit") else _next_power_of_two(len(subtrees))
        data_tree = _build_tree_from_nodes(subtrees, limit=limit)

    length_node = TreeNode(len(val).to_bytes(32, "little"))
    root = _sha256(data_tree.merkle_root() + length_node.merkle_root())
    return TreeNode(root, data_tree, length_node)


def _build_tree_for_vector(val: SSZVector) -> TreeNode:
    """Build a Merkle tree for a Vector."""
    elem_type = val._element_type

    if issubclass(elem_type, (uint, boolean)):
        byte_len = elem_type.type_byte_length()
        chunks = _pack_uints(list(val), byte_len)
        return _build_tree_from_chunks(chunks)
    else:
        subtrees = [_build_tree_for_value(elem) for elem in val]
        return _build_tree_from_nodes(subtrees, limit=len(subtrees))


def _build_tree_from_nodes(nodes: list[TreeNode], limit: int) -> TreeNode:
    """Build a binary tree from subtree nodes, padding to limit."""
    padded = _next_power_of_two(limit)
    while len(nodes) < padded:
        nodes.append(TreeNode(ZERO_HASHES[0]))

    layer = list(nodes)
    while len(layer) > 1:
        new_layer = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else TreeNode(ZERO_HASHES[0])
            root = _sha256(left.merkle_root() + right.merkle_root())
            new_layer.append(TreeNode(root, left, right))
        layer = new_layer

    return layer[0] if layer else TreeNode(ZERO_HASHES[0])


def _build_tree_from_type(typ: type, serialized: bytes) -> TreeNode:
    """Build a Merkle tree from serialized data and type info."""
    # Deserialize to get the structured object, then build tree
    obj = typ.decode_bytes(serialized)
    if isinstance(obj, Container):
        return _build_tree_for_container(obj)
    # Fallback: return a leaf node with the hash
    root = bytes(obj.hash_tree_root())
    return TreeNode(root)


# ---------------------------------------------------------------------------
# Integer types
# ---------------------------------------------------------------------------


class uint(int, View):
    _num_bits: int = 0

    def __new__(cls, val: Any = 0) -> uint:
        if isinstance(val, (bytes, bytearray)):
            val = int.from_bytes(val, "little")
        val = int(val)
        if cls._num_bits > 0:
            if val < 0 or val >= (1 << cls._num_bits):
                raise ValueError(
                    f"Value {val} out of range for {cls.__name__} "
                    f"(0 to {(1 << cls._num_bits) - 1})"
                )
        return super().__new__(cls, val)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({int(self)})"

    # Arithmetic operators that preserve the uint type
    def _wrap(self, result: Any) -> Any:
        """Create a new instance of the same type. Raises ValueError on overflow."""
        if result is NotImplemented:
            return NotImplemented
        return self.__class__(int(result))

    def __add__(self, other: Any) -> uint:
        return self._wrap(int.__add__(self, other))

    def __radd__(self, other: Any) -> uint:
        return self._wrap(int.__radd__(self, other))

    def __sub__(self, other: Any) -> uint:
        return self._wrap(int.__sub__(self, other))

    def __rsub__(self, other: Any) -> uint:
        return self._wrap(int.__rsub__(self, other))

    def __mul__(self, other: Any) -> uint:
        r = int.__mul__(self, other)
        if r is NotImplemented:
            return NotImplemented
        return self._wrap(r)

    def __rmul__(self, other: Any) -> uint:
        r = int.__rmul__(self, other)
        if r is NotImplemented:
            return NotImplemented
        return self._wrap(r)

    def __floordiv__(self, other: Any) -> uint:
        return self._wrap(int.__floordiv__(self, other))

    def __rfloordiv__(self, other: Any) -> uint:
        return self._wrap(int.__rfloordiv__(self, other))

    def __mod__(self, other: Any) -> uint:
        return self._wrap(int.__mod__(self, other))

    def __rmod__(self, other: Any) -> uint:
        return self._wrap(int.__rmod__(self, other))

    def __pow__(self, other: Any, mod: Any = None) -> uint:
        return self._wrap(int.__pow__(self, other, mod) if mod else int.__pow__(self, other))

    def __lshift__(self, other: Any) -> uint:
        return self._wrap(int.__lshift__(self, other))

    def __rshift__(self, other: Any) -> uint:
        return self._wrap(int.__rshift__(self, other))

    def __and__(self, other: Any) -> uint:
        return self._wrap(int.__and__(self, other))

    def __rand__(self, other: Any) -> uint:
        return self._wrap(int.__rand__(self, other))

    def __or__(self, other: Any) -> uint:
        return self._wrap(int.__or__(self, other))

    def __ror__(self, other: Any) -> uint:
        return self._wrap(int.__ror__(self, other))

    def __xor__(self, other: Any) -> uint:
        return self._wrap(int.__xor__(self, other))

    def __rxor__(self, other: Any) -> uint:
        return self._wrap(int.__rxor__(self, other))

    def __neg__(self) -> uint:
        return self._wrap(int.__neg__(self))

    def __invert__(self) -> uint:
        return self._wrap(int.__invert__(self))

    @classmethod
    def type_byte_length(cls) -> int:
        return cls._num_bits // 8

    @classmethod
    def _get_sedes(cls) -> Any:
        key = ("uint", cls._num_bits)
        if key not in _sedes_cache:
            _sedes_cache[key] = _PySszUInt(cls._num_bits)
        return _sedes_cache[key]

    def hash_tree_root(self) -> Bytes32:
        return Bytes32(_ssz.get_hash_tree_root(int(self), self._get_sedes()))

    def encode_bytes(self) -> bytes:
        return _ssz.encode(int(self), self._get_sedes())

    @classmethod
    def decode_bytes(cls, data: bytes) -> uint:
        return cls(_ssz.decode(data, cls._get_sedes()))

    def copy(self) -> uint:
        return self.__class__(int(self))


class uint8(uint):
    _num_bits = 8


class uint16(uint):
    _num_bits = 16


class uint32(uint):
    _num_bits = 32


class uint64(uint):
    _num_bits = 64


class uint128(uint):
    _num_bits = 128


class uint256(uint):
    _num_bits = 256


class boolean(uint):
    """SSZ boolean: 1-byte, True or False."""

    _num_bits = 8

    def __new__(cls, val: Any = 0) -> boolean:
        return super().__new__(cls, 1 if val else 0)

    def __bool__(self) -> bool:
        return int(self) == 1

    def __repr__(self) -> str:
        return f"boolean({bool(self)})"

    @classmethod
    def _get_sedes(cls) -> Any:
        return _pyssz_boolean

    def hash_tree_root(self) -> Bytes32:
        return Bytes32(_ssz.get_hash_tree_root(bool(self), _pyssz_boolean))

    def encode_bytes(self) -> bytes:
        return _ssz.encode(bool(self), _pyssz_boolean)

    @classmethod
    def decode_bytes(cls, data: bytes) -> boolean:
        return cls(_ssz.decode(data, _pyssz_boolean))


bit = boolean
byte = uint8


# ---------------------------------------------------------------------------
# Byte types
# ---------------------------------------------------------------------------


class ByteVector(bytes, View):
    _length: int = 0

    def __new__(cls, *args: Any) -> ByteVector:
        if not args:
            return super().__new__(cls, b"\x00" * cls._length)
        val = args[0]
        if isinstance(val, memoryview):
            val = bytes(val)
        if isinstance(val, str):
            val = bytes.fromhex(val[2:] if val.startswith("0x") else val)
        if isinstance(val, (int,)):
            val = bytes([val])
        if isinstance(val, (list, tuple)):
            val = bytes(val)
        result = super().__new__(cls, val)
        if cls._length > 0 and len(result) != cls._length:
            raise ValueError(
                f"{cls.__name__}: expected {cls._length} bytes, got {len(result)}"
            )
        return result

    def __class_getitem__(cls, length: int) -> type[ByteVector]:
        key = (cls, length)
        if key not in _type_cache:
            name = f"ByteVector_{length}" if cls is ByteVector else f"{cls.__name__}_{length}"
            _type_cache[key] = type(name, (cls,), {"_length": length})
        return _type_cache[key]

    @classmethod
    def type_byte_length(cls) -> int:
        return cls._length

    @classmethod
    def _get_sedes(cls) -> Any:
        key = ("bytevector", cls._length)
        if key not in _sedes_cache:
            _sedes_cache[key] = _PySszByteVector(cls._length)
        return _sedes_cache[key]

    def hash_tree_root(self) -> Bytes32:
        return Bytes32(_ssz.get_hash_tree_root(bytes(self), self._get_sedes()))

    def encode_bytes(self) -> bytes:
        return _ssz.encode(bytes(self), self._get_sedes())

    @classmethod
    def decode_bytes(cls, data: bytes) -> ByteVector:
        return cls(_ssz.decode(data, cls._get_sedes()))

    def copy(self) -> ByteVector:
        return self.__class__(bytes(self))

    @classmethod
    def type_repr(cls) -> str:
        return f"ByteVector[{cls._length}]"


class ByteList(bytes, View):
    _limit: int = 0

    def __new__(cls, *args: Any) -> ByteList:
        if not args:
            return super().__new__(cls, b"")
        val = args[0]
        if isinstance(val, memoryview):
            val = bytes(val)
        if isinstance(val, str) and val.startswith("0x"):
            val = bytes.fromhex(val[2:])
        if isinstance(val, (list, tuple)):
            val = bytes(val)
        return super().__new__(cls, val)

    def __class_getitem__(cls, limit: int) -> type[ByteList]:
        key = (cls, limit)
        if key not in _type_cache:
            name = f"ByteList_{limit}" if cls is ByteList else f"{cls.__name__}_{limit}"
            _type_cache[key] = type(name, (cls,), {"_limit": limit})
        return _type_cache[key]

    @classmethod
    def limit(cls) -> int:
        return cls._limit

    @classmethod
    def type_byte_length(cls) -> int:
        return cls._limit

    @classmethod
    def _get_sedes(cls) -> Any:
        key = ("bytelist", cls._limit)
        if key not in _sedes_cache:
            _sedes_cache[key] = _PySszByteList(cls._limit)
        return _sedes_cache[key]

    def hash_tree_root(self) -> Bytes32:
        return Bytes32(_ssz.get_hash_tree_root(bytes(self), self._get_sedes()))

    def encode_bytes(self) -> bytes:
        return _ssz.encode(bytes(self), self._get_sedes())

    @classmethod
    def decode_bytes(cls, data: bytes) -> ByteList:
        return cls(_ssz.decode(data, cls._get_sedes()))

    def copy(self) -> ByteList:
        return self.__class__(bytes(self))

    @classmethod
    def type_repr(cls) -> str:
        return f"ByteList[{cls._limit}]"


# Predefined byte types
Bytes1 = ByteVector[1]
Bytes4 = ByteVector[4]
Bytes8 = ByteVector[8]
Bytes20 = ByteVector[20]
Bytes31 = ByteVector[31]
Bytes32 = ByteVector[32]
Bytes48 = ByteVector[48]
Bytes96 = ByteVector[96]


# ---------------------------------------------------------------------------
# Container
# ---------------------------------------------------------------------------


class ContainerMeta(type):
    """Metaclass for SSZ Container: reads __annotations__ to build field descriptors."""

    def __new__(mcs, name: str, bases: tuple, namespace: dict) -> ContainerMeta:
        cls = super().__new__(mcs, name, bases, namespace)

        if name == "Container":
            cls._field_names = ()
            cls._field_types = {}
            return cls

        # Collect annotations from the MRO (child overrides parent)
        all_annotations: dict[str, type] = {}
        for base in reversed(cls.__mro__):
            ann = base.__dict__.get("__annotations__", {})
            for k, v in ann.items():
                if not k.startswith("_"):
                    all_annotations[k] = v

        field_names = []
        field_types = {}
        for fname, ftype in all_annotations.items():
            field_names.append(fname)
            field_types[fname] = ftype

        cls._field_names = tuple(field_names)
        cls._field_types = field_types

        # Build py-ssz Container sedes (lazily via _get_sedes)
        cls._ssz_sedes_cache = None

        return cls

    def __instancecheck__(cls, instance: Any) -> bool:
        return type.__instancecheck__(cls, instance)


class Container(View, metaclass=ContainerMeta):
    """SSZ Container with annotation-style field definitions."""

    _field_names: tuple[str, ...] = ()
    _field_types: dict[str, type] = {}

    def __init__(self, backing: Any = None, **kwargs: Any) -> None:
        values: dict[str, Any] = {}

        if backing is not None:
            # Reconstruct from a Backing object or raw bytes
            if isinstance(backing, Backing):
                restored = type(self).decode_bytes(backing._serialized)
                self.__dict__["_values"] = restored.__dict__["_values"]
                return
            if isinstance(backing, bytes):
                restored = type(self).decode_bytes(backing)
                self.__dict__["_values"] = restored.__dict__["_values"]
                return

        for fname in self._field_names:
            if fname in kwargs:
                val = kwargs[fname]
                ftype = self._field_types[fname]
                # Auto-wrap raw values into the expected SSZ type
                values[fname] = _coerce(val, ftype)
            else:
                values[fname] = _default_value(self._field_types[fname])

        self.__dict__["_values"] = values

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        values = self.__dict__.get("_values")
        if values is not None and name in values:
            return values[name]
        raise AttributeError(f"'{type(self).__name__}' has no field '{name}'")

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_"):
            super().__setattr__(name, value)
            return
        if name in self._field_types:
            self.__dict__["_values"][name] = _coerce(value, self._field_types[name])
        else:
            super().__setattr__(name, value)

    @classmethod
    def fields(cls) -> dict[str, type]:
        return dict(cls._field_types)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Container):
            return NotImplemented
        # Compare by field names and values (not exact type identity)
        if self._field_names != other._field_names:
            return False
        return self.__dict__["_values"] == other.__dict__["_values"]

    def __hash__(self) -> int:
        return hash(bytes(self.hash_tree_root()))

    def __repr__(self) -> str:
        fields = ", ".join(
            f"{f}={self.__dict__['_values'].get(f)!r}" for f in self._field_names
        )
        return f"{type(self).__name__}({fields})"

    def __iter__(self):
        for f in self._field_names:
            yield self.__dict__["_values"][f]

    def copy(self) -> Container:
        return _copy.deepcopy(self)

    @classmethod
    def _get_sedes(cls) -> Any:
        if cls._ssz_sedes_cache is None:
            field_sedes = tuple(
                _get_type_sedes(cls._field_types[f]) for f in cls._field_names
            )
            cls._ssz_sedes_cache = _PySszContainer(field_sedes)
        return cls._ssz_sedes_cache

    def hash_tree_root(self) -> Bytes32:
        sedes = self._get_sedes()
        pyssz_val = _to_pyssz(self)
        return Bytes32(_ssz.get_hash_tree_root(pyssz_val, sedes))

    def encode_bytes(self) -> bytes:
        sedes = self._get_sedes()
        pyssz_val = _to_pyssz(self)
        return _ssz.encode(pyssz_val, sedes)

    @classmethod
    def decode_bytes(cls, data: bytes) -> Container:
        sedes = cls._get_sedes()
        raw = _ssz.decode(data, sedes)
        return _from_pyssz(raw, cls)

    def get_backing(self) -> Backing:
        serialized = self.encode_bytes()
        root = bytes(self.hash_tree_root())
        backing = Backing(serialized, root, type(self))
        # Pre-build tree for containers so proof generation works
        backing._tree = _build_tree_for_container(self)
        return backing

    def set_backing(self, backing: Any) -> None:
        """Restore container state from a Backing object."""
        if isinstance(backing, Backing):
            restored = type(self).decode_bytes(backing._serialized)
        elif isinstance(backing, bytes):
            restored = type(self).decode_bytes(backing)
        else:
            raise TypeError(f"Cannot set_backing with {type(backing)}")
        self.__dict__["_values"] = restored.__dict__["_values"]

    @classmethod
    def type_repr(cls) -> str:
        return cls.__name__


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------


class SSZList(list, View):
    """SSZ List: variable-length homogeneous sequence."""

    _element_type: type = None  # type: ignore
    _limit: int = 0

    def __class_getitem__(cls, params: Any) -> type[SSZList]:
        if not isinstance(params, tuple) or len(params) != 2:
            raise TypeError(f"List requires [element_type, limit], got {params}")
        elem_type, limit = params
        key = (cls, elem_type, limit)
        if key not in _type_cache:
            name = f"List_{getattr(elem_type, '__name__', str(elem_type))}_{limit}"
            _type_cache[key] = type(name, (cls,), {
                "_element_type": elem_type,
                "_limit": limit,
            })
        return _type_cache[key]

    def __init__(self, *args: Any) -> None:
        if not args:
            super().__init__()
        elif len(args) == 1:
            val = args[0]
            elem_type = self._element_type
            # Don't iterate over single View objects (Container, ByteVector, etc.)
            if isinstance(val, View) and not isinstance(val, (SSZList, SSZVector, SSZBitlist, SSZBitvector)):
                super().__init__([_coerce(val, elem_type)])
            elif hasattr(val, "__iter__") and not isinstance(val, (str, bytes)):
                items = [_coerce(v, elem_type) for v in val]
                super().__init__(items)
            else:
                super().__init__([_coerce(val, elem_type)])
        else:
            super().__init__(_coerce(v, self._element_type) for v in args)

    def append(self, value: Any) -> None:
        super().append(_coerce(value, self._element_type))

    def __setitem__(self, key: Any, value: Any) -> None:
        if isinstance(key, slice):
            super().__setitem__(key, [_coerce(v, self._element_type) for v in value])
        else:
            super().__setitem__(key, _coerce(value, self._element_type))

    @classmethod
    def element_cls(cls) -> type:
        return cls._element_type

    @classmethod
    def limit(cls) -> int:
        return cls._limit

    @classmethod
    def _get_sedes(cls) -> Any:
        key = ("list", id(cls._element_type), cls._limit)
        if key not in _sedes_cache:
            _sedes_cache[key] = _PySszList(
                _get_type_sedes(cls._element_type), max_length=cls._limit
            )
        return _sedes_cache[key]

    def hash_tree_root(self) -> Bytes32:
        sedes = self._get_sedes()
        pyssz_val = _to_pyssz(self)
        return Bytes32(_ssz.get_hash_tree_root(pyssz_val, sedes))

    def encode_bytes(self) -> bytes:
        sedes = self._get_sedes()
        pyssz_val = _to_pyssz(self)
        return _ssz.encode(pyssz_val, sedes)

    @classmethod
    def decode_bytes(cls, data: bytes) -> SSZList:
        sedes = cls._get_sedes()
        raw = _ssz.decode(data, sedes)
        return _from_pyssz(raw, cls)

    def copy(self) -> SSZList:
        return _copy.deepcopy(self)

    @classmethod
    def type_repr(cls) -> str:
        return f"List[{cls._element_type.__name__}, {cls._limit}]"


# Export as 'List'
List = SSZList


# ---------------------------------------------------------------------------
# Vector
# ---------------------------------------------------------------------------


class SSZVector(list, View):
    """SSZ Vector: fixed-length homogeneous sequence."""

    _element_type: type = None  # type: ignore
    _length: int = 0

    def __class_getitem__(cls, params: Any) -> type[SSZVector]:
        if not isinstance(params, tuple) or len(params) != 2:
            raise TypeError(f"Vector requires [element_type, length], got {params}")
        elem_type, length = params
        key = (cls, elem_type, length)
        if key not in _type_cache:
            name = f"Vector_{getattr(elem_type, '__name__', str(elem_type))}_{length}"
            _type_cache[key] = type(name, (cls,), {
                "_element_type": elem_type,
                "_length": length,
            })
        return _type_cache[key]

    def __init__(self, *args: Any) -> None:
        if not args:
            # Default: vector of default values
            elem_type = self._element_type
            super().__init__(_default_value(elem_type) for _ in range(self._length))
        elif len(args) == 1:
            val = args[0]
            elem_type = self._element_type
            # Don't iterate over single View objects (Container, ByteVector, etc.)
            if isinstance(val, View) and not isinstance(val, (SSZList, SSZVector, SSZBitlist, SSZBitvector)):
                super().__init__([_coerce(val, elem_type)])
            elif hasattr(val, "__iter__") and not isinstance(val, (str, bytes)):
                items = [_coerce(v, elem_type) for v in val]
                super().__init__(items)
            else:
                super().__init__([_coerce(val, elem_type)])
        else:
            super().__init__(_coerce(v, self._element_type) for v in args)

    def __setitem__(self, key: Any, value: Any) -> None:
        if isinstance(key, slice):
            super().__setitem__(key, [_coerce(v, self._element_type) for v in value])
        else:
            super().__setitem__(key, _coerce(value, self._element_type))

    @classmethod
    def element_cls(cls) -> type:
        return cls._element_type

    @classmethod
    def vector_length(cls) -> int:
        return cls._length

    @classmethod
    def _get_sedes(cls) -> Any:
        key = ("vector", id(cls._element_type), cls._length)
        if key not in _sedes_cache:
            _sedes_cache[key] = _PySszVector(
                _get_type_sedes(cls._element_type), cls._length
            )
        return _sedes_cache[key]

    def hash_tree_root(self) -> Bytes32:
        sedes = self._get_sedes()
        pyssz_val = _to_pyssz(self)
        return Bytes32(_ssz.get_hash_tree_root(pyssz_val, sedes))

    def encode_bytes(self) -> bytes:
        sedes = self._get_sedes()
        pyssz_val = _to_pyssz(self)
        return _ssz.encode(pyssz_val, sedes)

    @classmethod
    def decode_bytes(cls, data: bytes) -> SSZVector:
        sedes = cls._get_sedes()
        raw = _ssz.decode(data, sedes)
        return _from_pyssz(raw, cls)

    def copy(self) -> SSZVector:
        return _copy.deepcopy(self)

    @classmethod
    def type_repr(cls) -> str:
        return f"Vector[{cls._element_type.__name__}, {cls._length}]"


# Export as 'Vector'
Vector = SSZVector


# ---------------------------------------------------------------------------
# Bitlist
# ---------------------------------------------------------------------------


class SSZBitlist(list, View):
    """SSZ Bitlist: variable-length sequence of bits."""

    _limit: int = 0

    def __class_getitem__(cls, limit: int) -> type[SSZBitlist]:
        key = (cls, limit)
        if key not in _type_cache:
            name = f"Bitlist_{limit}"
            _type_cache[key] = type(name, (cls,), {"_limit": limit})
        return _type_cache[key]

    def __init__(self, *args: Any) -> None:
        if not args:
            super().__init__()
        elif len(args) == 1:
            val = args[0]
            if isinstance(val, int):
                super().__init__([False] * val)
            elif hasattr(val, "__iter__"):
                super().__init__(bool(b) for b in val)
            else:
                super().__init__([bool(val)])
        else:
            super().__init__(bool(b) for b in args)

    def __setitem__(self, key: Any, value: Any) -> None:
        if isinstance(key, slice):
            super().__setitem__(key, [bool(v) for v in value])
        else:
            super().__setitem__(key, bool(value))

    @classmethod
    def element_cls(cls) -> type:
        return boolean

    @classmethod
    def limit(cls) -> int:
        return cls._limit

    @classmethod
    def _get_sedes(cls) -> Any:
        key = ("bitlist", cls._limit)
        if key not in _sedes_cache:
            _sedes_cache[key] = _PySszBitlist(cls._limit)
        return _sedes_cache[key]

    def hash_tree_root(self) -> Bytes32:
        sedes = self._get_sedes()
        return Bytes32(_ssz.get_hash_tree_root(tuple(self), sedes))

    def encode_bytes(self) -> bytes:
        sedes = self._get_sedes()
        return _ssz.encode(tuple(self), sedes)

    @classmethod
    def decode_bytes(cls, data: bytes) -> SSZBitlist:
        sedes = cls._get_sedes()
        raw = _ssz.decode(data, sedes)
        return cls(bool(b) for b in raw)

    def copy(self) -> SSZBitlist:
        return self.__class__(list(self))

    @classmethod
    def type_repr(cls) -> str:
        return f"Bitlist[{cls._limit}]"


Bitlist = SSZBitlist


# ---------------------------------------------------------------------------
# Bitvector
# ---------------------------------------------------------------------------


class SSZBitvector(list, View):
    """SSZ Bitvector: fixed-length sequence of bits."""

    _length: int = 0

    def __class_getitem__(cls, length: int) -> type[SSZBitvector]:
        key = (cls, length)
        if key not in _type_cache:
            name = f"Bitvector_{length}"
            _type_cache[key] = type(name, (cls,), {"_length": length})
        return _type_cache[key]

    def __init__(self, *args: Any) -> None:
        if not args:
            super().__init__([False] * self._length)
        elif len(args) == 1:
            val = args[0]
            if isinstance(val, int) and not isinstance(val, bool):
                super().__init__([False] * val)
            elif hasattr(val, "__iter__") and not isinstance(val, (str, bytes)):
                super().__init__(bool(b) for b in val)
            else:
                super().__init__([bool(val)])
        else:
            super().__init__(bool(b) for b in args)

    def __setitem__(self, key: Any, value: Any) -> None:
        if isinstance(key, slice):
            super().__setitem__(key, [bool(v) for v in value])
        else:
            super().__setitem__(key, bool(value))

    @classmethod
    def element_cls(cls) -> type:
        return boolean

    @classmethod
    def vector_length(cls) -> int:
        return cls._length

    @classmethod
    def _get_sedes(cls) -> Any:
        key = ("bitvector", cls._length)
        if key not in _sedes_cache:
            _sedes_cache[key] = _PySszBitvector(cls._length)
        return _sedes_cache[key]

    def hash_tree_root(self) -> Bytes32:
        sedes = self._get_sedes()
        return Bytes32(_ssz.get_hash_tree_root(tuple(self), sedes))

    def encode_bytes(self) -> bytes:
        sedes = self._get_sedes()
        return _ssz.encode(tuple(self), sedes)

    @classmethod
    def decode_bytes(cls, data: bytes) -> SSZBitvector:
        sedes = cls._get_sedes()
        raw = _ssz.decode(data, sedes)
        return cls(bool(b) for b in raw)

    def copy(self) -> SSZBitvector:
        return self.__class__(list(self))

    @classmethod
    def type_repr(cls) -> str:
        return f"Bitvector[{cls._length}]"


Bitvector = SSZBitvector


# ---------------------------------------------------------------------------
# Progressive types (standalone implementation, no py-ssz support)
# ---------------------------------------------------------------------------


class ProgressiveList(list, View):
    """SSZ Progressive List: unbounded variable-length list."""

    _element_type: type = None  # type: ignore

    def __class_getitem__(cls, elem_type: type) -> type[ProgressiveList]:
        key = (cls, elem_type)
        if key not in _type_cache:
            name = f"ProgressiveList_{getattr(elem_type, '__name__', str(elem_type))}"
            _type_cache[key] = type(name, (cls,), {"_element_type": elem_type})
        return _type_cache[key]

    def __init__(self, *args: Any) -> None:
        if not args:
            super().__init__()
        elif len(args) == 1:
            val = args[0]
            elem_type = self._element_type
            if elem_type is not None and hasattr(val, "__iter__") and not isinstance(val, (str, bytes)):
                super().__init__(_coerce(v, elem_type) for v in val)
            else:
                super().__init__([val])
        else:
            super().__init__(args)

    def append(self, value: Any) -> None:
        if self._element_type is not None:
            super().append(_coerce(value, self._element_type))
        else:
            super().append(value)

    def __setitem__(self, key: Any, value: Any) -> None:
        if isinstance(key, slice):
            super().__setitem__(key, list(value))
        else:
            super().__setitem__(key, value)

    @classmethod
    def element_cls(cls) -> type:
        return cls._element_type

    @classmethod
    def limit(cls) -> int:
        return 2**64 - 1

    def hash_tree_root(self) -> Bytes32:
        return Bytes32(_progressive_list_hash_tree_root(self, self._element_type))

    def encode_bytes(self) -> bytes:
        return _progressive_list_serialize(self, self._element_type)

    @classmethod
    def decode_bytes(cls, data: bytes) -> ProgressiveList:
        return _progressive_list_deserialize(cls, data)

    def copy(self) -> ProgressiveList:
        return _copy.deepcopy(self)

    @classmethod
    def type_repr(cls) -> str:
        return f"ProgressiveList[{getattr(cls._element_type, '__name__', '?')}]"


class ProgressiveBitlist(list, View):
    """SSZ Progressive Bitlist: unbounded variable-length bitlist."""

    def __init__(self, *args: Any) -> None:
        if not args:
            super().__init__()
        elif len(args) == 1:
            val = args[0]
            if isinstance(val, int) and not isinstance(val, bool):
                super().__init__([False] * val)
            elif hasattr(val, "__iter__") and not isinstance(val, (str, bytes)):
                super().__init__(bool(b) for b in val)
            else:
                super().__init__([bool(val)])
        else:
            super().__init__(bool(b) for b in args)

    def __setitem__(self, key: Any, value: Any) -> None:
        if isinstance(key, slice):
            super().__setitem__(key, [bool(v) for v in value])
        else:
            super().__setitem__(key, bool(value))

    @classmethod
    def element_cls(cls) -> type:
        return boolean

    @classmethod
    def limit(cls) -> int:
        return 2**64 - 1

    def length(self) -> int:
        return len(self)

    def hash_tree_root(self) -> Bytes32:
        return Bytes32(_progressive_bitlist_hash_tree_root(self))

    def encode_bytes(self) -> bytes:
        return _progressive_bitlist_serialize(self)

    @classmethod
    def decode_bytes(cls, data: bytes) -> ProgressiveBitlist:
        return _progressive_bitlist_deserialize(cls, data)

    def copy(self) -> ProgressiveBitlist:
        return self.__class__(list(self))

    @classmethod
    def type_repr(cls) -> str:
        return "ProgressiveBitlist"


class _ProgressiveContainerBase(Container):
    """Base for ProgressiveContainer subclasses."""
    _active_fields: list[int] = []


class _ProgressiveContainerFactory:
    """Factory to create ProgressiveContainer base classes with active_fields."""

    def __call__(self, active_fields: list[int] | None = None) -> type:
        if active_fields is None:
            active_fields = []
        key = ("progressive_container", tuple(active_fields))
        if key not in _type_cache:
            _type_cache[key] = type(
                f"ProgressiveContainerBase_{''.join(str(x) for x in active_fields)}",
                (_ProgressiveContainerBase,),
                {"_active_fields": list(active_fields)},
            )
        return _type_cache[key]

    def __instancecheck__(self, instance: Any) -> bool:
        return isinstance(instance, _ProgressiveContainerBase)

    def __subclasscheck__(self, subclass: type) -> bool:
        if subclass is _ProgressiveContainerBase:
            return True
        try:
            return issubclass(subclass, _ProgressiveContainerBase)
        except TypeError:
            return False


ProgressiveContainer = _ProgressiveContainerFactory()


# ---------------------------------------------------------------------------
# Union / CompatibleUnion
# ---------------------------------------------------------------------------


class Union(View):
    """SSZ Union type."""

    _options: tuple = ()

    def __class_getitem__(cls, options: Any) -> type[Union]:
        if not isinstance(options, tuple):
            options = (options,)
        key = (cls, options)
        if key not in _type_cache:
            name = f"Union_{'_'.join(str(o) for o in options)}"
            _type_cache[key] = type(name, (cls,), {"_options": options})
        return _type_cache[key]

    def __init__(self, *, selector: int = 0, value: Any = None) -> None:
        self._selector = selector
        self._value = value

    def selector(self) -> int:
        return self._selector

    def value(self) -> Any:
        return self._value

    @classmethod
    def options(cls) -> tuple:
        return cls._options

    def __eq__(self, other: Any) -> bool:
        if type(self) is not type(other):
            return False
        return self._selector == other._selector and self._value == other._value

    def __hash__(self) -> int:
        return hash((self._selector, self._value))

    def hash_tree_root(self) -> Bytes32:
        return Bytes32(_union_hash_tree_root(self))

    def encode_bytes(self) -> bytes:
        return _union_serialize(self)

    @classmethod
    def decode_bytes(cls, data: bytes) -> Union:
        return _union_deserialize(cls, data)

    def copy(self) -> Union:
        return _copy.deepcopy(self)

    @classmethod
    def type_repr(cls) -> str:
        return f"Union[{', '.join(str(o) for o in cls._options)}]"


class CompatibleUnion(View):
    """SSZ CompatibleUnion type."""

    _options_map: dict[int, type] = {}

    def __class_getitem__(cls, options_map: dict[int, type]) -> type[CompatibleUnion]:
        key = (cls, tuple(sorted(options_map.items())))
        if key not in _type_cache:
            name = f"CompatibleUnion_{hash(key)}"
            _type_cache[key] = type(name, (cls,), {"_options_map": dict(options_map)})
        return _type_cache[key]

    def __new__(cls, options_map: dict | None = None, **kwargs: Any) -> CompatibleUnion:
        if options_map is not None and not kwargs:
            # Called as CompatibleUnion({1: T1, 2: T2}) -- returns a TYPE, not an instance
            return cls[options_map]  # type: ignore
        return super().__new__(cls)

    def __init__(self, options_map: dict | None = None, *, selector: int = 0, data: Any = None) -> None:
        if options_map is not None and not hasattr(self, "_selector"):
            # This was a type creation call, __new__ returned a type
            return
        self._selector = selector
        self._data = data

    def selector(self) -> int:
        return self._selector

    def data(self) -> Any:
        return self._data

    @classmethod
    def options(cls) -> dict[int, type]:
        return dict(cls._options_map)

    def __eq__(self, other: Any) -> bool:
        if type(self) is not type(other):
            return False
        return self._selector == other._selector and self._data == other._data

    def __hash__(self) -> int:
        return hash((self._selector, self._data))

    def hash_tree_root(self) -> Bytes32:
        return Bytes32(_compatible_union_hash_tree_root(self))

    def encode_bytes(self) -> bytes:
        return _compatible_union_serialize(self)

    @classmethod
    def decode_bytes(cls, data_bytes: bytes) -> CompatibleUnion:
        return _compatible_union_deserialize(cls, data_bytes)

    def copy(self) -> CompatibleUnion:
        return _copy.deepcopy(self)

    @classmethod
    def type_repr(cls) -> str:
        return f"CompatibleUnion[{cls._options_map}]"


# ---------------------------------------------------------------------------
# Path and gindex utilities
# ---------------------------------------------------------------------------


def gindex_bit_iter(gindex: int) -> tuple[list[bool], int]:
    """Decompose a generalized index into a sequence of left/right choices (root to leaf)."""
    bits: list[bool] = []
    while gindex > 1:
        bits.append(bool(gindex & 1))
        gindex >>= 1
    bits.reverse()
    return bits, len(bits)


class Path:
    """Navigate SSZ type trees to compute generalized indices."""

    def __init__(self, typ: type, gindex: int = 1) -> None:
        self._typ = typ
        self._gindex = gindex

    def __truediv__(self, item: Any) -> Path:
        typ = self._typ
        gindex = self._gindex

        if isinstance(item, str):
            # Container field navigation
            if not hasattr(typ, "_field_names"):
                raise TypeError(f"{typ} is not a Container")
            fields = typ._field_names
            if item not in fields:
                raise KeyError(f"Field '{item}' not in {typ.__name__}")
            idx = list(fields).index(item)
            chunk_count = _next_power_of_two(len(fields))
            new_gindex = gindex * chunk_count + idx
            return Path(typ._field_types[item], new_gindex)
        elif isinstance(item, int):
            # List/Vector element navigation
            if hasattr(typ, "_element_type"):
                elem_type = typ._element_type
                if hasattr(typ, "_limit"):
                    # List: gindex * 2 (data subtree), then navigate
                    limit = typ._limit
                    chunk_count = _next_power_of_two(limit)
                    new_gindex = gindex * 2 * chunk_count + item
                elif hasattr(typ, "_length"):
                    # Vector
                    length = typ._length
                    chunk_count = _next_power_of_two(length)
                    new_gindex = gindex * chunk_count + item
                else:
                    chunk_count = _next_power_of_two(1)
                    new_gindex = gindex * chunk_count + item
                return Path(elem_type, new_gindex)
            raise TypeError(f"Cannot index into {typ}")
        raise TypeError(f"Invalid path item: {item}")

    def gindex(self) -> int:
        return self._gindex


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _get_type_sedes(typ: type) -> Any:
    """Get the py-ssz sedes for an SSZ type."""
    if hasattr(typ, "_get_sedes"):
        return typ._get_sedes()
    raise TypeError(f"No sedes for type: {typ}")


def _default_value(typ: type) -> Any:
    """Create the default (zero) value for an SSZ type."""
    if issubclass(typ, boolean):
        return typ(False)
    if issubclass(typ, uint):
        return typ(0)
    if issubclass(typ, ByteVector):
        return typ()
    if issubclass(typ, ByteList):
        return typ()
    if issubclass(typ, Container):
        return typ()
    if issubclass(typ, SSZList):
        return typ()
    if issubclass(typ, SSZVector):
        return typ()
    if issubclass(typ, SSZBitlist):
        return typ()
    if issubclass(typ, SSZBitvector):
        return typ()
    if issubclass(typ, ProgressiveList):
        return typ()
    if issubclass(typ, ProgressiveBitlist):
        return typ()
    if issubclass(typ, _ProgressiveContainerBase):
        return typ()
    return typ()


def _coerce(val: Any, typ: type) -> Any:
    """Coerce a value to the expected SSZ type if needed."""
    if val is None:
        return _default_value(typ)

    # Already correct type
    if isinstance(val, typ):
        return val

    # Basic integer types
    if issubclass(typ, boolean):
        return typ(val)
    if issubclass(typ, uint):
        # Wrap overflowing values modulo 2^N during coercion
        int_val = int(val)
        if typ._num_bits > 0 and (int_val < 0 or int_val >= (1 << typ._num_bits)):
            int_val = int_val % (1 << typ._num_bits)
        return typ(int_val)

    # Byte types
    if issubclass(typ, ByteVector):
        if isinstance(val, (bytes, bytearray, memoryview, str)):
            return typ(val)
        return val
    if issubclass(typ, ByteList):
        if isinstance(val, (bytes, bytearray, memoryview, str)):
            return typ(val)
        return val

    # List/Vector from iterable
    if issubclass(typ, (SSZList, SSZVector)):
        if hasattr(val, "__iter__") and not isinstance(val, (str, bytes)):
            return typ(val)
        return val

    # Bitlist/Bitvector from iterable
    if issubclass(typ, (SSZBitlist, SSZBitvector)):
        if hasattr(val, "__iter__") and not isinstance(val, (str, bytes)):
            return typ(val)
        return val

    # Container from dict
    if issubclass(typ, Container):
        if isinstance(val, dict):
            return typ(**val)
        return val

    return val


# ---------------------------------------------------------------------------
# Progressive types: standalone serialization/hashing
# ---------------------------------------------------------------------------


def _progressive_list_serialize(lst: ProgressiveList, elem_type: type) -> bytes:
    """Serialize a ProgressiveList."""
    if not lst:
        return b""
    parts = []
    if _is_fixed_size(elem_type):
        for item in lst:
            parts.append(item.encode_bytes() if hasattr(item, "encode_bytes") else _ssz.encode(_to_pyssz(item), _get_type_sedes(elem_type)))
        return b"".join(parts)
    else:
        # Variable-size elements: use offset-based encoding
        fixed_parts = []
        var_parts = []
        for item in lst:
            serialized = item.encode_bytes() if hasattr(item, "encode_bytes") else _ssz.encode(_to_pyssz(item), _get_type_sedes(elem_type))
            var_parts.append(serialized)
            fixed_parts.append(None)  # placeholder for offset

        offset = len(lst) * 4  # 4 bytes per offset
        result = b""
        for i in range(len(lst)):
            result += offset.to_bytes(4, "little")
            offset += len(var_parts[i])
        for part in var_parts:
            result += part
        return result


def _progressive_list_hash_tree_root(lst: ProgressiveList, elem_type: type) -> bytes:
    """Hash tree root for ProgressiveList (unbounded list)."""
    if elem_type is not None and issubclass(elem_type, (uint, boolean)):
        byte_len = elem_type.type_byte_length()
        chunks = _pack_uints(lst, byte_len)
    else:
        chunks = []
        for item in lst:
            if hasattr(item, "hash_tree_root"):
                chunks.append(bytes(item.hash_tree_root()))
            else:
                sedes = _get_type_sedes(elem_type)
                chunks.append(_ssz.get_hash_tree_root(_to_pyssz(item), sedes))

    # For progressive list, limit is unbounded -- use next_power_of_two of count
    root = _merkleize(chunks, limit=_next_power_of_two(len(chunks)) if chunks else 0)
    return _mix_in_length(root, len(lst))


def _progressive_list_deserialize(cls: type, data: bytes) -> ProgressiveList:
    """Deserialize a ProgressiveList."""
    elem_type = cls._element_type
    if not data:
        return cls()
    if _is_fixed_size(elem_type):
        elem_size = _fixed_size(elem_type)
        items = []
        for i in range(0, len(data), elem_size):
            chunk = data[i : i + elem_size]
            items.append(elem_type.decode_bytes(chunk))
        return cls(items)
    else:
        # Variable-size: read offsets
        if len(data) < 4:
            return cls()
        first_offset = int.from_bytes(data[0:4], "little")
        num_items = first_offset // 4
        offsets = [int.from_bytes(data[i * 4 : (i + 1) * 4], "little") for i in range(num_items)]
        offsets.append(len(data))
        items = []
        for i in range(num_items):
            chunk = data[offsets[i] : offsets[i + 1]]
            items.append(elem_type.decode_bytes(chunk))
        return cls(items)


def _progressive_bitlist_serialize(bits: ProgressiveBitlist) -> bytes:
    """Serialize a ProgressiveBitlist (same as regular Bitlist encoding with sentinel bit)."""
    n = len(bits)
    byte_length = (n + 8) // 8  # +1 for sentinel bit, then round up
    data = bytearray(byte_length)
    for i, b in enumerate(bits):
        if b:
            data[i // 8] |= 1 << (i % 8)
    # Set sentinel bit
    data[n // 8] |= 1 << (n % 8)
    return bytes(data)


def _progressive_bitlist_hash_tree_root(bits: ProgressiveBitlist) -> bytes:
    """Hash tree root for ProgressiveBitlist."""
    chunks = _pack_bits(list(bits))
    root = _merkleize(chunks, limit=_next_power_of_two(len(chunks)) if chunks else 0)
    return _mix_in_length(root, len(bits))


def _progressive_bitlist_deserialize(cls: type, data: bytes) -> ProgressiveBitlist:
    """Deserialize a ProgressiveBitlist."""
    if not data:
        return cls()
    # Find sentinel bit
    last_byte = data[-1]
    if last_byte == 0:
        raise ValueError("Invalid bitlist: last byte is zero")
    bit_length = (len(data) - 1) * 8
    for i in range(7, -1, -1):
        if last_byte & (1 << i):
            bit_length += i
            break
    bits = []
    for i in range(bit_length):
        bits.append(bool(data[i // 8] & (1 << (i % 8))))
    return cls(bits)


def _is_fixed_size(typ: type) -> bool:
    """Check if a type has a fixed serialization size."""
    if issubclass(typ, (uint, boolean)):
        return True
    if issubclass(typ, ByteVector):
        return True
    if issubclass(typ, ByteList):
        return False
    if issubclass(typ, Container):
        return all(_is_fixed_size(ft) for ft in typ._field_types.values())
    if issubclass(typ, SSZVector):
        return _is_fixed_size(typ._element_type)
    if issubclass(typ, SSZBitvector):
        return True
    return False


def _fixed_size(typ: type) -> int:
    """Get the fixed serialization size for a type."""
    if issubclass(typ, (uint, boolean)):
        return typ.type_byte_length()
    if issubclass(typ, ByteVector):
        return typ._length
    if issubclass(typ, Container):
        return sum(_fixed_size(ft) for ft in typ._field_types.values())
    if issubclass(typ, SSZVector):
        return typ._length * _fixed_size(typ._element_type)
    if issubclass(typ, SSZBitvector):
        return (typ._length + 7) // 8
    raise TypeError(f"Not a fixed-size type: {typ}")


# ---------------------------------------------------------------------------
# Union serialization/hashing (standalone)
# ---------------------------------------------------------------------------


def _union_serialize(union: Union) -> bytes:
    """Serialize a Union value."""
    selector = union.selector()
    value = union.value()
    if value is None:
        return bytes([selector])
    serialized = value.encode_bytes() if hasattr(value, "encode_bytes") else b""
    return bytes([selector]) + serialized


def _union_hash_tree_root(union: Union) -> bytes:
    """Hash tree root for a Union."""
    selector = union.selector()
    value = union.value()
    if value is None:
        value_root = ZERO_HASHES[0]
    else:
        value_root = bytes(value.hash_tree_root())
    selector_root = selector.to_bytes(32, "little")
    return _sha256(value_root + selector_root)


def _union_deserialize(cls: type, data: bytes) -> Union:
    """Deserialize a Union value."""
    selector = data[0]
    options = cls.options()
    value_type = options[selector]
    if value_type is None:
        return cls(selector=selector, value=None)
    value_data = data[1:]
    value = value_type.decode_bytes(value_data)
    return cls(selector=selector, value=value)


def _compatible_union_serialize(union: CompatibleUnion) -> bytes:
    """Serialize a CompatibleUnion value."""
    selector = union.selector()
    data = union.data()
    serialized = data.encode_bytes() if hasattr(data, "encode_bytes") else b""
    return bytes([selector]) + serialized


def _compatible_union_hash_tree_root(union: CompatibleUnion) -> bytes:
    """Hash tree root for a CompatibleUnion."""
    data = union.data()
    data_root = bytes(data.hash_tree_root()) if data is not None else ZERO_HASHES[0]
    selector = union.selector()
    selector_root = selector.to_bytes(32, "little")
    return _sha256(data_root + selector_root)


def _compatible_union_deserialize(cls: type, data_bytes: bytes) -> CompatibleUnion:
    """Deserialize a CompatibleUnion value."""
    selector = data_bytes[0]
    options = cls.options()
    value_type = options[selector]
    value_data = data_bytes[1:]
    value = value_type.decode_bytes(value_data)
    return cls(selector=selector, data=value)

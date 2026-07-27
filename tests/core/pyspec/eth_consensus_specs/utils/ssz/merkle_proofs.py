"""
Generalized indices and Merkle proofs for the SSZ type system.

``eth-ssz-specs`` computes hash tree roots but keeps no tree, and it offers no
way to address a nested field by generalized index. Both are needed by the
light-client specifications, so they are reconstructed here from the library's
own type metadata and merkleization rules.

The algorithms follow ``ssz/merkle-proofs.md``, extended to the progressive
shapes of EIP-7495 and EIP-7916.
"""

import math
from collections.abc import Sequence
from hashlib import sha256
from typing import Any

from ssz.bitfields import BaseBitlist, BaseBitvector, ProgressiveBitlist
from ssz.boolean import Boolean
from ssz.byte_arrays import BaseByteList, BaseBytes
from ssz.collections import List, ProgressiveList, Vector
from ssz.container import Container, ProgressiveContainer
from ssz.merkleization import (
    BITS_PER_CHUNK,
    BYTES_PER_CHUNK,
    Chunk,
    hash_tree_root,
    Root,
    ZERO_ROOT,
)
from ssz.ssz_base import SSZType
from ssz.uint import BaseUint, Uint8, Uint64
from ssz.union import CompatibleUnion

type GeneralizedIndex = int
type SSZVariableName = str

# Shapes whose root mixes in a trailing word, so the data lives in the left
# subtree and the mixed-in value in the right one.
_MIXED_IN = (BaseByteList, BaseBitlist, List, ProgressiveList, ProgressiveBitlist)

# Shapes whose data subtree is a progressive spine rather than a padded
# binary tree, so a position is not reachable by a fixed-depth descent.
_PROGRESSIVE = (ProgressiveList, ProgressiveBitlist, ProgressiveContainer)


def _next_pow2(x: int) -> int:
    return 1 if x <= 1 else 1 << (x - 1).bit_length()


def is_basic_type(typ: type[SSZType]) -> bool:
    """Whether values of this type are packed into chunks rather than merkleized."""
    return issubclass(typ, (BaseUint, Boolean))


def item_length(typ: type[SSZType]) -> int:
    """Number of bytes in a basic type, or 32 (a full hash) for compound types."""
    return typ.get_byte_length() if is_basic_type(typ) else BYTES_PER_CHUNK


def get_elem_type(
    typ: type[SSZType], index_or_variable_name: int | SSZVariableName
) -> type[SSZType]:
    """Type of the element reached by one step of a path."""
    if issubclass(typ, (Container, ProgressiveContainer)):
        return typ.model_fields[str(index_or_variable_name)].annotation
    if issubclass(typ, (BaseBytes, BaseByteList)):
        return Uint8
    if issubclass(typ, (BaseBitvector, BaseBitlist, ProgressiveBitlist)):
        return Boolean
    return typ.ELEMENT_TYPE


def chunk_count(typ: type[SSZType]) -> int:
    """Number of chunks the top-level elements of this type occupy."""
    if is_basic_type(typ):
        return 1
    if issubclass(typ, BaseBitvector):
        return math.ceil(typ.LENGTH / BITS_PER_CHUNK)
    if issubclass(typ, BaseBitlist):
        return math.ceil(typ.LIMIT / BITS_PER_CHUNK)
    if issubclass(typ, BaseBytes):
        return math.ceil(typ.LENGTH / BYTES_PER_CHUNK)
    if issubclass(typ, BaseByteList):
        return math.ceil(typ.LIMIT / BYTES_PER_CHUNK)
    if issubclass(typ, Vector):
        return math.ceil(typ.LENGTH * item_length(typ.ELEMENT_TYPE) / BYTES_PER_CHUNK)
    if issubclass(typ, List):
        return math.ceil(typ.LIMIT * item_length(typ.ELEMENT_TYPE) / BYTES_PER_CHUNK)
    if issubclass(typ, ProgressiveContainer):
        return len(typ.ACTIVE_FIELDS)
    if issubclass(typ, Container):
        return len(typ.model_fields)
    raise ValueError(f"Type not supported: {typ}")


def _chunk_position(typ: type[SSZType], index_or_variable_name: int | SSZVariableName) -> int:
    """Index of the chunk holding the given element or field."""
    if issubclass(typ, ProgressiveContainer):
        name = str(index_or_variable_name)
        field_index = list(typ.model_fields).index(name)
        # A field sits at the layout position of its own set bit, not at its
        # declaration index: a cleared position leaves a gap that holds the
        # remaining fields in place.
        active_positions = [i for i, bit in enumerate(typ.ACTIVE_FIELDS) if bit]
        return active_positions[field_index]
    if issubclass(typ, Container):
        return list(typ.model_fields).index(str(index_or_variable_name))
    if issubclass(typ, (BaseBitvector, BaseBitlist, ProgressiveBitlist)):
        return int(index_or_variable_name) // BITS_PER_CHUNK
    element_type = get_elem_type(typ, index_or_variable_name)
    return int(index_or_variable_name) * item_length(element_type) // BYTES_PER_CHUNK


def _progressive_index(root: GeneralizedIndex, chunk_index: int) -> GeneralizedIndex:
    """
    Generalized index of one chunk inside a progressive spine rooted at ``root``.

    The spine leans right: level n holds 4**(n-1) chunks in an ordinary binary
    subtree, and the level after it hangs off the right child. A chunk's
    position therefore depends only on its own index, never on how many
    chunks follow it.
    """
    successor = root
    capacity = 1
    start = 0
    while True:
        subtree = successor * 2
        successor = successor * 2 + 1
        if chunk_index < start + capacity:
            depth = capacity.bit_length() - 1
            return subtree * (1 << depth) + (chunk_index - start)
        start += capacity
        capacity *= 4


def get_generalized_index(ssz_class: Any, *path: int | SSZVariableName) -> GeneralizedIndex:
    """
    Convert a path into the generalized index of its position in the Merkle tree.

    For example ``[7, "foo", 3]`` addresses ``x[7].foo[3]``, and
    ``[12, "bar", "__len__"]`` addresses ``len(x[12].bar)``.
    """
    typ: type[SSZType] = ssz_class
    root: GeneralizedIndex = 1
    for p in path:
        # Descending into a basic type leaves nowhere further to go.
        assert not is_basic_type(typ)
        if p == "__len__":
            assert issubclass(typ, _MIXED_IN)
            typ = Uint64
            root = root * 2 + 1
        elif issubclass(typ, _PROGRESSIVE):
            # The data spine is the left child; the mixed-in word is the right.
            root = _progressive_index(root * 2, _chunk_position(typ, p))
            typ = get_elem_type(typ, p)
        else:
            base_index = 2 if issubclass(typ, _MIXED_IN) else 1
            root = root * base_index * _next_pow2(chunk_count(typ)) + _chunk_position(typ, p)
            typ = get_elem_type(typ, p)
    return root


class _Node:
    """A node of a materialized Merkle tree, kept only while a proof is built."""

    __slots__ = ("_root", "left", "right")

    def __init__(
        self, left: "_Node | None" = None, right: "_Node | None" = None, root: Root | None = None
    ) -> None:
        self.left = left
        self.right = right
        self._root = root

    @property
    def root(self) -> Root:
        if self._root is None:
            left, right = _children(self)
            self._root = Root(sha256(left.root + right.root).digest())
        return self._root


def _children(node: _Node) -> tuple[_Node, _Node]:
    """The two children of an internal node."""
    assert node.left is not None
    assert node.right is not None
    return node.left, node.right


def _leaf(root: Chunk) -> _Node:
    return _Node(root=Root(root))


_ZERO_SUBTREES: list[_Node] = [_leaf(ZERO_ROOT)]


def _zero_subtree(depth: int) -> _Node:
    """Root node of a perfect all-zero subtree of the given depth, memoized."""
    while len(_ZERO_SUBTREES) <= depth:
        previous = _ZERO_SUBTREES[-1]
        _ZERO_SUBTREES.append(_Node(previous, previous))
    return _ZERO_SUBTREES[depth]


def _zero_subtree_of_width(width: int) -> _Node:
    """Root node of an all-zero perfect tree holding ``width`` (a power of two) leaves."""
    return _zero_subtree(width.bit_length() - 1)


def _merkleize_tree(nodes: Sequence[_Node], limit: int | None = None) -> _Node:
    """Build a padded binary tree over the given nodes, mirroring ``merkleize``."""
    count = len(nodes)
    if count == 0:
        return _zero_subtree_of_width(_next_pow2(limit)) if limit is not None else _leaf(ZERO_ROOT)
    if limit is None:
        width = _next_pow2(count)
    else:
        assert limit >= count
        width = _next_pow2(limit)
    if width == 1:
        return nodes[0]

    # Walk one tree layer per iteration. A missing right sibling is the
    # all-zero subtree of the current size, so zero leaves are never built.
    level = list(nodes)
    subtree_size = 1
    while subtree_size < width:
        parents: list[_Node] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else _zero_subtree_of_width(subtree_size)
            parents.append(_Node(left, right))
        level = parents
        subtree_size *= 2
    assert len(level) == 1
    return level[0]


def _merkleize_progressive_tree(nodes: Sequence[_Node], num_leaves: int = 1) -> _Node:
    """Build a progressive spine over the given nodes, mirroring ``merkleize_progressive``."""
    if not nodes:
        return _leaf(ZERO_ROOT)
    subtree = _merkleize_tree(nodes[:num_leaves], limit=num_leaves)
    successor = _merkleize_progressive_tree(nodes[num_leaves:], num_leaves * 4)
    return _Node(subtree, successor)


def _pack_bytes_nodes(data: bytes) -> list[_Node]:
    return [
        _leaf(Chunk(data[i : i + BYTES_PER_CHUNK].ljust(BYTES_PER_CHUNK, b"\x00")))
        for i in range(0, len(data), BYTES_PER_CHUNK)
    ]


def _pack_bits_nodes(bits: Sequence[Boolean]) -> list[_Node]:
    packed = sum(1 << i for i, bit in enumerate(bits) if bit)
    return _pack_bytes_nodes(packed.to_bytes(math.ceil(len(bits) / 8), "little"))


def _length_leaf(length: int) -> _Node:
    return _leaf(Chunk(length.to_bytes(BYTES_PER_CHUNK, "little")))


def _element_nodes(value: Any) -> list[_Node]:
    """Data-subtree leaves of a sequence, packed for basic elements."""
    element_type = type(value).ELEMENT_TYPE
    if is_basic_type(element_type):
        return _pack_bytes_nodes(b"".join(e.encode_bytes() for e in value))
    return [_build_tree(e) for e in value]


def _build_tree(value: Any) -> _Node:
    """Materialize the full Merkle tree of an SSZ value."""
    if isinstance(value, (BaseUint, Boolean, BaseBytes)):
        return _merkleize_tree(_pack_bytes_nodes(value.encode_bytes()))

    if isinstance(value, BaseByteList):
        limit = math.ceil(type(value).LIMIT / BYTES_PER_CHUNK)
        data = _merkleize_tree(_pack_bytes_nodes(value.encode_bytes()), limit=limit)
        return _Node(data, _length_leaf(len(value.data)))

    if isinstance(value, BaseBitvector):
        limit = math.ceil(type(value).LENGTH / BITS_PER_CHUNK)
        return _merkleize_tree(_pack_bits_nodes(value.data), limit=limit)

    if isinstance(value, BaseBitlist):
        limit = math.ceil(type(value).LIMIT / BITS_PER_CHUNK)
        data = _merkleize_tree(_pack_bits_nodes(value.data), limit=limit)
        return _Node(data, _length_leaf(len(value.data)))

    if isinstance(value, ProgressiveBitlist):
        data = _merkleize_progressive_tree(_pack_bits_nodes(value.data))
        return _Node(data, _length_leaf(len(value.data)))

    if isinstance(value, Vector):
        cls = type(value)
        limit = (
            math.ceil(cls.LENGTH * item_length(cls.ELEMENT_TYPE) / BYTES_PER_CHUNK)
            if is_basic_type(cls.ELEMENT_TYPE)
            else cls.LENGTH
        )
        return _merkleize_tree(_element_nodes(value), limit=limit)

    if isinstance(value, List):
        cls = type(value)
        limit = (
            math.ceil(cls.LIMIT * item_length(cls.ELEMENT_TYPE) / BYTES_PER_CHUNK)
            if is_basic_type(cls.ELEMENT_TYPE)
            else cls.LIMIT
        )
        data = _merkleize_tree(_element_nodes(value), limit=limit)
        return _Node(data, _length_leaf(len(value)))

    if isinstance(value, ProgressiveList):
        data = _merkleize_progressive_tree(_element_nodes(value))
        return _Node(data, _length_leaf(len(value)))

    if isinstance(value, ProgressiveContainer):
        cls = type(value)
        leaves: list[_Node] = [_leaf(ZERO_ROOT)] * len(cls.ACTIVE_FIELDS)
        active_positions = (i for i, bit in enumerate(cls.ACTIVE_FIELDS) if bit)
        for position, name in zip(active_positions, cls.model_fields, strict=True):
            leaves[position] = _build_tree(getattr(value, name))
        packed = sum(1 << i for i, bit in enumerate(cls.ACTIVE_FIELDS) if bit)
        return _Node(_merkleize_progressive_tree(leaves), _length_leaf(packed))

    if isinstance(value, CompatibleUnion):
        return _Node(_build_tree(value.data), _length_leaf(int(value.selector)))

    if isinstance(value, Container):
        fields = [_build_tree(getattr(value, name)) for name in type(value).model_fields]
        return _merkleize_tree(fields)

    raise ValueError(f"Value not supported: {type(value).__name__}")


def compute_merkle_proof(obj: Any, index: GeneralizedIndex) -> list[Root]:
    """Merkle proof of the node at ``index``, ordered from the leaf upwards."""
    if index <= 1:
        return []
    tree = _build_tree(obj)
    # The bits of the index below its leading one spell the descent: 0 is left,
    # 1 is right. The sibling at each step is what the proof carries.
    depth = index.bit_length() - 1
    proof: list[Root] = []
    node = tree
    for level in range(depth - 1, -1, -1):
        left, right = _children(node)
        if (index >> level) & 1:
            proof.append(left.root)
            node = right
        else:
            proof.append(right.root)
            node = left
    return list(reversed(proof))


def build_proof(obj: Any, index: GeneralizedIndex) -> list[Root]:
    """Alias under the name the test helpers use."""
    return compute_merkle_proof(obj, index)


def get_node_root(obj: Any, index: GeneralizedIndex) -> Root:
    """Root of the subtree at ``index``, used to check a proof end to end."""
    tree = _build_tree(obj)
    for level in range(index.bit_length() - 2, -1, -1):
        left, right = _children(tree)
        tree = right if (index >> level) & 1 else left
    return tree.root


__all__ = [
    "GeneralizedIndex",
    "SSZVariableName",
    "build_proof",
    "chunk_count",
    "compute_merkle_proof",
    "get_elem_type",
    "get_generalized_index",
    "get_node_root",
    "hash_tree_root",
    "is_basic_type",
    "item_length",
]

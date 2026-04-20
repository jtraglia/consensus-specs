# Phase 0 -- Merkle Proofs

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Introduction](#introduction)
- [Constants](#constants)
- [Generalized-index helpers](#generalized-index-helpers)
  - [`get_power_of_two_ceil`](#get_power_of_two_ceil)
  - [`get_generalized_index_length`](#get_generalized_index_length)
  - [`get_generalized_index_bit`](#get_generalized_index_bit)
  - [`generalized_index_sibling`](#generalized_index_sibling)
  - [`generalized_index_child`](#generalized_index_child)
  - [`generalized_index_parent`](#generalized_index_parent)
- [Proof construction](#proof-construction)
  - [Layout helpers](#layout-helpers)
    - [`get_subtree_siblings`](#get_subtree_siblings)
    - [`get_container_leaves`](#get_container_leaves)
    - [`get_basic_vector_chunks`](#get_basic_vector_chunks)
    - [`get_basic_list_chunks`](#get_basic_list_chunks)
    - [`get_bitfield_chunks`](#get_bitfield_chunks)
    - [`get_byte_chunks`](#get_byte_chunks)
  - [Structural descent](#structural-descent)
    - [`descend_proof`](#descend_proof)
    - [`descend_container`](#descend_container)
    - [`descend_list`](#descend_list)
    - [`descend_vector`](#descend_vector)
    - [`descend_byte_vector`](#descend_byte_vector)
    - [`descend_byte_list`](#descend_byte_list)
    - [`descend_bitvector`](#descend_bitvector)
    - [`descend_bitlist`](#descend_bitlist)
  - [`build_proof`](#build_proof)
- [Proof verification](#proof-verification)
  - [`calculate_merkle_root`](#calculate_merkle_root)
  - [`verify_merkle_proof`](#verify_merkle_proof)

<!-- mdformat-toc end -->

## Introduction

This document is the executable Python specification of Merkle proof
construction and verification over SSZ values.

Proofs are computed against the implicit Merkle tree an SSZ value Merkleizes
to (see [`hash_tree_root`](../../ssz/simple-serialize.md#merkleization)). A
proof for a generalized index `gindex` consists of the sibling hashes along
the path from the root to the node at `gindex`, ordered from the deepest
sibling (closest to the target) up toward the root.

All functions below are pure and take SSZ values as arguments. Nothing here
maintains persistent tree state.

## Constants

A pre-computed list of zero-subtree roots is used to cheaply expand missing
nodes at any depth. `ZERO_HASHES[0]` is a 32-byte zero chunk; `ZERO_HASHES[d]`
is the root of a perfect binary tree of `2**d` zero chunks. It is imported
from the `ssz` package.

## Generalized-index helpers

### `get_power_of_two_ceil`

```python
def get_power_of_two_ceil(x: int) -> int:
    """
    Smallest power of two >= x, with x <= 1 mapping to 1.
    """
    if x <= 1:
        return 1
    return 1 << (x - 1).bit_length()
```

### `get_generalized_index_length`

```python
def get_generalized_index_length(index: int) -> int:
    """
    Return the depth of `index` in the implicit Merkle tree.
    """
    return index.bit_length() - 1
```

### `get_generalized_index_bit`

```python
def get_generalized_index_bit(index: int, position: int) -> bool:
    """
    Return the given bit of a generalized index (0 = least significant).
    """
    return (index & (1 << position)) > 0
```

### `generalized_index_sibling`

```python
def generalized_index_sibling(index: int) -> int:
    return index ^ 1
```

### `generalized_index_child`

```python
def generalized_index_child(index: int, right_side: bool) -> int:
    return index * 2 + (1 if right_side else 0)
```

### `generalized_index_parent`

```python
def generalized_index_parent(index: int) -> int:
    return index // 2
```

## Proof construction

### Layout helpers

These helpers materialize the leaf-chunk layer of each SSZ composite type's
Merkle subtree. They do not touch the tree above the leaves -- that is done
by [`get_subtree_siblings`](#get_subtree_siblings).

#### `get_subtree_siblings`

Given a power-of-two list of leaf hashes and a top-down bit path through the
subtree, return the list of sibling hashes along the path (bottom-up) and
the final leaf position the path lands on.

```python
def get_subtree_siblings(
    leaves: Sequence[bytes], bits: Sequence[int]
) -> Tuple[Sequence[bytes], int]:
    # Materialize all tree layers, bottom-up.
    levels: list[list[bytes]] = [list(leaves)]
    while len(levels[-1]) > 1:
        prev = levels[-1]
        levels.append(
            [hash(prev[i] + prev[i + 1]) for i in range(0, len(prev), 2)]
        )
    depth = len(levels) - 1
    assert len(bits) <= depth, "bit path exceeds tree depth"
    siblings_top_down: list[bytes] = []
    pos = 0
    for i, bit in enumerate(bits):
        below = levels[depth - i - 1]
        child_pos = pos * 2 + bit
        siblings_top_down.append(below[child_pos ^ 1])
        pos = child_pos
    # Return bottom-up: deepest sibling first.
    return list(reversed(siblings_top_down)), pos
```

#### `get_container_leaves`

```python
def get_container_leaves(value: Container) -> Sequence[bytes]:
    """
    Return the leaf layer for a Container: the hash_tree_root of each field,
    padded with zero chunks to the next power of two.
    """
    roots = [getattr(value, name).hash_tree_root() for name, _ in value._FIELDS]
    width = get_power_of_two_ceil(max(1, len(roots)))
    while len(roots) < width:
        roots.append(ZERO_HASHES[0])
    return roots
```

#### `get_basic_vector_chunks`

```python
def get_basic_vector_chunks(value: Vector) -> Sequence[bytes]:
    """
    Pack a Vector of basic elements into 32-byte chunks, right-padded, and
    extend to the next power of two.
    """
    joined = b"".join(e.encode_bytes() for e in value)
    padded = joined + b"\x00" * (-len(joined) % 32)
    chunks = [padded[i : i + 32] for i in range(0, len(padded), 32)]
    width = get_power_of_two_ceil(max(1, len(chunks)))
    while len(chunks) < width:
        chunks.append(ZERO_HASHES[0])
    return chunks
```

#### `get_basic_list_chunks`

```python
def get_basic_list_chunks(value: List) -> Sequence[bytes]:
    """
    Pack a List of basic elements into 32-byte chunks, right-padded, and
    extend to the next power of two of the List's chunk limit.
    """
    joined = b"".join(e.encode_bytes() for e in value)
    padded = joined + b"\x00" * (-len(joined) % 32)
    chunks = [padded[i : i + 32] for i in range(0, len(padded), 32)]
    basic_size = value.ELEMENT_TYPE.type_byte_length()
    chunk_limit = (value.LIMIT * basic_size + 31) // 32
    width = get_power_of_two_ceil(max(1, chunk_limit))
    while len(chunks) < width:
        chunks.append(ZERO_HASHES[0])
    return chunks
```

#### `get_bitfield_chunks`

```python
def get_bitfield_chunks(bits: Sequence[bool], chunk_limit: int) -> Sequence[bytes]:
    """
    Pack a sequence of bits into 32-byte chunks and extend to the next power
    of two of `chunk_limit`.
    """
    n = len(bits)
    packed = bytearray((n + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            packed[i >> 3] |= 1 << (i & 7)
    joined = bytes(packed) + b"\x00" * (-len(packed) % 32)
    chunks = [joined[i : i + 32] for i in range(0, len(joined), 32)]
    width = get_power_of_two_ceil(max(1, chunk_limit))
    while len(chunks) < width:
        chunks.append(ZERO_HASHES[0])
    return chunks
```

#### `get_byte_chunks`

```python
def get_byte_chunks(data: bytes, chunk_limit: int) -> Sequence[bytes]:
    """
    Pack raw bytes into 32-byte chunks and extend to the next power of two
    of `chunk_limit`.
    """
    padded = data + b"\x00" * (-len(data) % 32) if data else b""
    chunks = [padded[i : i + 32] for i in range(0, len(padded), 32)]
    width = get_power_of_two_ceil(max(1, chunk_limit))
    while len(chunks) < width:
        chunks.append(ZERO_HASHES[0])
    return chunks
```

### Structural descent

To build a proof for a generalized index `gindex` that addresses a deeply
nested value, we walk the type structure of the value from the outside in,
emitting siblings at each level. The bit path is the binary expansion of
`gindex` with the leading `1` stripped, read top-down.

#### `descend_proof`

```python
def descend_proof(value: SszObject, bits: Sequence[int]) -> Sequence[bytes]:
    if len(bits) == 0:
        return []
    if isinstance(value, Container):
        return descend_container(value, bits)
    if isinstance(value, List):
        return descend_list(value, bits)
    if isinstance(value, Vector):
        return descend_vector(value, bits)
    if isinstance(value, ByteList):
        return descend_byte_list(value, bits)
    if isinstance(value, ByteVector):
        return descend_byte_vector(value, bits)
    if isinstance(value, Bitlist):
        return descend_bitlist(value, bits)
    if isinstance(value, Bitvector):
        return descend_bitvector(value, bits)
    raise TypeError(f"cannot descend proof through {type(value).__name__}")
```

#### `descend_container`

```python
def descend_container(value: Container, bits: Sequence[int]) -> Sequence[bytes]:
    fields = [getattr(value, name) for name, _ in value._FIELDS]
    num_fields = len(fields)
    # A 1-field Container's root IS the field's root (no wrapping tree level).
    if num_fields == 1:
        return descend_proof(fields[0], bits)
    width = get_power_of_two_ceil(num_fields)
    depth = width.bit_length() - 1
    container_bits = list(bits[:depth])
    remaining = list(bits[depth:])
    leaves = get_container_leaves(value)
    siblings, leaf_idx = get_subtree_siblings(leaves, container_bits)
    if len(remaining) > 0:
        assert leaf_idx < num_fields, "gindex addresses a padded field slot"
        return list(descend_proof(fields[leaf_idx], remaining)) + list(siblings)
    return list(siblings)
```

#### `descend_list`

```python
def descend_list(value: List, bits: Sequence[int]) -> Sequence[bytes]:
    # A List root is hash(contents_root, length_leaf).
    # bit 0 -> contents subtree; bit 1 -> length leaf.
    if bits[0] == 1:
        assert len(bits) == 1, "gindex descends past length leaf"
        return [hash_tree_root_contents_only(value)]
    length_leaf = len(value).to_bytes(32, "little")
    contents_bits = list(bits[1:])
    elem_type = value.ELEMENT_TYPE
    if issubclass(elem_type, (uintN, boolean)):
        chunks = list(get_basic_list_chunks(value))
        siblings, _ = get_subtree_siblings(chunks, contents_bits)
        return list(siblings) + [length_leaf]
    width = get_power_of_two_ceil(max(1, value.LIMIT))
    depth = width.bit_length() - 1
    inner_bits = contents_bits[:depth]
    remaining = contents_bits[depth:]
    roots = [e.hash_tree_root() for e in value]
    while len(roots) < width:
        roots.append(ZERO_HASHES[0])
    siblings, idx = get_subtree_siblings(roots, inner_bits)
    if len(remaining) > 0:
        assert idx < len(value), "gindex addresses a padded list slot"
        return list(descend_proof(value[idx], remaining)) + list(siblings) + [length_leaf]
    return list(siblings) + [length_leaf]
```

The helper `hash_tree_root_contents_only` computes the contents-subtree root
of a list (without the length mix-in), needed only as the sibling when the
caller requests the length leaf itself:

```python
def hash_tree_root_contents_only(value: List) -> bytes:
    elem_type = value.ELEMENT_TYPE
    if issubclass(elem_type, (uintN, boolean)):
        basic_size = elem_type.type_byte_length()
        chunk_limit = (value.LIMIT * basic_size + 31) // 32
        joined = b"".join(e.encode_bytes() for e in value)
        padded = joined + b"\x00" * (-len(joined) % 32)
        chunks = [padded[i : i + 32] for i in range(0, len(padded), 32)]
    else:
        chunks = [e.hash_tree_root() for e in value]
        chunk_limit = value.LIMIT
    return _merkleize_chunks(chunks, chunk_limit)
```

```python
def _merkleize_chunks(chunks: Sequence[bytes], limit: int) -> bytes:
    """
    Merkleize `chunks` padded with zero chunks to `next_pow_of_two(limit)`.
    """
    assert limit >= len(chunks), "chunk count exceeds limit"
    width = get_power_of_two_ceil(max(1, limit))
    if len(chunks) == 0:
        return ZERO_HASHES[max(0, width.bit_length() - 1)]
    if width == 1:
        return bytes(chunks[0])
    layer = list(chunks)
    depth = 0
    while (1 << depth) < width:
        if len(layer) % 2 == 1:
            layer.append(ZERO_HASHES[depth])
        layer = [hash(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
        depth += 1
        while len(layer) == 1 and (1 << depth) < width:
            layer = [hash(layer[0] + ZERO_HASHES[depth])]
            depth += 1
    return layer[0]
```

#### `descend_vector`

```python
def descend_vector(value: Vector, bits: Sequence[int]) -> Sequence[bytes]:
    length = value.LENGTH
    elem_type = value.ELEMENT_TYPE
    if issubclass(elem_type, (uintN, boolean)):
        chunks = list(get_basic_vector_chunks(value))
        siblings, _ = get_subtree_siblings(chunks, list(bits))
        return list(siblings)
    width = get_power_of_two_ceil(max(1, length))
    depth = width.bit_length() - 1
    inner_bits = list(bits[:depth])
    remaining = list(bits[depth:])
    roots = [e.hash_tree_root() for e in value]
    while len(roots) < width:
        roots.append(ZERO_HASHES[0])
    siblings, idx = get_subtree_siblings(roots, inner_bits)
    if len(remaining) > 0:
        assert idx < length, "gindex addresses a padded vector slot"
        return list(descend_proof(value[idx], remaining)) + list(siblings)
    return list(siblings)
```

#### `descend_byte_vector`

```python
def descend_byte_vector(value: ByteVector, bits: Sequence[int]) -> Sequence[bytes]:
    chunk_count = (value.LENGTH + 31) // 32
    chunks = list(get_byte_chunks(bytes(value), chunk_count))
    siblings, _ = get_subtree_siblings(chunks, list(bits))
    return list(siblings)
```

#### `descend_byte_list`

```python
def descend_byte_list(value: ByteList, bits: Sequence[int]) -> Sequence[bytes]:
    if bits[0] == 1:
        assert len(bits) == 1, "gindex descends past length leaf"
        chunk_limit = (value.LIMIT + 31) // 32
        joined = bytes(value) + b"\x00" * (-len(value) % 32) if len(value) > 0 else b""
        chunks = [joined[i : i + 32] for i in range(0, len(joined), 32)]
        return [_merkleize_chunks(chunks, chunk_limit)]
    length_leaf = len(value).to_bytes(32, "little")
    chunk_limit = (value.LIMIT + 31) // 32
    chunks = list(get_byte_chunks(bytes(value), chunk_limit))
    siblings, _ = get_subtree_siblings(chunks, list(bits[1:]))
    return list(siblings) + [length_leaf]
```

#### `descend_bitvector`

```python
def descend_bitvector(value: Bitvector, bits: Sequence[int]) -> Sequence[bytes]:
    chunk_count = (value.LENGTH + 255) // 256
    chunks = list(get_bitfield_chunks(list(value), chunk_count))
    siblings, _ = get_subtree_siblings(chunks, list(bits))
    return list(siblings)
```

#### `descend_bitlist`

```python
def descend_bitlist(value: Bitlist, bits: Sequence[int]) -> Sequence[bytes]:
    if bits[0] == 1:
        assert len(bits) == 1, "gindex descends past length leaf"
        chunk_limit = (value.LIMIT + 255) // 256
        # Only `chunk_limit` chunks of the bit-packed payload (length excluded).
        chunks = list(get_bitfield_chunks(list(value), chunk_limit))
        return [_merkleize_chunks(chunks, chunk_limit)]
    length_leaf = len(value).to_bytes(32, "little")
    chunk_limit = (value.LIMIT + 255) // 256
    chunks = list(get_bitfield_chunks(list(value), chunk_limit))
    siblings, _ = get_subtree_siblings(chunks, list(bits[1:]))
    return list(siblings) + [length_leaf]
```

### `build_proof`

```python
def build_proof(anchor: SszObject, gindex: int) -> Sequence[bytes]:
    """
    Build the Merkle proof for the node at `gindex` in `anchor`'s hash tree.
    Returns the siblings ordered leaf-closest-first.
    """
    if gindex == 1:
        return []
    # Extract bit path: binary of gindex without leading 1, MSB-first.
    bits: list[int] = []
    g = gindex
    while g > 1:
        bits.append(g & 1)
        g >>= 1
    bits.reverse()
    return descend_proof(anchor, bits)
```

## Proof verification

Given a leaf hash, a generalized index, and the proof returned by
[`build_proof`](#build_proof), reconstruct the tree root and check it against
an expected root.

### `calculate_merkle_root`

```python
def calculate_merkle_root(leaf: bytes, proof: Sequence[bytes], index: int) -> bytes:
    assert len(proof) == get_generalized_index_length(index)
    node = leaf
    for i, sibling in enumerate(proof):
        if get_generalized_index_bit(index, i):
            node = hash(sibling + node)
        else:
            node = hash(node + sibling)
    return node
```

### `verify_merkle_proof`

```python
def verify_merkle_proof(leaf: bytes, proof: Sequence[bytes], index: int, root: bytes) -> bool:
    return calculate_merkle_root(leaf, proof, index) == root
```

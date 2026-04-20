# Phase 0 -- Merkle Proofs

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Introduction](#introduction)
- [Generalized-index helpers](#generalized-index-helpers)
  - [`get_generalized_index_length`](#get_generalized_index_length)
  - [`get_generalized_index_bit`](#get_generalized_index_bit)
  - [`generalized_index_sibling`](#generalized_index_sibling)
  - [`generalized_index_child`](#generalized_index_child)
  - [`generalized_index_parent`](#generalized_index_parent)
- [Type introspection](#type-introspection)
  - [`zero_hash`](#zero_hash)
  - [`item_length`](#item_length)
  - [`chunk_count`](#chunk_count)
  - [`get_field_type`](#get_field_type)
  - [`get_item_position`](#get_item_position)
- [`get_generalized_index`](#get_generalized_index)
- [Proof construction](#proof-construction)
  - [Leaf layout](#leaf-layout)
    - [`get_subtree_siblings`](#get_subtree_siblings)
    - [`get_container_leaves`](#get_container_leaves)
    - [`get_basic_vector_chunks`](#get_basic_vector_chunks)
    - [`get_basic_list_chunks`](#get_basic_list_chunks)
    - [`get_bitfield_chunks`](#get_bitfield_chunks)
    - [`get_byte_chunks`](#get_byte_chunks)
    - [`merkleize_chunks`](#merkleize_chunks)
    - [`list_contents_root`](#list_contents_root)
  - [Structural descent](#structural-descent)
    - [`descend_proof`](#descend_proof)
    - [`descend_container`](#descend_container)
    - [`descend_list`](#descend_list)
    - [`descend_vector`](#descend_vector)
    - [`descend_byte_vector`](#descend_byte_vector)
    - [`descend_byte_list`](#descend_byte_list)
    - [`descend_bitvector`](#descend_bitvector)
    - [`descend_bitlist`](#descend_bitlist)
  - [`compute_merkle_proof`](#compute_merkle_proof)
- [Proof verification](#proof-verification)
  - [`calculate_merkle_root`](#calculate_merkle_root)
  - [`verify_merkle_proof`](#verify_merkle_proof)

<!-- mdformat-toc end -->

## Introduction

This document is the executable Python specification of Merkle proofs over
SSZ values. Two independent pieces live here:

1. **Generalized-index computation** -- `get_generalized_index(typ, *path)`
   produces the generalized index (a 1-based node position in the implicit
   Merkle tree) for a nested access path like
   `get_generalized_index(BeaconState, "finalized_checkpoint", "root")`.

2. **Proof construction and verification** -- `compute_merkle_proof(value,
   gindex)` builds the list of sibling hashes from the leaf at `gindex` up
   to the root; `verify_merkle_proof(leaf, proof, gindex, root)` checks it.

Everything is a pure function. SSZ types are imported from the `ssz`
package; nothing here carries state across calls.

## Generalized-index helpers

### `get_generalized_index_length`

```python
def get_generalized_index_length(index: int) -> int:
    """
    Return the depth of ``index`` in the implicit Merkle tree.
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

## Type introspection

These helpers compute layout properties of SSZ types that both generalized-
index computation and proof construction depend on.

### `zero_hash`

```python
def zero_hash(depth: int) -> bytes:
    """
    Root of a perfect binary tree of ``2**depth`` zero chunks.
    """
    h = b"\x00" * 32
    for _ in range(depth):
        h = hash(h + h)
    return h
```

### `item_length`

```python
def item_length(typ: Type[SszObject]) -> int:
    """
    Byte length of a basic element, or 32 (a full chunk) for composite
    elements packed one per chunk.
    """
    if issubclass(typ, (uintN, boolean)):
        return typ.type_byte_length()
    return 32
```

### `chunk_count`

```python
def chunk_count(typ: Type[SszObject]) -> int:
    """
    Number of 32-byte chunks in the leaf layer of ``typ``'s Merkle tree.
    """
    if issubclass(typ, (uintN, boolean)):
        return 1
    if issubclass(typ, Bitvector):
        return (typ.LENGTH + 255) // 256
    if issubclass(typ, Bitlist):
        return (typ.LIMIT + 255) // 256
    if issubclass(typ, ByteVector):
        return (typ.LENGTH + 31) // 32
    if issubclass(typ, ByteList):
        return (typ.LIMIT + 31) // 32
    if issubclass(typ, Vector):
        return (typ.LENGTH * item_length(typ.ELEMENT_TYPE) + 31) // 32
    if issubclass(typ, List):
        return (typ.LIMIT * item_length(typ.ELEMENT_TYPE) + 31) // 32
    if issubclass(typ, Container):
        return len(typ._FIELDS)
    raise Exception(f"chunk_count: unsupported type {typ}")
```

### `get_field_type`

```python
def get_field_type(
    typ: Type[SszObject], index_or_name
) -> Type[SszObject]:
    """
    Return the type of the child reached by ``index_or_name``:
    a field type for Containers, the element type otherwise.
    """
    if issubclass(typ, Container):
        for name, field_type in typ._FIELDS:
            if name == index_or_name:
                return field_type
        raise KeyError(f"field {index_or_name!r} not in {typ.__name__}")
    return typ.ELEMENT_TYPE
```

### `get_item_position`

```python
def get_item_position(
    typ: Type[SszObject], index_or_name
) -> Tuple[int, int, int]:
    """
    Return ``(chunk_index, start_byte, end_byte)`` locating the child
    within ``typ``'s leaf layer. For composite element types the child
    occupies a full chunk (start=0, end=32).
    """
    if issubclass(typ, Container):
        names = [n for n, _ in typ._FIELDS]
        pos = names.index(index_or_name)
        return pos, 0, item_length(get_field_type(typ, index_or_name))
    if issubclass(typ, (Vector, List)):
        idx = int(index_or_name)
        size = item_length(typ.ELEMENT_TYPE)
        start = idx * size
        return start // 32, start % 32, start % 32 + size
    if issubclass(typ, (Bitvector, Bitlist, ByteVector, ByteList)):
        idx = int(index_or_name)
        size = 1 if issubclass(typ, (ByteVector, ByteList)) else 1
        # Bitfields pack 256 bits per chunk; byte arrays pack 32 bytes per chunk.
        per_chunk = 256 if issubclass(typ, (Bitvector, Bitlist)) else 32
        return idx // per_chunk, 0, size
    raise Exception(f"get_item_position: unsupported type {typ}")
```

## `get_generalized_index`

```python
def get_generalized_index(typ: Type[SszObject], *path) -> int:
    """
    Convert a path like ``("finalized_checkpoint", "root")`` or
    ``("blob_kzg_commitments", 7)`` into the generalized index for that
    position in ``typ``'s Merkle tree.

    A path element of ``"__len__"`` targets the length leaf of a List or
    Bitlist.
    """
    root = 1
    for p in path:
        assert not issubclass(typ, (uintN, boolean)), (
            "cannot descend past a basic type"
        )
        if p == "__len__":
            assert issubclass(typ, (List, Bitlist, ByteList)), (
                "__len__ is only valid on variable-length types"
            )
            typ = uint64
            root = root * 2 + 1
        else:
            pos, _, _ = get_item_position(typ, p)
            base = 2 if issubclass(typ, (List, Bitlist, ByteList)) else 1
            root = root * base * get_power_of_two_ceil(chunk_count(typ)) + pos
            typ = get_field_type(typ, p)
    return root
```

## Proof construction

To build a proof for a generalized index `gindex` that addresses a deeply
nested value, we walk the value from the outside in, emitting sibling
hashes at each level. The bit path is the binary expansion of `gindex`
with the leading `1` stripped, read top-down.

### Leaf layout

#### `get_subtree_siblings`

```python
def get_subtree_siblings(
    leaves: Sequence[bytes], bits: Sequence[int]
) -> Tuple[Sequence[bytes], int]:
    """
    Given a power-of-two sequence of leaf hashes and a top-down bit path,
    return ``(siblings_bottom_up, final_position)``. ``final_position`` is
    the leaf (or internal-node) index the path lands on.
    """
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
        child = pos * 2 + bit
        siblings_top_down.append(below[child ^ 1])
        pos = child
    return list(reversed(siblings_top_down)), pos
```

#### `get_container_leaves`

```python
def get_container_leaves(value: Container) -> Sequence[bytes]:
    roots = [getattr(value, name).hash_tree_root() for name, _ in value._FIELDS]
    width = get_power_of_two_ceil(max(1, len(roots)))
    while len(roots) < width:
        roots.append(zero_hash(0))
    return roots
```

#### `get_basic_vector_chunks`

```python
def get_basic_vector_chunks(value: Vector) -> Sequence[bytes]:
    joined = b"".join(e.encode_bytes() for e in value)
    padded = joined + b"\x00" * (-len(joined) % 32)
    chunks = [padded[i : i + 32] for i in range(0, len(padded), 32)]
    width = get_power_of_two_ceil(max(1, len(chunks)))
    while len(chunks) < width:
        chunks.append(zero_hash(0))
    return chunks
```

#### `get_basic_list_chunks`

```python
def get_basic_list_chunks(value: List) -> Sequence[bytes]:
    joined = b"".join(e.encode_bytes() for e in value)
    padded = joined + b"\x00" * (-len(joined) % 32)
    chunks = [padded[i : i + 32] for i in range(0, len(padded), 32)]
    basic_size = value.ELEMENT_TYPE.type_byte_length()
    chunk_limit = (value.LIMIT * basic_size + 31) // 32
    width = get_power_of_two_ceil(max(1, chunk_limit))
    while len(chunks) < width:
        chunks.append(zero_hash(0))
    return chunks
```

#### `get_bitfield_chunks`

```python
def get_bitfield_chunks(bits: Sequence[bool], chunk_limit: int) -> Sequence[bytes]:
    n = len(bits)
    packed = bytearray((n + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            packed[i >> 3] |= 1 << (i & 7)
    joined = bytes(packed) + b"\x00" * (-len(packed) % 32)
    chunks = [joined[i : i + 32] for i in range(0, len(joined), 32)]
    width = get_power_of_two_ceil(max(1, chunk_limit))
    while len(chunks) < width:
        chunks.append(zero_hash(0))
    return chunks
```

#### `get_byte_chunks`

```python
def get_byte_chunks(data: bytes, chunk_limit: int) -> Sequence[bytes]:
    padded = data + b"\x00" * (-len(data) % 32) if data else b""
    chunks = [padded[i : i + 32] for i in range(0, len(padded), 32)]
    width = get_power_of_two_ceil(max(1, chunk_limit))
    while len(chunks) < width:
        chunks.append(zero_hash(0))
    return chunks
```

#### `merkleize_chunks`

```python
def merkleize_chunks(chunks: Sequence[bytes], limit: int) -> bytes:
    """
    Merkleize ``chunks`` padded with zero chunks to ``next_pow_of_two(limit)``.
    """
    assert limit >= len(chunks), "chunk count exceeds limit"
    width = get_power_of_two_ceil(max(1, limit))
    if len(chunks) == 0:
        return zero_hash(max(0, width.bit_length() - 1))
    if width == 1:
        return bytes(chunks[0])
    layer = list(chunks)
    depth = 0
    while (1 << depth) < width:
        if len(layer) % 2 == 1:
            layer.append(zero_hash(depth))
        layer = [hash(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
        depth += 1
        while len(layer) == 1 and (1 << depth) < width:
            layer = [hash(layer[0] + zero_hash(depth))]
            depth += 1
    return layer[0]
```

#### `list_contents_root`

```python
def list_contents_root(value: List) -> bytes:
    """
    Merkle root of a List's contents subtree, excluding the length mix-in.
    Used only as a sibling when a caller requests the length leaf itself.
    """
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
    return merkleize_chunks(chunks, chunk_limit)
```

### Structural descent

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
        return [list_contents_root(value)]
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
        roots.append(zero_hash(0))
    siblings, idx = get_subtree_siblings(roots, inner_bits)
    if len(remaining) > 0:
        assert idx < len(value), "gindex addresses a padded list slot"
        return list(descend_proof(value[idx], remaining)) + list(siblings) + [length_leaf]
    return list(siblings) + [length_leaf]
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
        roots.append(zero_hash(0))
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
        return [merkleize_chunks(chunks, chunk_limit)]
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
        chunks = list(get_bitfield_chunks(list(value), chunk_limit))
        return [merkleize_chunks(chunks, chunk_limit)]
    length_leaf = len(value).to_bytes(32, "little")
    chunk_limit = (value.LIMIT + 255) // 256
    chunks = list(get_bitfield_chunks(list(value), chunk_limit))
    siblings, _ = get_subtree_siblings(chunks, list(bits[1:]))
    return list(siblings) + [length_leaf]
```

### `compute_merkle_proof`

```python
def compute_merkle_proof(value: SszObject, gindex: int) -> Sequence[bytes]:
    """
    Build the Merkle proof for the node at ``gindex`` in ``value``'s hash
    tree. Returns siblings ordered leaf-closest-first.
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
    return descend_proof(value, bits)
```

## Proof verification

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

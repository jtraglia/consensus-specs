from collections.abc import Iterator


def gindex_bit_iter(gindex: int) -> tuple[Iterator[bool], int]:
    """Iterate the path bits of a generalized index, from the root down to the leaf."""
    gindex = int(gindex)
    if gindex < 1:
        raise Exception(f"invalid gindex: {gindex}")
    bit_len = gindex.bit_length()

    def iter_bits() -> Iterator[bool]:
        if bit_len <= 1:
            return
        shift_v = 1 << (bit_len - 2)
        while shift_v != 0:
            yield (gindex & shift_v) != 0
            shift_v >>= 1

    return iter_bits(), bit_len - 1


def build_proof(anchor, leaf_index):
    if leaf_index <= 1:
        return []  # Nothing to prove / invalid index
    node = anchor
    proof = []
    # Walk down, top to bottom to the leaf
    bit_iter, _ = gindex_bit_iter(leaf_index)
    for bit in bit_iter:
        # Always take the opposite hand for the proof.
        # 1 = right as leaf, thus get left
        if bit:
            proof.append(node.get_left().merkle_root())
            node = node.get_right()
        else:
            proof.append(node.get_right().merkle_root())
            node = node.get_left()

    return list(reversed(proof))

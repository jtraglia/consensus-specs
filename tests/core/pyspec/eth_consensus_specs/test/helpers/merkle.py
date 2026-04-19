"""Merkle proof helpers.

Remerkleable maintained a persistent node-tree backing for every value, so
proofs could be built by walking down the tree. The ``ssz`` package uses a
stateless, value-native Merkleization and does not yet expose a proof API.

This module is a placeholder: call sites that need real proofs (altair light
client generators) will fail loudly until a proof builder is ported.
"""


def build_proof(anchor, leaf_index):
    raise NotImplementedError(
        "build_proof has not been ported to the ssz package; "
        "tree-backed proof construction is pending"
    )

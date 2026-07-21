from eth_consensus_specs.test.context import (
    spec_state_test,
    with_all_phases_from_to,
    with_test_suite_name,
)
from eth_consensus_specs.test.helpers.attestations import (
    state_transition_with_full_block,
)
from eth_consensus_specs.test.helpers.constants import (
    CAPELLA,
    GLOAS,
)
from eth_consensus_specs.utils.ssz.ssz_impl import hash_tree_root


@with_test_suite_name("BeaconBlockBody")
@with_all_phases_from_to(CAPELLA, GLOAS)
@spec_state_test
def test_execution_merkle_proof(spec, state):
    block = state_transition_with_full_block(
        spec, state, fill_cur_epoch=True, fill_prev_epoch=False
    )

    yield "object", block.message.body
    gindex = spec.EXECUTION_PAYLOAD_GINDEX
    branch = spec.compute_merkle_proof(block.message.body, gindex)
    yield (
        "proof",
        {
            "leaf": "0x" + hash_tree_root(block.message.body.execution_payload).hex(),
            "leaf_index": gindex,
            "branch": ["0x" + root.hex() for root in branch],
        },
    )
    assert spec.is_valid_merkle_branch(
        leaf=hash_tree_root(block.message.body.execution_payload),
        branch=branch,
        depth=spec.floorlog2(gindex),
        index=spec.get_subtree_index(gindex),
        root=hash_tree_root(block.message.body),
    )

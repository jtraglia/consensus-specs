from eth_utils import encode_hex

from eth2spec.test.helpers.forks import (
    is_post_altair,
    is_post_capella,
    is_post_deneb,
)


def get_seen(spec):
    """Create an empty Seen object for gossip validation."""
    kwargs = dict(
        proposer_slots=set(),
        aggregator_epochs=set(),
        aggregate_data_roots={},
        voluntary_exit_indices=set(),
        proposer_slashing_indices=set(),
        attester_slashing_indices=set(),
        attestation_validator_epochs=set(),
    )
    # Add altair fields if available
    if is_post_altair(spec):
        kwargs.update(
            sync_contribution_aggregator_slots=set(),
            sync_contribution_data={},
            sync_message_validator_slots=set(),
        )
    # Add capella fields if available
    if is_post_capella(spec):
        kwargs.update(
            bls_to_execution_change_indices=set(),
        )
    # Add deneb fields if available
    if is_post_deneb(spec):
        kwargs.update(
            blob_sidecar_slots=set(),
        )
    return spec.Seen(**kwargs)


def get_filename(obj):
    """Get a filename for an SSZ object based on its type."""
    class_name = obj.__class__.__name__

    # Map class names to filename prefixes
    if "BeaconBlock" in class_name:
        prefix = "block"
    elif class_name == "Attestation":
        prefix = "attestation"
    elif "AggregateAndProof" in class_name:
        prefix = "aggregate"
    elif class_name == "ProposerSlashing":
        prefix = "proposer_slashing"
    elif class_name == "AttesterSlashing":
        prefix = "attester_slashing"
    elif "VoluntaryExit" in class_name:
        prefix = "voluntary_exit"
    elif "ContributionAndProof" in class_name:
        prefix = "contribution"
    elif class_name == "SyncCommitteeMessage":
        prefix = "sync_committee_message"
    elif class_name == "BLSToExecutionChange":
        prefix = "bls_to_execution_change"
    elif class_name == "BlobSidecar":
        prefix = "blob_sidecar"
    else:
        raise Exception(f"unsupported type: {class_name}")

    return f"{prefix}_{encode_hex(obj.hash_tree_root())}"

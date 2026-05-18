# Electra -- Networking

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Introduction](#introduction)
- [Modifications in Electra](#modifications-in-electra)
  - [Configuration](#configuration)
  - [Helpers](#helpers)
    - [Modified `Seen`](#modified-seen)
    - [Modified `compute_fork_version`](#modified-compute_fork_version)
    - [Modified `compute_max_request_blob_sidecars`](#modified-compute_max_request_blob_sidecars)
  - [The gossip domain: gossipsub](#the-gossip-domain-gossipsub)
    - [Topics and messages](#topics-and-messages)
      - [Global topics](#global-topics)
        - [`beacon_block`](#beacon_block)
        - [`beacon_aggregate_and_proof`](#beacon_aggregate_and_proof)
        - [`attester_slashing`](#attester_slashing)
        - [`blob_sidecar_{subnet_id}`](#blob_sidecar_subnet_id)
      - [Attestation subnets](#attestation-subnets)
        - [`beacon_attestation_{subnet_id}`](#beacon_attestation_subnet_id)
  - [The Req/Resp domain](#the-reqresp-domain)
    - [Messages](#messages)
      - [BeaconBlocksByRange v2](#beaconblocksbyrange-v2)
      - [BeaconBlocksByRoot v2](#beaconblocksbyroot-v2)
      - [BlobSidecarsByRange v1](#blobsidecarsbyrange-v1)
      - [BlobSidecarsByRoot v1](#blobsidecarsbyroot-v1)

<!-- mdformat-toc end -->

## Introduction

This document contains the consensus-layer networking specifications for
Electra.

The specification of these changes continues in the same format as the network
specifications of previous upgrades, and assumes them as pre-requisite.

## Modifications in Electra

### Configuration

*[New in Electra:EIP7691]*

| Name                                | Value | Description                                                       |
| ----------------------------------- | ----- | ----------------------------------------------------------------- |
| `BLOB_SIDECAR_SUBNET_COUNT_ELECTRA` | `9`   | The number of blob sidecar subnets used in the gossipsub protocol |

### Helpers

#### Modified `Seen`

```python
@dataclass
class Seen(object):
    proposer_slots: Set[Tuple[ValidatorIndex, Slot]]
    aggregator_epochs: Set[Tuple[ValidatorIndex, Epoch]]
    # [Modified in Electra:EIP7549]
    aggregate_data_roots: Dict[Tuple[Root, CommitteeIndex], Set[Tuple[boolean, ...]]]
    voluntary_exit_indices: Set[ValidatorIndex]
    proposer_slashing_indices: Set[ValidatorIndex]
    attester_slashing_indices: Set[ValidatorIndex]
    attestation_validator_epochs: Set[Tuple[ValidatorIndex, Epoch]]
    sync_contribution_aggregator_slots: Set[Tuple[ValidatorIndex, Slot, uint64]]
    sync_contribution_data: Dict[Tuple[Slot, Root, uint64], Set[Tuple[boolean, ...]]]
    sync_message_validator_slots: Set[Tuple[Slot, ValidatorIndex, uint64]]
    bls_to_execution_change_indices: Set[ValidatorIndex]
    blob_sidecar_tuples: Set[Tuple[Slot, ValidatorIndex, BlobIndex]]
```

#### Modified `compute_fork_version`

```python
def compute_fork_version(epoch: Epoch) -> Version:
    """
    Return the fork version at the given ``epoch``.
    """
    if epoch >= ELECTRA_FORK_EPOCH:
        return ELECTRA_FORK_VERSION
    if epoch >= DENEB_FORK_EPOCH:
        return DENEB_FORK_VERSION
    if epoch >= CAPELLA_FORK_EPOCH:
        return CAPELLA_FORK_VERSION
    if epoch >= BELLATRIX_FORK_EPOCH:
        return BELLATRIX_FORK_VERSION
    if epoch >= ALTAIR_FORK_EPOCH:
        return ALTAIR_FORK_VERSION
    return GENESIS_FORK_VERSION
```

#### Modified `compute_max_request_blob_sidecars`

```python
def compute_max_request_blob_sidecars() -> uint64:
    """
    Return the maximum number of blob sidecars in a single request.
    """
    # [Modified in Electra:EIP7691]
    return uint64(MAX_REQUEST_BLOCKS_DENEB * MAX_BLOBS_PER_BLOCK_ELECTRA)
```

### The gossip domain: gossipsub

Some gossip meshes are upgraded in Electra to support upgraded types.

#### Topics and messages

Topics follow the same specification as in prior upgrades.

The `beacon_block` topic is modified to also support Electra blocks.

The `beacon_aggregate_and_proof` and `beacon_attestation_{subnet_id}` topics are
modified to support the gossip of the new attestation type.

The `attester_slashing` topic is modified to support the gossip of the new
`AttesterSlashing` type.

The specification around the creation, validation, and dissemination of messages
has not changed from the Deneb document unless explicitly noted here.

The derivation of the `message-id` remains stable.

##### Global topics

###### `beacon_block`

*Note*: This function is modified per EIP-7691. The block's KZG commitment count
is bounded by `MAX_BLOBS_PER_BLOCK_ELECTRA`.

```python
def validate_beacon_block_gossip(
    seen: Seen,
    store: Store,
    state: BeaconState,
    signed_beacon_block: SignedBeaconBlock,
    current_time_ms: uint64,
    block_payload_statuses: Dict[Root, PayloadValidationStatus] = {},
) -> None:
    """
    Validate a SignedBeaconBlock for gossip propagation.
    Raises GossipIgnore or GossipReject on validation failure.
    """
    block = signed_beacon_block.message
    execution_payload = block.body.execution_payload

    # [IGNORE] The block is not from a future slot
    # (MAY be queued for processing at the appropriate slot)
    if not is_not_from_future_slot(state, block.slot, current_time_ms):
        raise GossipIgnore(BeaconBlockGossipError.BLOCK_FROM_FUTURE_SLOT)

    # [IGNORE] The block is from a slot greater than the latest finalized slot
    # (MAY choose to validate and store such blocks for additional purposes
    # -- e.g. slashing detection, archive nodes, etc)
    finalized_slot = compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)
    if block.slot <= finalized_slot:
        raise GossipIgnore(BeaconBlockGossipError.BLOCK_NOT_AFTER_FINALIZED)

    # [IGNORE] The block is the first block with valid signature received for
    # the proposer for the slot
    if (block.proposer_index, block.slot) in seen.proposer_slots:
        raise GossipIgnore(BeaconBlockGossipError.BLOCK_ALREADY_SEEN)

    # [REJECT] The proposer index is a valid validator index
    if block.proposer_index >= len(state.validators):
        raise GossipReject(BeaconBlockGossipError.PROPOSER_INDEX_OUT_OF_RANGE)

    # [REJECT] The proposer signature is valid
    proposer = state.validators[block.proposer_index]
    domain = get_domain(state, DOMAIN_BEACON_PROPOSER, compute_epoch_at_slot(block.slot))
    signing_root = compute_signing_root(block, domain)
    if not bls.Verify(proposer.pubkey, signing_root, signed_beacon_block.signature):
        raise GossipReject(BeaconBlockGossipError.INVALID_PROPOSER_SIGNATURE)

    # [IGNORE] The block's parent has been seen (via gossip or non-gossip sources)
    # (MAY be queued until parent is retrieved)
    if block.parent_root not in store.blocks:
        raise GossipIgnore(BeaconBlockGossipError.PARENT_NOT_SEEN)

    # [REJECT] The block's execution payload timestamp is correct with respect to the slot
    if execution_payload.timestamp != compute_time_at_slot(state, block.slot):
        raise GossipReject(BeaconBlockGossipError.INCORRECT_EXECUTION_PAYLOAD_TIMESTAMP)

    parent_payload_status = PAYLOAD_STATUS_NOT_VALIDATED
    if block.parent_root in block_payload_statuses:
        parent_payload_status = block_payload_statuses[block.parent_root]

    if block.parent_root not in store.block_states:
        if parent_payload_status == PAYLOAD_STATUS_NOT_VALIDATED:
            # [REJECT] The block's parent passes validation
            raise GossipReject(BeaconBlockGossipError.PARENT_INVALID_EL_RESULT_UNKNOWN)

        # [IGNORE] The block's parent passes validation
        raise GossipIgnore(BeaconBlockGossipError.PARENT_INVALID_EL_RESULT_KNOWN)

    # [IGNORE] The block's parent's execution payload passes validation
    if parent_payload_status == PAYLOAD_STATUS_INVALIDATED:
        raise GossipIgnore(BeaconBlockGossipError.PARENT_VALID_EL_RESULT_INVALID)

    # [REJECT] The block is from a higher slot than its parent
    if block.slot <= store.blocks[block.parent_root].slot:
        raise GossipReject(BeaconBlockGossipError.BLOCK_NOT_AFTER_PARENT)

    # [REJECT] The current finalized checkpoint is an ancestor of the block
    checkpoint_block = get_checkpoint_block(
        store, block.parent_root, store.finalized_checkpoint.epoch
    )
    if checkpoint_block != store.finalized_checkpoint.root:
        raise GossipReject(BeaconBlockGossipError.FINALIZED_NOT_ANCESTOR)

    # [Modified in Electra:EIP7691]
    # [REJECT] The length of KZG commitments is less than or equal to the limit
    if len(block.body.blob_kzg_commitments) > MAX_BLOBS_PER_BLOCK_ELECTRA:
        raise GossipReject(BeaconBlockGossipError.TOO_MANY_BLOB_KZG_COMMITMENTS)

    # [REJECT] The block is proposed by the expected proposer for the slot
    # (if shuffling is not available, IGNORE instead and MAY be queued for later)
    parent_state = store.block_states[block.parent_root].copy()
    process_slots(parent_state, block.slot)
    expected_proposer = get_beacon_proposer_index(parent_state)
    if block.proposer_index != expected_proposer:
        raise GossipReject(BeaconBlockGossipError.PROPOSER_MISMATCH)

    # Mark this block as seen
    seen.proposer_slots.add((block.proposer_index, block.slot))
```

###### `beacon_aggregate_and_proof`

*Note*: This function is modified per EIP-7549. The committee index is now
encoded in `aggregate.committee_bits`, `aggregate.data.index` MUST be zero, and
the gossip seen-cache is keyed by
`(hash_tree_root(aggregate.data), committee_index)`.

```python
class BeaconAggregateAndProofGossipError(StrEnum):
    """Gossip validation errors for ``beacon_aggregate_and_proof``."""

    AGGREGATE_ALREADY_SEEN = auto()
    """A valid aggregate with a superset of aggregation bits has already been seen."""
    AGGREGATION_BITS_LENGTH_MISMATCH = auto()
    """The aggregation bits length does not match the committee size."""
    AGGREGATOR_ALREADY_SEEN = auto()
    """An aggregate has already been seen from this aggregator for this epoch."""
    AGGREGATOR_NOT_IN_COMMITTEE = auto()
    """The aggregator index is not in the committee."""
    BLOCK_FAILED_VALIDATION = auto()
    """The block being voted for failed validation."""
    BLOCK_NOT_SEEN = auto()
    """The block being voted for has not been seen."""
    COMMITTEE_INDEX_OUT_OF_RANGE = auto()
    """The committee index is out of range."""
    # [New in Electra]
    DATA_INDEX_NON_ZERO = auto()
    """The aggregate attestation's data index is non-zero."""
    EPOCH_MISMATCH = auto()
    """The aggregate attestation's epoch does not match its target."""
    EPOCH_NOT_PREVIOUS_OR_CURRENT = auto()
    """The aggregate attestation's epoch is not the previous or current epoch."""
    FINALIZED_NOT_ANCESTOR = auto()
    """The finalized checkpoint is not an ancestor of the block."""
    INVALID_AGGREGATE_SIGNATURE = auto()
    """The aggregate signature is invalid."""
    INVALID_AGGREGATOR_SIGNATURE = auto()
    """The aggregator signature is invalid."""
    # [New in Electra]
    INVALID_COMMITTEE_BITS = auto()
    """The aggregate committee bits do not specify exactly one committee."""
    INVALID_SELECTION_PROOF_SIGNATURE = auto()
    """The selection proof signature is invalid."""
    NOT_AGGREGATOR = auto()
    """The validator is not selected as an aggregator."""
    NO_PARTICIPANTS = auto()
    """The aggregate attestation has no participants."""
    SLOT_FROM_FUTURE = auto()
    """The aggregate attestation's slot is from a future slot."""
    TARGET_NOT_ANCESTOR_OF_LMD_VOTE = auto()
    """The target block is not an ancestor of the LMD vote block."""
```

```python
def validate_beacon_aggregate_and_proof_gossip(
    seen: Seen,
    store: Store,
    state: BeaconState,
    signed_aggregate_and_proof: SignedAggregateAndProof,
    current_time_ms: uint64,
) -> None:
    """
    Validate a SignedAggregateAndProof for gossip propagation.
    Raises GossipIgnore or GossipReject on validation failure.
    """
    aggregate_and_proof = signed_aggregate_and_proof.message
    aggregate = aggregate_and_proof.aggregate
    aggregation_bits = aggregate.aggregation_bits

    # [New in Electra:EIP7549]
    # [REJECT] The aggregate attestation's data index is zero
    if aggregate.data.index != 0:
        raise GossipReject(BeaconAggregateAndProofGossipError.DATA_INDEX_NON_ZERO)

    # [New in Electra:EIP7549]
    # [REJECT] Exactly one committee is specified by the committee bits
    committee_indices = get_committee_indices(aggregate.committee_bits)
    if len(committee_indices) != 1:
        raise GossipReject(BeaconAggregateAndProofGossipError.INVALID_COMMITTEE_BITS)
    index = committee_indices[0]

    # [REJECT] The committee index is within the expected range
    committee_count = get_committee_count_per_slot(state, aggregate.data.target.epoch)
    if index >= committee_count:
        raise GossipReject(BeaconAggregateAndProofGossipError.COMMITTEE_INDEX_OUT_OF_RANGE)

    # [IGNORE] The aggregate attestation's slot is not from a future slot
    # (MAY be queued for processing at the appropriate slot)
    if not is_not_from_future_slot(state, aggregate.data.slot, current_time_ms):
        raise GossipIgnore(BeaconAggregateAndProofGossipError.SLOT_FROM_FUTURE)

    # [IGNORE] The aggregate attestation's epoch is either the current or previous epoch
    attestation_epoch = compute_epoch_at_slot(aggregate.data.slot)
    is_previous_epoch_attestation = is_within_slot_range(
        state,
        compute_start_slot_at_epoch(Epoch(attestation_epoch + 1)),
        SLOTS_PER_EPOCH - 1,
        current_time_ms,
    )
    is_current_epoch_attestation = is_within_slot_range(
        state,
        compute_start_slot_at_epoch(attestation_epoch),
        SLOTS_PER_EPOCH - 1,
        current_time_ms,
    )
    if not (is_previous_epoch_attestation or is_current_epoch_attestation):
        raise GossipIgnore(BeaconAggregateAndProofGossipError.EPOCH_NOT_PREVIOUS_OR_CURRENT)

    # [REJECT] The aggregate attestation's epoch matches its target
    if aggregate.data.target.epoch != compute_epoch_at_slot(aggregate.data.slot):
        raise GossipReject(BeaconAggregateAndProofGossipError.EPOCH_MISMATCH)

    # [REJECT] The number of aggregation bits matches the committee size
    committee = get_beacon_committee(state, aggregate.data.slot, index)
    if len(aggregation_bits) != len(committee):
        raise GossipReject(BeaconAggregateAndProofGossipError.AGGREGATION_BITS_LENGTH_MISMATCH)

    # [REJECT] The aggregate attestation has participants
    attesting_indices = get_attesting_indices(state, aggregate)
    if len(attesting_indices) < 1:
        raise GossipReject(BeaconAggregateAndProofGossipError.NO_PARTICIPANTS)

    # [Modified in Electra:EIP7549]
    # [IGNORE] A valid aggregate with a superset of aggregation bits has not already been seen
    aggregate_data_root = hash_tree_root(aggregate.data)
    aggregate_cache_key = (aggregate_data_root, index)
    aggregate_bits = tuple(bool(bit) for bit in aggregation_bits)
    seen_bits = seen.aggregate_data_roots.get(aggregate_cache_key, set())
    if is_non_strict_superset(seen_bits, aggregate_bits):
        raise GossipIgnore(BeaconAggregateAndProofGossipError.AGGREGATE_ALREADY_SEEN)

    # [IGNORE] This is the first valid aggregate for this aggregator in this epoch
    aggregator_index = aggregate_and_proof.aggregator_index
    target_epoch = aggregate.data.target.epoch
    if (aggregator_index, target_epoch) in seen.aggregator_epochs:
        raise GossipIgnore(BeaconAggregateAndProofGossipError.AGGREGATOR_ALREADY_SEEN)

    # [REJECT] The selection proof selects the validator as an aggregator
    if not is_aggregator(state, aggregate.data.slot, index, aggregate_and_proof.selection_proof):
        raise GossipReject(BeaconAggregateAndProofGossipError.NOT_AGGREGATOR)

    # [REJECT] The aggregator's validator index is within the committee
    if aggregator_index not in committee:
        raise GossipReject(BeaconAggregateAndProofGossipError.AGGREGATOR_NOT_IN_COMMITTEE)

    # [REJECT] The selection proof signature is valid
    aggregator = state.validators[aggregator_index]
    domain = get_domain(state, DOMAIN_SELECTION_PROOF, target_epoch)
    signing_root = compute_signing_root(aggregate.data.slot, domain)
    if not bls.Verify(aggregator.pubkey, signing_root, aggregate_and_proof.selection_proof):
        raise GossipReject(BeaconAggregateAndProofGossipError.INVALID_SELECTION_PROOF_SIGNATURE)

    # [REJECT] The aggregator signature is valid
    domain = get_domain(state, DOMAIN_AGGREGATE_AND_PROOF, target_epoch)
    signing_root = compute_signing_root(aggregate_and_proof, domain)
    if not bls.Verify(aggregator.pubkey, signing_root, signed_aggregate_and_proof.signature):
        raise GossipReject(BeaconAggregateAndProofGossipError.INVALID_AGGREGATOR_SIGNATURE)

    # [REJECT] The aggregate signature is valid
    if not is_valid_indexed_attestation(state, get_indexed_attestation(state, aggregate)):
        raise GossipReject(BeaconAggregateAndProofGossipError.INVALID_AGGREGATE_SIGNATURE)

    # [IGNORE] The block being voted for has been seen (via gossip or non-gossip sources)
    # (MAY be queued until block is retrieved)
    if aggregate.data.beacon_block_root not in store.blocks:
        raise GossipIgnore(BeaconAggregateAndProofGossipError.BLOCK_NOT_SEEN)

    # [REJECT] The block being voted for passes validation
    if aggregate.data.beacon_block_root not in store.block_states:
        raise GossipReject(BeaconAggregateAndProofGossipError.BLOCK_FAILED_VALIDATION)

    # [REJECT] The target block is an ancestor of the LMD vote block
    checkpoint_block = get_checkpoint_block(
        store, aggregate.data.beacon_block_root, aggregate.data.target.epoch
    )
    if checkpoint_block != aggregate.data.target.root:
        raise GossipReject(BeaconAggregateAndProofGossipError.TARGET_NOT_ANCESTOR_OF_LMD_VOTE)

    # [IGNORE] The finalized checkpoint is an ancestor of the block
    finalized_checkpoint_block = get_checkpoint_block(
        store, aggregate.data.beacon_block_root, store.finalized_checkpoint.epoch
    )
    if finalized_checkpoint_block != store.finalized_checkpoint.root:
        raise GossipIgnore(BeaconAggregateAndProofGossipError.FINALIZED_NOT_ANCESTOR)

    # Mark this aggregate as seen
    seen.aggregator_epochs.add((aggregator_index, target_epoch))
    if aggregate_cache_key not in seen.aggregate_data_roots:
        seen.aggregate_data_roots[aggregate_cache_key] = set()
    seen.aggregate_data_roots[aggregate_cache_key].add(aggregate_bits)
```

###### `attester_slashing`

*Note*: This function is modified per EIP-7549. The new `AttesterSlashing` type
wraps an `IndexedAttestation` payload sized for
`MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT` attesting indices; the
validation logic is otherwise unchanged.

###### `blob_sidecar_{subnet_id}`

*Note*: This function is modified per EIP-7691. The sidecar's index is bounded
by `MAX_BLOBS_PER_BLOCK_ELECTRA`.

```python
def validate_blob_sidecar_gossip(
    seen: Seen,
    store: Store,
    state: BeaconState,
    blob_sidecar: BlobSidecar,
    subnet_id: SubnetID,
    current_time_ms: uint64,
) -> None:
    """
    Validate a BlobSidecar for gossip propagation on a subnet.
    Raises GossipIgnore or GossipReject on validation failure.
    """
    block_header = blob_sidecar.signed_block_header.message

    # [Modified in Electra:EIP7691]
    # [REJECT] The sidecar's index is consistent with MAX_BLOBS_PER_BLOCK_ELECTRA
    if blob_sidecar.index >= MAX_BLOBS_PER_BLOCK_ELECTRA:
        raise GossipReject(BlobSidecarGossipError.INDEX_OUT_OF_RANGE)

    # [REJECT] The sidecar is for the correct subnet
    if compute_subnet_for_blob_sidecar(blob_sidecar.index) != subnet_id:
        raise GossipReject(BlobSidecarGossipError.WRONG_SUBNET)

    # [IGNORE] The sidecar is not from a future slot
    # (MAY be queued for processing at the appropriate slot)
    if not is_not_from_future_slot(state, block_header.slot, current_time_ms):
        raise GossipIgnore(BlobSidecarGossipError.SLOT_FROM_FUTURE)

    # [IGNORE] The sidecar is from a slot greater than the latest finalized slot
    finalized_slot = compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)
    if block_header.slot <= finalized_slot:
        raise GossipIgnore(BlobSidecarGossipError.SLOT_NOT_AFTER_FINALIZED)

    # [REJECT] The proposer index is a valid validator index
    if block_header.proposer_index >= len(state.validators):
        raise GossipReject(BlobSidecarGossipError.PROPOSER_INDEX_OUT_OF_RANGE)

    # [REJECT] The proposer signature of blob_sidecar.signed_block_header is valid
    proposer = state.validators[block_header.proposer_index]
    domain = get_domain(state, DOMAIN_BEACON_PROPOSER, compute_epoch_at_slot(block_header.slot))
    signing_root = compute_signing_root(block_header, domain)
    if not bls.Verify(proposer.pubkey, signing_root, blob_sidecar.signed_block_header.signature):
        raise GossipReject(BlobSidecarGossipError.INVALID_PROPOSER_SIGNATURE)

    # [IGNORE] The sidecar's block's parent has been seen
    # (MAY be queued for processing once the parent block is retrieved)
    if block_header.parent_root not in store.blocks:
        raise GossipIgnore(BlobSidecarGossipError.PARENT_NOT_SEEN)

    # [REJECT] The sidecar's block's parent passes validation
    if block_header.parent_root not in store.block_states:
        raise GossipReject(BlobSidecarGossipError.PARENT_FAILED_VALIDATION)

    # [REJECT] The sidecar is from a higher slot than the sidecar's block's parent
    if block_header.slot <= store.blocks[block_header.parent_root].slot:
        raise GossipReject(BlobSidecarGossipError.SLOT_NOT_AFTER_PARENT)

    # [REJECT] The current finalized_checkpoint is an ancestor of the sidecar's block
    checkpoint_block = get_checkpoint_block(
        store, block_header.parent_root, store.finalized_checkpoint.epoch
    )
    if checkpoint_block != store.finalized_checkpoint.root:
        raise GossipReject(BlobSidecarGossipError.FINALIZED_NOT_ANCESTOR)

    # [REJECT] The sidecar's inclusion proof is valid as verified by verify_blob_sidecar_inclusion_proof
    if not verify_blob_sidecar_inclusion_proof(blob_sidecar):
        raise GossipReject(BlobSidecarGossipError.INVALID_INCLUSION_PROOF)

    # [REJECT] The sidecar's blob is valid as verified by verify_blob_kzg_proof
    if not verify_blob_kzg_proof(
        blob_sidecar.blob, blob_sidecar.kzg_commitment, blob_sidecar.kzg_proof
    ):
        raise GossipReject(BlobSidecarGossipError.INVALID_KZG_PROOF)

    # [IGNORE] The sidecar is the first sidecar for the tuple
    # (block_header.slot, block_header.proposer_index, blob_sidecar.index)
    sidecar_tuple = (block_header.slot, block_header.proposer_index, blob_sidecar.index)
    if sidecar_tuple in seen.blob_sidecar_tuples:
        raise GossipIgnore(BlobSidecarGossipError.ALREADY_SEEN)

    # [REJECT] The sidecar is proposed by the expected proposer_index
    # (if shuffling is not available, IGNORE instead and MAY be queued for later)
    parent_state = store.block_states[block_header.parent_root].copy()
    process_slots(parent_state, block_header.slot)
    expected_proposer = get_beacon_proposer_index(parent_state)
    if block_header.proposer_index != expected_proposer:
        raise GossipReject(BlobSidecarGossipError.PROPOSER_MISMATCH)

    # Mark this blob sidecar as seen
    seen.blob_sidecar_tuples.add(sidecar_tuple)
```

##### Attestation subnets

###### `beacon_attestation_{subnet_id}`

*Note*: This function is modified per EIP-7549. The topic now propagates
`SingleAttestation` objects: the attesting validator's index is carried directly
in the message, the committee index is read from `attestation.committee_index`,
and `attestation.data.index` MUST be zero.

```python
class BeaconAttestationGossipError(StrEnum):
    """Gossip validation errors for ``beacon_attestation_{subnet_id}``."""

    AGGREGATION_BITS_LENGTH_MISMATCH = auto()
    """The aggregation bits length does not match the committee size."""
    ALREADY_SEEN = auto()
    """An attestation from this validator for this epoch has already been seen."""
    # [New in Electra]
    ATTESTER_NOT_IN_COMMITTEE = auto()
    """The attester is not a member of the committee."""
    BLOCK_FAILED_VALIDATION = auto()
    """The block being voted for failed validation."""
    BLOCK_NOT_SEEN = auto()
    """The block being voted for has not been seen."""
    COMMITTEE_INDEX_OUT_OF_RANGE = auto()
    """The committee index is out of range."""
    # [New in Electra]
    DATA_INDEX_NON_ZERO = auto()
    """The attestation's data index is non-zero."""
    EPOCH_MISMATCH = auto()
    """The attestation's epoch does not match its target."""
    EPOCH_NOT_PREVIOUS_OR_CURRENT = auto()
    """The attestation's epoch is not the previous or current epoch."""
    FINALIZED_NOT_ANCESTOR = auto()
    """The finalized checkpoint is not an ancestor of the block."""
    INVALID_SIGNATURE = auto()
    """The attestation signature is invalid."""
    NOT_UNAGGREGATED = auto()
    """The attestation is not unaggregated."""
    SLOT_FROM_FUTURE = auto()
    """The attestation's slot is from a future slot."""
    TARGET_NOT_ANCESTOR_OF_LMD_VOTE = auto()
    """The target block is not an ancestor of the LMD vote block."""
    WRONG_SUBNET = auto()
    """The attestation is for the wrong subnet."""
```

```python
def validate_beacon_attestation_gossip(
    seen: Seen,
    store: Store,
    state: BeaconState,
    # [Modified in Electra:EIP7549]
    attestation: SingleAttestation,
    subnet_id: uint64,
    current_time_ms: uint64,
) -> None:
    """
    Validate a SingleAttestation for gossip propagation on a subnet.
    Raises GossipIgnore or GossipReject on validation failure.
    """
    data = attestation.data
    # [Modified in Electra:EIP7549]
    committee_index = attestation.committee_index
    attester_index = attestation.attester_index
    target_epoch = data.target.epoch

    # [New in Electra:EIP7549]
    # [REJECT] The attestation's data index is zero
    if data.index != 0:
        raise GossipReject(BeaconAttestationGossipError.DATA_INDEX_NON_ZERO)

    # [REJECT] The committee index is within the expected range
    committees_per_slot = get_committee_count_per_slot(state, target_epoch)
    if committee_index >= committees_per_slot:
        raise GossipReject(BeaconAttestationGossipError.COMMITTEE_INDEX_OUT_OF_RANGE)

    # [REJECT] The attestation is for the correct subnet
    expected_subnet = compute_subnet_for_attestation(
        committees_per_slot, data.slot, committee_index
    )
    if expected_subnet != subnet_id:
        raise GossipReject(BeaconAttestationGossipError.WRONG_SUBNET)

    # [IGNORE] The attestation's slot is not from a future slot
    # (MAY be queued for processing at the appropriate slot)
    if not is_not_from_future_slot(state, data.slot, current_time_ms):
        raise GossipIgnore(BeaconAttestationGossipError.SLOT_FROM_FUTURE)

    # [IGNORE] The attestation's epoch is either the current or previous epoch
    attestation_epoch = compute_epoch_at_slot(data.slot)
    is_previous_epoch_attestation = is_within_slot_range(
        state,
        compute_start_slot_at_epoch(Epoch(attestation_epoch + 1)),
        SLOTS_PER_EPOCH - 1,
        current_time_ms,
    )
    is_current_epoch_attestation = is_within_slot_range(
        state,
        compute_start_slot_at_epoch(attestation_epoch),
        SLOTS_PER_EPOCH - 1,
        current_time_ms,
    )
    if not (is_previous_epoch_attestation or is_current_epoch_attestation):
        raise GossipIgnore(BeaconAttestationGossipError.EPOCH_NOT_PREVIOUS_OR_CURRENT)

    # [REJECT] The attestation's epoch matches its target
    if target_epoch != compute_epoch_at_slot(data.slot):
        raise GossipReject(BeaconAttestationGossipError.EPOCH_MISMATCH)

    # [New in Electra:EIP7549]
    # [REJECT] The attester is a member of the committee
    committee = get_beacon_committee(state, data.slot, committee_index)
    if attester_index not in committee:
        raise GossipReject(BeaconAttestationGossipError.ATTESTER_NOT_IN_COMMITTEE)

    # [Modified in Electra:EIP7549]
    # [IGNORE] No other valid attestation seen for this validator and target epoch
    if (attester_index, target_epoch) in seen.attestation_validator_epochs:
        raise GossipIgnore(BeaconAttestationGossipError.ALREADY_SEEN)

    # [Modified in Electra:EIP7549]
    # [REJECT] The attestation signature is valid
    attester = state.validators[attester_index]
    domain = get_domain(state, DOMAIN_BEACON_ATTESTER, target_epoch)
    signing_root = compute_signing_root(data, domain)
    if not bls.Verify(attester.pubkey, signing_root, attestation.signature):
        raise GossipReject(BeaconAttestationGossipError.INVALID_SIGNATURE)

    # [IGNORE] The block being voted for has been seen (via gossip or non-gossip sources)
    # (MAY be queued until block is retrieved)
    beacon_block_root = data.beacon_block_root
    if beacon_block_root not in store.blocks:
        raise GossipIgnore(BeaconAttestationGossipError.BLOCK_NOT_SEEN)

    # [REJECT] The block being voted for passes validation
    if beacon_block_root not in store.block_states:
        raise GossipReject(BeaconAttestationGossipError.BLOCK_FAILED_VALIDATION)

    # [REJECT] The attestation's target block is an ancestor of the LMD vote block
    target_checkpoint_block = get_checkpoint_block(store, beacon_block_root, target_epoch)
    if target_checkpoint_block != data.target.root:
        raise GossipReject(BeaconAttestationGossipError.TARGET_NOT_ANCESTOR_OF_LMD_VOTE)

    # [IGNORE] The current finalized_checkpoint is an ancestor of the block
    finalized_checkpoint_block = get_checkpoint_block(
        store, beacon_block_root, store.finalized_checkpoint.epoch
    )
    if finalized_checkpoint_block != store.finalized_checkpoint.root:
        raise GossipIgnore(BeaconAttestationGossipError.FINALIZED_NOT_ANCESTOR)

    # Mark this attestation as seen
    seen.attestation_validator_epochs.add((attester_index, target_epoch))
```

### The Req/Resp domain

#### Messages

##### BeaconBlocksByRange v2

**Protocol ID:** `/eth2/beacon_chain/req/beacon_blocks_by_range/2/`

The Electra fork-digest is introduced to the `context` enum to specify Electra
beacon block type.

<!-- eth_consensus_specs: skip -->

| `fork_version`           | Chunk SSZ type                |
| ------------------------ | ----------------------------- |
| `GENESIS_FORK_VERSION`   | `phase0.SignedBeaconBlock`    |
| `ALTAIR_FORK_VERSION`    | `altair.SignedBeaconBlock`    |
| `BELLATRIX_FORK_VERSION` | `bellatrix.SignedBeaconBlock` |
| `CAPELLA_FORK_VERSION`   | `capella.SignedBeaconBlock`   |
| `DENEB_FORK_VERSION`     | `deneb.SignedBeaconBlock`     |
| `ELECTRA_FORK_VERSION`   | `electra.SignedBeaconBlock`   |

##### BeaconBlocksByRoot v2

**Protocol ID:** `/eth2/beacon_chain/req/beacon_blocks_by_root/2/`

<!-- eth_consensus_specs: skip -->

| `fork_version`           | Chunk SSZ type                |
| ------------------------ | ----------------------------- |
| `GENESIS_FORK_VERSION`   | `phase0.SignedBeaconBlock`    |
| `ALTAIR_FORK_VERSION`    | `altair.SignedBeaconBlock`    |
| `BELLATRIX_FORK_VERSION` | `bellatrix.SignedBeaconBlock` |
| `CAPELLA_FORK_VERSION`   | `capella.SignedBeaconBlock`   |
| `DENEB_FORK_VERSION`     | `deneb.SignedBeaconBlock`     |
| `ELECTRA_FORK_VERSION`   | `electra.SignedBeaconBlock`   |

##### BlobSidecarsByRange v1

**Protocol ID:** `/eth2/beacon_chain/req/blob_sidecars_by_range/1/`

*[Modified in Electra:EIP7691]*

*Note*: The `compute_max_request_blob_sidecars` function has been modified which
affects the request, response, and validation logic.

##### BlobSidecarsByRoot v1

**Protocol ID:** `/eth2/beacon_chain/req/blob_sidecars_by_root/1/`

*[Modified in Electra:EIP7691]*

*Note*: The `compute_max_request_blob_sidecars` function has been modified which
affects the request, response, and validation logic.

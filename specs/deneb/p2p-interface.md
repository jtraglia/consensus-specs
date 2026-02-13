# Deneb -- Networking

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Introduction](#introduction)
- [Modifications in Deneb](#modifications-in-deneb)
  - [Preset](#preset)
  - [Configuration](#configuration)
  - [Containers](#containers)
    - [`BlobSidecar`](#blobsidecar)
    - [`BlobIdentifier`](#blobidentifier)
  - [Helpers](#helpers)
    - [Modified `compute_fork_version`](#modified-compute_fork_version)
    - [`verify_blob_sidecar_inclusion_proof`](#verify_blob_sidecar_inclusion_proof)
    - [Modified `is_valid_attestation_slot_time`](#modified-is_valid_attestation_slot_time)
    - [Modified `Seen`](#modified-seen)
    - [Modified `validate_beacon_block_gossip`](#modified-validate_beacon_block_gossip)
  - [The gossip domain: gossipsub](#the-gossip-domain-gossipsub)
    - [Topics and messages](#topics-and-messages)
      - [Global topics](#global-topics)
        - [`beacon_block`](#beacon_block)
        - [`beacon_aggregate_and_proof`](#beacon_aggregate_and_proof)
      - [Blob subnets](#blob-subnets)
        - [`blob_sidecar_{subnet_id}`](#blob_sidecar_subnet_id)
        - [Blob retrieval via local execution-layer client](#blob-retrieval-via-local-execution-layer-client)
      - [Attestation subnets](#attestation-subnets)
        - [`beacon_attestation_{subnet_id}`](#beacon_attestation_subnet_id)
    - [Transitioning the gossip](#transitioning-the-gossip)
  - [The Req/Resp domain](#the-reqresp-domain)
    - [Messages](#messages)
      - [BeaconBlocksByRange v2](#beaconblocksbyrange-v2)
      - [BeaconBlocksByRoot v2](#beaconblocksbyroot-v2)
      - [BlobSidecarsByRange v1](#blobsidecarsbyrange-v1)
      - [BlobSidecarsByRoot v1](#blobsidecarsbyroot-v1)
- [Design decision rationale](#design-decision-rationale)
  - [Why are blobs relayed as a sidecar, separate from beacon blocks?](#why-are-blobs-relayed-as-a-sidecar-separate-from-beacon-blocks)

<!-- mdformat-toc end -->

## Introduction

This document contains the consensus-layer networking specifications for Deneb.

The specification of these changes continues in the same format as the network
specifications of previous upgrades, and assumes them as pre-requisite.

## Modifications in Deneb

### Preset

*[New in Deneb:EIP4844]*

| Name                                   | Value                                                                                                                                     | Description                                                                 |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| `KZG_COMMITMENT_INCLUSION_PROOF_DEPTH` | `uint64(floorlog2(get_generalized_index(BeaconBlockBody, 'blob_kzg_commitments')) + 1 + ceillog2(MAX_BLOB_COMMITMENTS_PER_BLOCK))` (= 17) | <!-- predefined --> Merkle proof depth for `blob_kzg_commitments` list item |

### Configuration

*[New in Deneb:EIP4844]*

| Name                                    | Value                                            | Description                                                        |
| --------------------------------------- | ------------------------------------------------ | ------------------------------------------------------------------ |
| `MAX_REQUEST_BLOCKS_DENEB`              | `2**7` (= 128)                                   | Maximum number of blocks in a single request                       |
| `MAX_REQUEST_BLOB_SIDECARS`             | `MAX_REQUEST_BLOCKS_DENEB * MAX_BLOBS_PER_BLOCK` | Maximum number of blob sidecars in a single request                |
| `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS` | `2**12` (= 4096 epochs, ~18 days)                | The minimum epoch range over which a node must serve blob sidecars |
| `BLOB_SIDECAR_SUBNET_COUNT`             | `6`                                              | The number of blob sidecar subnets used in the gossipsub protocol  |

### Containers

#### `BlobSidecar`

*[New in Deneb:EIP4844]*

*Note*: `index` is the index of the blob in the block.

```python
class BlobSidecar(Container):
    index: BlobIndex
    blob: Blob
    kzg_commitment: KZGCommitment
    kzg_proof: KZGProof
    signed_block_header: SignedBeaconBlockHeader
    kzg_commitment_inclusion_proof: Vector[Bytes32, KZG_COMMITMENT_INCLUSION_PROOF_DEPTH]
```

#### `BlobIdentifier`

*[New in Deneb:EIP4844]*

```python
class BlobIdentifier(Container):
    block_root: Root
    index: BlobIndex
```

### Helpers

#### Modified `compute_fork_version`

```python
def compute_fork_version(epoch: Epoch) -> Version:
    """
    Return the fork version at the given ``epoch``.
    """
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

#### `verify_blob_sidecar_inclusion_proof`

```python
def verify_blob_sidecar_inclusion_proof(blob_sidecar: BlobSidecar) -> bool:
    gindex = get_subtree_index(
        get_generalized_index(BeaconBlockBody, "blob_kzg_commitments", blob_sidecar.index)
    )
    return is_valid_merkle_branch(
        leaf=blob_sidecar.kzg_commitment.hash_tree_root(),
        branch=blob_sidecar.kzg_commitment_inclusion_proof,
        depth=KZG_COMMITMENT_INCLUSION_PROOF_DEPTH,
        index=gindex,
        root=blob_sidecar.signed_block_header.message.body_root,
    )
```

#### Modified `is_valid_attestation_slot_time`

*[Modified in Deneb:EIP7045]*

The attestation propagation check is changed from a slot-range based check to an
epoch-based check. Attestations created in epoch `N` can be gossiped through the
entire range of slots in epoch `N+1`.

```python
def is_valid_attestation_slot_time(
    state: BeaconState,
    attestation_slot: Slot,
    current_time_ms: uint64,
) -> bool:
    """
    Check if an attestation's slot time is valid given the current time.
    The attestation must be from the current or previous epoch and not from the future.
    """
    attestation_time_ms = compute_time_at_slot_ms(state, attestation_slot)
    if current_time_ms + MAXIMUM_GOSSIP_CLOCK_DISPARITY < attestation_time_ms:
        # Attestation is from the future
        return False
    if compute_epoch_at_slot(attestation_slot) not in (
        get_previous_epoch(state),
        get_current_epoch(state),
    ):
        # Attestation is not from current or previous epoch
        return False
    return True
```

#### Modified `Seen`

The `Seen` class is extended with an additional field to track blob sidecar
gossip deduplication state.

```python
@dataclass
class Seen(object):
    proposer_slots: Set[Tuple[ValidatorIndex, Slot]]
    aggregator_epochs: Set[Tuple[ValidatorIndex, Epoch]]
    aggregate_data_roots: Dict[Root, Set[Tuple[boolean, ...]]]
    voluntary_exit_indices: Set[ValidatorIndex]
    proposer_slashing_indices: Set[ValidatorIndex]
    attester_slashing_indices: Set[ValidatorIndex]
    attestation_validator_epochs: Set[Tuple[ValidatorIndex, Epoch]]
    sync_contribution_aggregator_slots: Set[Tuple[ValidatorIndex, Slot, uint64]]
    sync_contribution_data: Dict[Tuple[Slot, Root, uint64], Set[Tuple[boolean, ...]]]
    sync_message_validator_slots: Set[Tuple[ValidatorIndex, Slot, uint64]]
    bls_to_execution_change_indices: Set[ValidatorIndex]
    # [New in Deneb]
    blob_sidecar_slots: Set[Tuple[ValidatorIndex, Slot, BlobIndex]]
```

#### Modified `validate_beacon_block_gossip`

The `validate_beacon_block_gossip` function from the Bellatrix document is
modified to add a KZG commitment length check.

```python
def validate_beacon_block_gossip(
    seen: Seen,
    store: Store,
    state: BeaconState,
    signed_beacon_block: SignedBeaconBlock,
    current_time_ms: uint64,
) -> None:
    """
    Validate a SignedBeaconBlock for gossip propagation.
    Raises GossipIgnore or GossipReject on validation failure.
    """
    block = signed_beacon_block.message

    # [IGNORE] The block is not from a future slot (with MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance)
    # (MAY be queued for processing at the appropriate slot)
    block_time_ms = compute_time_at_slot_ms(state, block.slot)
    if current_time_ms + MAXIMUM_GOSSIP_CLOCK_DISPARITY < block_time_ms:
        raise GossipIgnore("block is from a future slot")

    # [IGNORE] The block is from a slot greater than the latest finalized slot
    # (MAY choose to validate and store such blocks for additional purposes
    # -- e.g. slashing detection, archive nodes, etc).
    finalized_slot = compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)
    if block.slot <= finalized_slot:
        raise GossipIgnore("block is not from a slot greater than the latest finalized slot")

    # [IGNORE] The block is the first block with valid signature received for the proposer for the slot
    if (block.proposer_index, block.slot) in seen.proposer_slots:
        raise GossipIgnore("block is not the first valid block for this proposer and slot")

    # [REJECT] The proposer signature is valid with respect to the proposer_index pubkey
    if block.proposer_index >= len(state.validators):
        raise GossipReject("invalid proposer signature")
    proposer = state.validators[block.proposer_index]
    domain = get_domain(state, DOMAIN_BEACON_PROPOSER, compute_epoch_at_slot(block.slot))
    signing_root = compute_signing_root(block, domain)
    if not bls.Verify(proposer.pubkey, signing_root, signed_beacon_block.signature):
        raise GossipReject("invalid proposer signature")

    # [IGNORE] The block's parent has been seen (via gossip or non-gossip sources)
    # (MAY be queued until parent is retrieved)
    if block.parent_root not in store.blocks:
        raise GossipIgnore("block's parent has not been seen")

    # [REJECT] The block's parent passes validation
    if store.block_states.get(block.parent_root) is None:
        raise GossipReject("block's parent failed validation")

    # [REJECT] The block is from a higher slot than its parent
    parent_block = store.blocks[block.parent_root]
    if block.slot <= parent_block.slot:
        raise GossipReject("block is not from a higher slot than its parent")

    # [REJECT] The current finalized_checkpoint is an ancestor of block
    checkpoint_block = get_checkpoint_block(
        store, block.parent_root, store.finalized_checkpoint.epoch
    )
    if checkpoint_block != store.finalized_checkpoint.root:
        raise GossipReject("finalized checkpoint is not an ancestor of block")

    # Get state at parent for proposer verification
    parent_state = store.block_states[block.parent_root].copy()
    process_slots(parent_state, block.slot)

    # [REJECT] The block is proposed by the expected proposer_index for the block's slot
    # (if shuffling is not available, IGNORE instead and MAY be queued for later)
    expected_proposer = get_beacon_proposer_index(parent_state)
    if block.proposer_index != expected_proposer:
        raise GossipReject("block proposer_index does not match expected proposer")

    # [REJECT] The block's execution payload timestamp is correct with respect to the slot
    if is_execution_enabled(parent_state, block.body):
        execution_payload = block.body.execution_payload
        if execution_payload.timestamp != compute_time_at_slot(parent_state, block.slot):
            raise GossipReject("incorrect execution payload timestamp")

    # [New in Deneb:EIP4844]
    # [REJECT] The length of KZG commitments is <= MAX_BLOBS_PER_BLOCK
    if len(block.body.blob_kzg_commitments) > MAX_BLOBS_PER_BLOCK:
        raise GossipReject("too many KZG commitments")

    # Mark this block as seen for this proposer/slot combination
    seen.proposer_slots.add((block.proposer_index, block.slot))
```

### The gossip domain: gossipsub

Some gossip meshes are upgraded in Deneb to support upgraded types.

#### Topics and messages

Topics follow the same specification as in prior upgrades.

The `beacon_block` topic is modified to also support Deneb blocks and new topics
are added per table below.

The `voluntary_exit` topic is implicitly modified despite the lock-in use of
`CAPELLA_FORK_VERSION` for this message signature validation for EIP-7044.

The `beacon_aggregate_and_proof` and `beacon_attestation_{subnet_id}` topics are
modified to support the gossip of attestations created in epoch `N` to be
gossiped through the entire range of slots in epoch `N+1` rather than only
through one epoch of slots for EIP-7045.

The specification around the creation, validation, and dissemination of messages
has not changed from the Capella document unless explicitly noted here.

The derivation of the `message-id` remains stable.

The new topics along with the type of the `data` field of a gossipsub message
are given in this table:

| Name                       | Message Type                         |
| -------------------------- | ------------------------------------ |
| `blob_sidecar_{subnet_id}` | `BlobSidecar` [New in Deneb:EIP4844] |

##### Global topics

###### `beacon_block`

The *type* of the payload of this topic changes to the (modified)
`SignedBeaconBlock` found in Deneb.

*[Modified in Deneb:EIP4844]*

New validation:

- _[REJECT]_ The length of KZG commitments is less than or equal to the
  limitation defined in the consensus layer -- i.e. validate that
  `len(signed_beacon_block.message.body.blob_kzg_commitments) <= MAX_BLOBS_PER_BLOCK`

###### `beacon_aggregate_and_proof`

*[Modified in Deneb:EIP7045]*

The following validation is removed:

- _[IGNORE]_ `aggregate.data.slot` is within the last
  `ATTESTATION_PROPAGATION_SLOT_RANGE` slots (with a
  `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance) -- i.e.
  `aggregate.data.slot + ATTESTATION_PROPAGATION_SLOT_RANGE >= current_slot >= aggregate.data.slot`
  (a client MAY queue future aggregates for processing at the appropriate slot).

The following validations are added in its place:

- _[IGNORE]_ `aggregate.data.slot` is equal to or earlier than the
  `current_slot` (with a `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance) -- i.e.
  `aggregate.data.slot <= current_slot` (a client MAY queue future aggregates
  for processing at the appropriate slot).
- _[IGNORE]_ the epoch of `aggregate.data.slot` is either the current or
  previous epoch (with a `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance) -- i.e.
  `compute_epoch_at_slot(aggregate.data.slot) in (get_previous_epoch(state), get_current_epoch(state))`

##### Blob subnets

###### `blob_sidecar_{subnet_id}`

*[New in Deneb:EIP4844]*

This topic is used to propagate blob sidecars, where each blob index maps to
some `subnet_id`.

The following validations MUST pass before forwarding the `blob_sidecar` on the
network, assuming the alias
`block_header = blob_sidecar.signed_block_header.message`:

```python
def validate_blob_sidecar_gossip(
    seen: Seen,
    store: Store,
    state: BeaconState,
    blob_sidecar: BlobSidecar,
    subnet_id: uint64,
    current_time_ms: uint64,
) -> None:
    """
    Validate a BlobSidecar for gossip propagation.
    Raises GossipIgnore or GossipReject on validation failure.
    """
    block_header = blob_sidecar.signed_block_header.message

    # [REJECT] The sidecar's index is consistent with MAX_BLOBS_PER_BLOCK
    if blob_sidecar.index >= MAX_BLOBS_PER_BLOCK:
        raise GossipReject("blob index too large")

    # [REJECT] The sidecar is for the correct subnet
    if compute_subnet_for_blob_sidecar(blob_sidecar.index) != subnet_id:
        raise GossipReject("blob sidecar is for wrong subnet")

    # [IGNORE] The sidecar is not from a future slot (with MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance)
    block_time_ms = compute_time_at_slot_ms(state, block_header.slot)
    if current_time_ms + MAXIMUM_GOSSIP_CLOCK_DISPARITY < block_time_ms:
        raise GossipIgnore("blob sidecar is from a future slot")

    # [IGNORE] The sidecar is from a slot greater than the latest finalized slot
    finalized_slot = compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)
    if block_header.slot <= finalized_slot:
        raise GossipIgnore("blob sidecar is not from a slot greater than the latest finalized slot")

    # [REJECT] The proposer signature of blob_sidecar.signed_block_header is valid
    if block_header.proposer_index >= len(state.validators):
        raise GossipReject("invalid proposer signature")
    proposer = state.validators[block_header.proposer_index]
    domain = get_domain(state, DOMAIN_BEACON_PROPOSER, compute_epoch_at_slot(block_header.slot))
    signing_root = compute_signing_root(block_header, domain)
    if not bls.Verify(proposer.pubkey, signing_root, blob_sidecar.signed_block_header.signature):
        raise GossipReject("invalid proposer signature")

    # [IGNORE] The sidecar's block's parent has been seen
    if block_header.parent_root not in store.blocks:
        raise GossipIgnore("blob sidecar's parent has not been seen")

    # [REJECT] The sidecar's block's parent passes validation
    if store.block_states.get(block_header.parent_root) is None:
        raise GossipReject("blob sidecar's parent failed validation")

    # [REJECT] The sidecar is from a higher slot than the sidecar's block's parent
    parent_block = store.blocks[block_header.parent_root]
    if block_header.slot <= parent_block.slot:
        raise GossipReject("blob sidecar is not from a higher slot than its parent")

    # [REJECT] The current finalized_checkpoint is an ancestor of the sidecar's block
    checkpoint_block = get_checkpoint_block(
        store, block_header.parent_root, store.finalized_checkpoint.epoch
    )
    if checkpoint_block != store.finalized_checkpoint.root:
        raise GossipReject("finalized checkpoint is not an ancestor of blob sidecar's block")

    # [REJECT] The sidecar's inclusion proof is valid
    if not verify_blob_sidecar_inclusion_proof(blob_sidecar):
        raise GossipReject("invalid blob sidecar inclusion proof")

    # [REJECT] The sidecar's blob is valid
    if not verify_blob_kzg_proof(
        blob_sidecar.blob, blob_sidecar.kzg_commitment, blob_sidecar.kzg_proof
    ):
        raise GossipReject("invalid blob KZG proof")

    # [IGNORE] The sidecar is the first sidecar for the tuple
    # (block_header.slot, block_header.proposer_index, blob_sidecar.index)
    sidecar_key = (block_header.proposer_index, block_header.slot, blob_sidecar.index)
    if sidecar_key in seen.blob_sidecar_slots:
        raise GossipIgnore("already seen blob sidecar for this slot/proposer/index")

    # Get state at parent for proposer verification
    parent_state = store.block_states[block_header.parent_root].copy()
    process_slots(parent_state, block_header.slot)

    # [REJECT] The sidecar is proposed by the expected proposer_index for the block's slot
    expected_proposer = get_beacon_proposer_index(parent_state)
    if block_header.proposer_index != expected_proposer:
        raise GossipReject("blob sidecar proposer_index does not match expected proposer")

    # Mark as seen
    seen.blob_sidecar_slots.add(sidecar_key)
```

The `ForkDigest` context epoch is determined by
`compute_epoch_at_slot(blob_sidecar.signed_block_header.message.slot)`.

Per `fork_version = compute_fork_version(epoch)`:

<!-- eth2spec: skip -->

| `fork_version`                 | Chunk SSZ type      |
| ------------------------------ | ------------------- |
| `DENEB_FORK_VERSION` and later | `deneb.BlobSidecar` |

###### Blob retrieval via local execution-layer client

In addition to `BlobSidecarsByRoot` requests, recent blobs MAY be retrieved by
querying the execution layer (i.e. via `engine_getBlobsV1`). Honest nodes SHOULD
query `engine_getBlobsV1` as soon as they receive a valid gossip block that
contains data, and import the returned blobs.

When clients use the local execution layer to retrieve blobs, they MUST behave
as if the corresponding `blob_sidecar` had been received via gossip. In
particular they MUST:

- Publish the corresponding `blob_sidecar` on the `blob_sidecar_{subnet_id}`
  subnet.
- Update gossip rule related data structures (i.e. update the anti-equivocation
  cache).

##### Attestation subnets

###### `beacon_attestation_{subnet_id}`

*[Modified in Deneb:EIP7045]*

The following validation is removed:

- _[IGNORE]_ `attestation.data.slot` is within the last
  `ATTESTATION_PROPAGATION_SLOT_RANGE` slots (with a
  `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance) -- i.e.
  `attestation.data.slot + ATTESTATION_PROPAGATION_SLOT_RANGE >= current_slot >= attestation.data.slot`
  (a client MAY queue future attestations for processing at the appropriate
  slot).

The following validations are added in its place:

- _[IGNORE]_ `attestation.data.slot` is equal to or earlier than the
  `current_slot` (with a `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance) -- i.e.
  `attestation.data.slot <= current_slot` (a client MAY queue future attestation
  for processing at the appropriate slot).
- _[IGNORE]_ the epoch of `attestation.data.slot` is either the current or
  previous epoch (with a `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance) -- i.e.
  `compute_epoch_at_slot(attestation.data.slot) in (get_previous_epoch(state), get_current_epoch(state))`

#### Transitioning the gossip

See gossip transition details found in the
[Altair document](../altair/p2p-interface.md#transitioning-the-gossip) for
details on how to handle transitioning gossip topics for this upgrade.

### The Req/Resp domain

#### Messages

##### BeaconBlocksByRange v2

**Protocol ID:** `/eth2/beacon_chain/req/beacon_blocks_by_range/2/`

The Deneb fork-digest is introduced to the `context` enum to specify Deneb
beacon block type.

<!-- eth2spec: skip -->

| `fork_version`           | Chunk SSZ type                |
| ------------------------ | ----------------------------- |
| `GENESIS_FORK_VERSION`   | `phase0.SignedBeaconBlock`    |
| `ALTAIR_FORK_VERSION`    | `altair.SignedBeaconBlock`    |
| `BELLATRIX_FORK_VERSION` | `bellatrix.SignedBeaconBlock` |
| `CAPELLA_FORK_VERSION`   | `capella.SignedBeaconBlock`   |
| `DENEB_FORK_VERSION`     | `deneb.SignedBeaconBlock`     |

No more than `MAX_REQUEST_BLOCKS_DENEB` may be requested at a time.

##### BeaconBlocksByRoot v2

**Protocol ID:** `/eth2/beacon_chain/req/beacon_blocks_by_root/2/`

<!-- eth2spec: skip -->

| `fork_version`           | Chunk SSZ type                |
| ------------------------ | ----------------------------- |
| `GENESIS_FORK_VERSION`   | `phase0.SignedBeaconBlock`    |
| `ALTAIR_FORK_VERSION`    | `altair.SignedBeaconBlock`    |
| `BELLATRIX_FORK_VERSION` | `bellatrix.SignedBeaconBlock` |
| `CAPELLA_FORK_VERSION`   | `capella.SignedBeaconBlock`   |
| `DENEB_FORK_VERSION`     | `deneb.SignedBeaconBlock`     |

No more than `MAX_REQUEST_BLOCKS_DENEB` may be requested at a time.

*[Modified in Deneb:EIP4844]* Clients SHOULD include a block in the response as
soon as it passes the gossip validation rules. Clients SHOULD NOT respond with
blocks that fail the beacon-chain state transition.

##### BlobSidecarsByRange v1

**Protocol ID:** `/eth2/beacon_chain/req/blob_sidecars_by_range/1/`

*[New in Deneb:EIP4844]*

Request Content:

```
(
  start_slot: Slot
  count: uint64
)
```

Response Content:

```
(
  List[BlobSidecar, MAX_REQUEST_BLOB_SIDECARS]
)
```

Requests blob sidecars in the slot range `[start_slot, start_slot + count)`,
leading up to the current head block as selected by fork choice.

Before consuming the next response chunk, the response reader SHOULD verify the
blob sidecar is well-formatted, has valid inclusion proof, and is correct w.r.t.
the expected KZG commitments through `verify_blob_kzg_proof`.

`BlobSidecarsByRange` is primarily used to sync blobs that may have been missed
on gossip and to sync within the `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS` window.

The request MUST be encoded as an SSZ-container.

The response MUST consist of zero or more `response_chunk`. Each _successful_
`response_chunk` MUST contain a single `BlobSidecar` payload.

Let `blob_serve_range` be
`[max(current_epoch - MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS, DENEB_FORK_EPOCH), current_epoch]`.
Clients MUST keep a record of blob sidecars seen on the epoch range
`blob_serve_range` where `current_epoch` is defined by the current wall-clock
time, and clients MUST support serving requests of blobs on this range.

Peers that are unable to reply to blob sidecar requests within the range
`blob_serve_range` SHOULD respond with error code `3: ResourceUnavailable`. Such
peers that are unable to successfully reply to this range of requests MAY get
descored or disconnected at any time.

*Note*: The above requirement implies that nodes that start from a recent weak
subjectivity checkpoint MUST backfill the local blobs database to at least the
range `blob_serve_range` to be fully compliant with `BlobSidecarsByRange`
requests.

*Note*: Although clients that bootstrap from a weak subjectivity checkpoint can
begin participating in the networking immediately, other peers MAY disconnect
and/or temporarily ban such an un-synced or semi-synced client.

Clients MUST respond with at least the blob sidecars of the first blob-carrying
block that exists in the range, if they have it, and no more than
`MAX_REQUEST_BLOB_SIDECARS` sidecars.

Clients MUST include all blob sidecars of each block from which they include
blob sidecars.

The following blob sidecars, where they exist, MUST be sent in consecutive
`(slot, index)` order.

Slots that do not contain known blobs MUST be skipped, mimicking the behaviour
of the `BlocksByRange` request. Only response chunks with known blobs should
therefore be sent.

Clients MAY limit the number of blob sidecars in the response.

The response MUST contain no more than `count * MAX_BLOBS_PER_BLOCK` blob
sidecars.

Clients MUST respond with blob sidecars from their view of the current fork
choice -- that is, blob sidecars as included by blocks from the single chain
defined by the current head. Of note, blocks from slots before the finalization
MUST lead to the finalized block reported in the `Status` handshake.

Clients MUST respond with blob sidecars that are consistent from a single chain
within the context of the request.

After the initial blob sidecar, clients MAY stop in the process of responding if
their fork choice changes the view of the chain in the context of the request.

For each successful `response_chunk`, the `ForkDigest` context epoch is
determined by
`compute_epoch_at_slot(blob_sidecar.signed_block_header.message.slot)`.

Per `fork_version = compute_fork_version(epoch)`:

<!-- eth2spec: skip -->

| `fork_version`                 | Chunk SSZ type      |
| ------------------------------ | ------------------- |
| `DENEB_FORK_VERSION` and later | `deneb.BlobSidecar` |

##### BlobSidecarsByRoot v1

**Protocol ID:** `/eth2/beacon_chain/req/blob_sidecars_by_root/1/`

*[New in Deneb:EIP4844]*

Request Content:

```
(
  List[BlobIdentifier, MAX_REQUEST_BLOB_SIDECARS]
)
```

Response Content:

```
(
  List[BlobSidecar, MAX_REQUEST_BLOB_SIDECARS]
)
```

Requests sidecars by block root and index. The response is a list of
`BlobSidecar` whose length is less than or equal to the number of requests. It
may be less in the case that the responding peer is missing blocks or sidecars.

Before consuming the next response chunk, the response reader SHOULD verify the
blob sidecar is well-formatted, has valid inclusion proof, and is correct w.r.t.
the expected KZG commitments through `verify_blob_kzg_proof`.

No more than `MAX_REQUEST_BLOB_SIDECARS` may be requested at a time.

`BlobSidecarsByRoot` is primarily used to recover recent blobs (e.g. when
receiving a block with a transaction whose corresponding blob is missing).

The response MUST consist of zero or more `response_chunk`. Each _successful_
`response_chunk` MUST contain a single `BlobSidecar` payload.

Clients MUST support requesting sidecars since `minimum_request_epoch`, where
`minimum_request_epoch = max(finalized_epoch, current_epoch - MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS, DENEB_FORK_EPOCH)`.
If any root in the request content references a block earlier than
`minimum_request_epoch`, peers MAY respond with error code
`3: ResourceUnavailable` or not include the blob sidecar in the response.

Clients MUST respond with at least one sidecar, if they have it. Clients MAY
limit the number of blocks and sidecars in the response.

Clients SHOULD include a sidecar in the response as soon as it passes the gossip
validation rules. Clients SHOULD NOT respond with sidecars related to blocks
that fail gossip validation rules. Clients SHOULD NOT respond with sidecars
related to blocks that fail the beacon-chain state transition

For each successful `response_chunk`, the `ForkDigest` context epoch is
determined by
`compute_epoch_at_slot(blob_sidecar.signed_block_header.message.slot)`.

Per `fork_version = compute_fork_version(epoch)`:

<!-- eth2spec: skip -->

| `fork_version`                 | Chunk SSZ type      |
| ------------------------------ | ------------------- |
| `DENEB_FORK_VERSION` and later | `deneb.BlobSidecar` |

## Design decision rationale

### Why are blobs relayed as a sidecar, separate from beacon blocks?

This "sidecar" design provides forward compatibility for further data increases
by black-boxing `is_data_available()`: with full sharding `is_data_available()`
can be replaced by data-availability-sampling (DAS) thus avoiding all blobs
being downloaded by all beacon nodes on the network.

Such sharding design may introduce an updated `BlobSidecar` to identify the
shard, but does not affect the `BeaconBlock` structure.

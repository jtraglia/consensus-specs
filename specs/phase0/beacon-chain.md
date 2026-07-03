# Phase 0 -- The Beacon Chain

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Introduction](#introduction)
- [Notation](#notation)
- [Types](#types)
- [Constants](#constants)
  - [Misc](#misc)
  - [Withdrawal prefixes](#withdrawal-prefixes)
  - [Domains](#domains)
- [Preset](#preset)
  - [Misc](#misc-1)
  - [Gwei values](#gwei-values)
  - [Time parameters](#time-parameters)
  - [State list lengths](#state-list-lengths)
  - [Rewards and penalties](#rewards-and-penalties)
  - [Max operations per block](#max-operations-per-block)
- [Configuration](#configuration)
  - [Genesis settings](#genesis-settings)
  - [Time parameters](#time-parameters-1)
  - [Validator cycle](#validator-cycle)
- [Containers](#containers)
  - [Misc dependencies](#misc-dependencies)
    - [`Fork`](#fork)
    - [`ForkData`](#forkdata)
    - [`Checkpoint`](#checkpoint)
    - [`Validator`](#validator)
    - [`AttestationData`](#attestationdata)
    - [`AttestingIndices`](#attestingindices)
    - [`IndexedAttestation`](#indexedattestation)
    - [`AggregationBits`](#aggregationbits)
    - [`PendingAttestation`](#pendingattestation)
    - [`Eth1Data`](#eth1data)
    - [`BlockRoots`](#blockroots)
    - [`StateRoots`](#stateroots)
    - [`HistoricalBatch`](#historicalbatch)
    - [`DepositMessage`](#depositmessage)
    - [`DepositData`](#depositdata)
    - [`BeaconBlockHeader`](#beaconblockheader)
    - [`SigningData`](#signingdata)
  - [Beacon operations](#beacon-operations)
    - [`ProposerSlashing`](#proposerslashing)
    - [`AttesterSlashing`](#attesterslashing)
    - [`Attestation`](#attestation)
    - [`DepositProof`](#depositproof)
    - [`Deposit`](#deposit)
    - [`VoluntaryExit`](#voluntaryexit)
  - [Beacon blocks](#beacon-blocks)
    - [`ProposerSlashings`](#proposerslashings)
    - [`AttesterSlashings`](#attesterslashings)
    - [`Attestations`](#attestations)
    - [`Deposits`](#deposits)
    - [`VoluntaryExits`](#voluntaryexits)
    - [`BeaconBlockBody`](#beaconblockbody)
    - [`BeaconBlock`](#beaconblock)
  - [Beacon state](#beacon-state)
    - [`HistoricalRoots`](#historicalroots)
    - [`Eth1DataVotes`](#eth1datavotes)
    - [`Validators`](#validators)
    - [`Balances`](#balances)
    - [`RandaoMixes`](#randaomixes)
    - [`Slashings`](#slashings)
    - [`PendingAttestations`](#pendingattestations)
    - [`JustificationBits`](#justificationbits)
    - [`BeaconState`](#beaconstate)
  - [Signed envelopes](#signed-envelopes)
    - [`SignedVoluntaryExit`](#signedvoluntaryexit)
    - [`SignedBeaconBlock`](#signedbeaconblock)
    - [`SignedBeaconBlockHeader`](#signedbeaconblockheader)
- [Helpers](#helpers)
  - [Math](#math)
    - [`integer_squareroot`](#integer_squareroot)
    - [`xor`](#xor)
    - [`uint_to_bytes`](#uint_to_bytes)
    - [`bytes_to_uint64`](#bytes_to_uint64)
  - [Crypto](#crypto)
    - [`hash`](#hash)
    - [`hash_tree_root`](#hash_tree_root)
    - [BLS signatures](#bls-signatures)
  - [Predicates](#predicates)
    - [`is_active_validator`](#is_active_validator)
    - [`is_eligible_for_activation_queue`](#is_eligible_for_activation_queue)
    - [`is_eligible_for_activation`](#is_eligible_for_activation)
    - [`is_slashable_validator`](#is_slashable_validator)
    - [`is_slashable_attestation_data`](#is_slashable_attestation_data)
    - [`is_valid_indexed_attestation`](#is_valid_indexed_attestation)
    - [`compute_merkle_branch_root`](#compute_merkle_branch_root)
    - [`is_valid_merkle_branch`](#is_valid_merkle_branch)
  - [Misc](#misc-2)
    - [`compute_shuffled_permutation`](#compute_shuffled_permutation)
    - [`compute_shuffled_index`](#compute_shuffled_index)
    - [`compute_proposer_index`](#compute_proposer_index)
    - [`compute_committee`](#compute_committee)
    - [`compute_time_at_slot`](#compute_time_at_slot)
    - [`compute_epoch_at_slot`](#compute_epoch_at_slot)
    - [`compute_start_slot_at_epoch`](#compute_start_slot_at_epoch)
    - [`compute_activation_exit_epoch`](#compute_activation_exit_epoch)
    - [`compute_fork_data_root`](#compute_fork_data_root)
    - [`compute_domain`](#compute_domain)
    - [`compute_signing_root`](#compute_signing_root)
  - [Beacon state accessors](#beacon-state-accessors)
    - [`get_current_epoch`](#get_current_epoch)
    - [`get_previous_epoch`](#get_previous_epoch)
    - [`get_block_root`](#get_block_root)
    - [`get_block_root_at_slot`](#get_block_root_at_slot)
    - [`get_randao_mix`](#get_randao_mix)
    - [`get_active_validator_indices`](#get_active_validator_indices)
    - [`get_validator_churn_limit`](#get_validator_churn_limit)
    - [`get_seed`](#get_seed)
    - [`get_committee_count_per_slot`](#get_committee_count_per_slot)
    - [`get_beacon_committee`](#get_beacon_committee)
    - [`get_beacon_proposer_index`](#get_beacon_proposer_index)
    - [`get_total_balance`](#get_total_balance)
    - [`get_total_active_balance`](#get_total_active_balance)
    - [`get_domain`](#get_domain)
    - [`get_indexed_attestation`](#get_indexed_attestation)
    - [`get_attesting_indices`](#get_attesting_indices)
  - [Beacon state mutators](#beacon-state-mutators)
    - [`increase_balance`](#increase_balance)
    - [`decrease_balance`](#decrease_balance)
    - [`initiate_validator_exit`](#initiate_validator_exit)
    - [`slash_validator`](#slash_validator)
- [Genesis](#genesis)
  - [Genesis state](#genesis-state)
  - [Genesis block](#genesis-block)
- [Beacon chain state transition function](#beacon-chain-state-transition-function)
  - [Epoch processing](#epoch-processing)
    - [Helpers](#helpers-1)
    - [Justification and finalization](#justification-and-finalization)
    - [Rewards and penalties](#rewards-and-penalties-1)
      - [Helpers](#helpers-2)
      - [Components of attestation deltas](#components-of-attestation-deltas)
      - [`get_attestation_deltas`](#get_attestation_deltas)
      - [`process_rewards_and_penalties`](#process_rewards_and_penalties)
    - [Registry updates](#registry-updates)
    - [Slashings](#slashings)
    - [Eth1 data votes updates](#eth1-data-votes-updates)
    - [Effective balances updates](#effective-balances-updates)
    - [Slashings balances updates](#slashings-balances-updates)
    - [Randao mixes updates](#randao-mixes-updates)
    - [Historical roots updates](#historical-roots-updates)
    - [Participation records rotation](#participation-records-rotation)
  - [Block processing](#block-processing)
    - [Block header](#block-header)
    - [RANDAO](#randao)
    - [Eth1 data](#eth1-data)
    - [Operations](#operations)
      - [Proposer slashings](#proposer-slashings)
      - [Attester slashings](#attester-slashings)
      - [Attestations](#attestations)
      - [Deposits](#deposits)
      - [Voluntary exits](#voluntary-exits)

<!-- mdformat-toc end -->

## Introduction

This document represents the specification for Phase 0 -- The Beacon Chain.

At the core of Ethereum proof-of-stake is a system chain called the "beacon
chain". The beacon chain stores and manages the registry of validators. In the
initial deployment phases of proof-of-stake, the only mechanism to become a
validator is to make a one-way ETH transaction to a deposit contract on the
Ethereum proof-of-work chain. Activation as a validator happens when deposit
receipts are processed by the beacon chain, the activation balance is reached,
and a queuing process is completed. Exit is either voluntary or done forcibly as
a penalty for misbehavior. The primary source of load on the beacon chain is
"attestations". Attestations are simultaneously availability votes for a shard
block (in a later upgrade) and proof-of-stake votes for a beacon block (Phase
0).

## Notation

Code snippets appearing in `this style` are to be interpreted as Python 3 code.

## Types

We define the following Python custom types for type hinting and readability:

| Name             | SSZ equivalent | Description                       |
| ---------------- | -------------- | --------------------------------- |
| `Slot`           | `Uint64`       | A slot number                     |
| `Epoch`          | `Uint64`       | An epoch number                   |
| `CommitteeIndex` | `Uint64`       | A committee index at a slot       |
| `ValidatorIndex` | `Uint64`       | A validator registry index        |
| `Gwei`           | `Uint64`       | An amount in Gwei                 |
| `Root`           | `Bytes32`      | A Merkle root                     |
| `Hash32`         | `Bytes32`      | A 256-bit hash                    |
| `Version`        | `Bytes4`       | A fork version number             |
| `DomainType`     | `Bytes4`       | A domain type                     |
| `ForkDigest`     | `Bytes4`       | A digest of the current fork data |
| `Domain`         | `Bytes32`      | A signature domain                |
| `BLSPubkey`      | `Bytes48`      | A BLS12-381 public key            |
| `BLSSignature`   | `Bytes96`      | A BLS12-381 signature             |

## Constants

The following values are (non-configurable) constants used throughout the
specification.

### Misc

| Name                          | Value                 |
| ----------------------------- | --------------------- |
| `UINT64_MAX`                  | `Uint64(2**64 - 1)`   |
| `UINT64_MAX_SQRT`             | `Uint64(4294967295)`  |
| `GENESIS_SLOT`                | `Slot(0)`             |
| `GENESIS_EPOCH`               | `Epoch(0)`            |
| `FAR_FUTURE_EPOCH`            | `Epoch(2**64 - 1)`    |
| `BASE_REWARDS_PER_EPOCH`      | `Uint64(4)`           |
| `DEPOSIT_CONTRACT_TREE_DEPTH` | `Uint64(2**5)` (= 32) |
| `JUSTIFICATION_BITS_LENGTH`   | `Uint64(4)`           |
| `ENDIANNESS`                  | `'little'`            |

### Withdrawal prefixes

| Name                             | Value            |
| -------------------------------- | ---------------- |
| `BLS_WITHDRAWAL_PREFIX`          | `Bytes1('0x00')` |
| `ETH1_ADDRESS_WITHDRAWAL_PREFIX` | `Bytes1('0x01')` |

### Domains

| Name                         | Value                      |
| ---------------------------- | -------------------------- |
| `DOMAIN_BEACON_PROPOSER`     | `DomainType('0x00000000')` |
| `DOMAIN_BEACON_ATTESTER`     | `DomainType('0x01000000')` |
| `DOMAIN_RANDAO`              | `DomainType('0x02000000')` |
| `DOMAIN_DEPOSIT`             | `DomainType('0x03000000')` |
| `DOMAIN_VOLUNTARY_EXIT`      | `DomainType('0x04000000')` |
| `DOMAIN_SELECTION_PROOF`     | `DomainType('0x05000000')` |
| `DOMAIN_AGGREGATE_AND_PROOF` | `DomainType('0x06000000')` |
| `DOMAIN_APPLICATION_MASK`    | `DomainType('0x00000001')` |

*Note*: `DOMAIN_APPLICATION_MASK` reserves the rest of the bitspace in
`DomainType` for application usage. This means for some `DomainType`
`DOMAIN_SOME_APPLICATION`, `DOMAIN_SOME_APPLICATION & DOMAIN_APPLICATION_MASK`
**MUST** be non-zero. This expression for any other `DomainType` in the
consensus-layer specifications **MUST** be zero.

## Preset

*Note*: The below configuration is bundled as a preset: a bundle of
configuration variables which are expected to differ between different modes of
operation, e.g. testing, but not generally between different networks.
Additional preset configurations can be found in the [`configs`](../../configs)
directory.

### Misc

| Name                             | Value                     |
| -------------------------------- | ------------------------- |
| `MAX_COMMITTEES_PER_SLOT`        | `Uint64(2**6)` (= 64)     |
| `TARGET_COMMITTEE_SIZE`          | `Uint64(2**7)` (= 128)    |
| `MAX_VALIDATORS_PER_COMMITTEE`   | `Uint64(2**11)` (= 2,048) |
| `SHUFFLE_ROUND_COUNT`            | `Uint64(90)`              |
| `HYSTERESIS_QUOTIENT`            | `Uint64(4)`               |
| `HYSTERESIS_DOWNWARD_MULTIPLIER` | `Uint64(1)`               |
| `HYSTERESIS_UPWARD_MULTIPLIER`   | `Uint64(5)`               |

- For the safety of committees, `TARGET_COMMITTEE_SIZE` exceeds
  [the recommended minimum committee size of 111](http://web.archive.org/web/20190504131341/https://vitalik.ca/files/Ithaca201807_Sharding.pdf);
  with sufficient active validators (at least
  `SLOTS_PER_EPOCH * TARGET_COMMITTEE_SIZE`), the shuffling algorithm ensures
  committee sizes of at least `TARGET_COMMITTEE_SIZE`. (Unbiasable randomness
  with a Verifiable Delay Function (VDF) will improve committee robustness and
  lower the safe minimum committee size.)

### Gwei values

| Name                          | Value                                   |
| ----------------------------- | --------------------------------------- |
| `MIN_DEPOSIT_AMOUNT`          | `Gwei(2**0 * 10**9)` (= 1,000,000,000)  |
| `MAX_EFFECTIVE_BALANCE`       | `Gwei(2**5 * 10**9)` (= 32,000,000,000) |
| `EFFECTIVE_BALANCE_INCREMENT` | `Gwei(2**0 * 10**9)` (= 1,000,000,000)  |

### Time parameters

| Name                               | Value                     | Unit   |
| ---------------------------------- | ------------------------- | ------ |
| `MIN_ATTESTATION_INCLUSION_DELAY`  | `Uint64(2**0)` (= 1)      | slots  |
| `SLOTS_PER_EPOCH`                  | `Uint64(2**5)` (= 32)     | slots  |
| `MIN_SEED_LOOKAHEAD`               | `Uint64(2**0)` (= 1)      | epochs |
| `MAX_SEED_LOOKAHEAD`               | `Uint64(2**2)` (= 4)      | epochs |
| `MIN_EPOCHS_TO_INACTIVITY_PENALTY` | `Uint64(2**2)` (= 4)      | epochs |
| `EPOCHS_PER_ETH1_VOTING_PERIOD`    | `Uint64(2**6)` (= 64)     | epochs |
| `SLOTS_PER_HISTORICAL_ROOT`        | `Uint64(2**13)` (= 8,192) | slots  |

### State list lengths

| Name                           | Value                                 | Unit             |
| ------------------------------ | ------------------------------------- | ---------------- |
| `EPOCHS_PER_HISTORICAL_VECTOR` | `Uint64(2**16)` (= 65,536)            | epochs           |
| `EPOCHS_PER_SLASHINGS_VECTOR`  | `Uint64(2**13)` (= 8,192)             | epochs           |
| `HISTORICAL_ROOTS_LIMIT`       | `Uint64(2**24)` (= 16,777,216)        | historical roots |
| `VALIDATOR_REGISTRY_LIMIT`     | `Uint64(2**40)` (= 1,099,511,627,776) | validators       |

### Rewards and penalties

| Name                               | Value                          |
| ---------------------------------- | ------------------------------ |
| `BASE_REWARD_FACTOR`               | `Uint64(2**6)` (= 64)          |
| `WHISTLEBLOWER_REWARD_QUOTIENT`    | `Uint64(2**9)` (= 512)         |
| `PROPOSER_REWARD_QUOTIENT`         | `Uint64(2**3)` (= 8)           |
| `INACTIVITY_PENALTY_QUOTIENT`      | `Uint64(2**26)` (= 67,108,864) |
| `MIN_SLASHING_PENALTY_QUOTIENT`    | `Uint64(2**7)` (= 128)         |
| `PROPORTIONAL_SLASHING_MULTIPLIER` | `Uint64(1)`                    |

- The `INACTIVITY_PENALTY_QUOTIENT` equals `INVERSE_SQRT_E_DROP_TIME**2` where
  `INVERSE_SQRT_E_DROP_TIME := 2**13` epochs is the time it takes the inactivity
  penalty to reduce the balance of non-participating validators to about
  `1/sqrt(e) ~= 60.6%`. Indeed, the balance retained by offline validators after
  `n` epochs is about `(1 - 1/INACTIVITY_PENALTY_QUOTIENT)**(n**2/2)`; so after
  `INVERSE_SQRT_E_DROP_TIME` epochs, it is roughly
  `(1 - 1/INACTIVITY_PENALTY_QUOTIENT)**(INACTIVITY_PENALTY_QUOTIENT/2) ~= 1/sqrt(e)`.
  Note this value will be upgraded to `2**24` after Phase 0 mainnet stabilizes
  to provide a faster recovery in the event of an inactivity leak.

- The `PROPORTIONAL_SLASHING_MULTIPLIER` is set to `1` at initial mainnet
  launch, resulting in one-third of the minimum accountable safety margin in the
  event of a finality attack. After Phase 0 mainnet stabilizes, this value will
  be upgraded to `3` to provide the maximal minimum accountable safety margin.

### Max operations per block

| Name                     | Value                  |
| ------------------------ | ---------------------- |
| `MAX_PROPOSER_SLASHINGS` | `Uint64(2**4)` (= 16)  |
| `MAX_ATTESTER_SLASHINGS` | `Uint64(2**1)` (= 2)   |
| `MAX_ATTESTATIONS`       | `Uint64(2**7)` (= 128) |
| `MAX_DEPOSITS`           | `Uint64(2**4)` (= 16)  |
| `MAX_VOLUNTARY_EXITS`    | `Uint64(2**4)` (= 16)  |

## Configuration

*Note*: The default mainnet configuration values are included here for
illustrative purposes. Defaults for this more dynamic type of configuration are
available with the presets in the [`configs`](../../configs) directory. Testnets
and other types of chain instances may use a different configuration.

### Genesis settings

| Name                                 | Value                                        |
| ------------------------------------ | -------------------------------------------- |
| `MIN_GENESIS_ACTIVE_VALIDATOR_COUNT` | `Uint64(2**14)` (= 16,384)                   |
| `MIN_GENESIS_TIME`                   | `Uint64(1606824000)` (Dec 1, 2020, 12pm UTC) |
| `GENESIS_FORK_VERSION`               | `Version('0x00000000')`                      |
| `GENESIS_DELAY`                      | `Uint64(604800)` (7 days)                    |

### Time parameters

| Name                                  | Value                     | Unit         |
| ------------------------------------- | ------------------------- | ------------ |
| `SLOT_DURATION_MS`                    | `Uint64(12000)`           | milliseconds |
| `SECONDS_PER_ETH1_BLOCK`              | `Uint64(14)`              | seconds      |
| `MIN_VALIDATOR_WITHDRAWABILITY_DELAY` | `Uint64(2**8)` (= 256)    | epochs       |
| `SHARD_COMMITTEE_PERIOD`              | `Uint64(2**8)` (= 256)    | epochs       |
| `ETH1_FOLLOW_DISTANCE`                | `Uint64(2**11)` (= 2,048) | Eth1 blocks  |

### Validator cycle

| Name                        | Value                                   |
| --------------------------- | --------------------------------------- |
| `EJECTION_BALANCE`          | `Gwei(2**4 * 10**9)` (= 16,000,000,000) |
| `MIN_PER_EPOCH_CHURN_LIMIT` | `Uint64(2**2)` (= 4)                    |
| `CHURN_LIMIT_QUOTIENT`      | `Uint64(2**16)` (= 65,536)              |

## Containers

The following types are [SimpleSerialize (SSZ)](../../ssz/simple-serialize.md)
containers.

*Note*: The definitions are ordered topologically to facilitate execution of the
specification.

*Note*: Fields missing in container instantiations default to their zero value.

### Misc dependencies

#### `Fork`

```python
class Fork(Container):
    previous_version: Version
    current_version: Version
    epoch: Epoch
```

#### `ForkData`

```python
class ForkData(Container):
    current_version: Version
    genesis_validators_root: Root
```

#### `Checkpoint`

```python
class Checkpoint(Container):
    epoch: Epoch
    root: Root
```

#### `Validator`

```python
class Validator(Container):
    pubkey: BLSPubkey
    withdrawal_credentials: Bytes32
    effective_balance: Gwei
    slashed: Boolean
    activation_eligibility_epoch: Epoch
    activation_epoch: Epoch
    exit_epoch: Epoch
    withdrawable_epoch: Epoch
```

#### `AttestationData`

```python
class AttestationData(Container):
    slot: Slot
    index: CommitteeIndex
    beacon_block_root: Root
    source: Checkpoint
    target: Checkpoint
```

#### `AttestingIndices`

```python
class AttestingIndices(List[ValidatorIndex]):
    LIMIT = MAX_VALIDATORS_PER_COMMITTEE
```

#### `IndexedAttestation`

```python
class IndexedAttestation(Container):
    attesting_indices: AttestingIndices
    data: AttestationData
    signature: BLSSignature
```

#### `AggregationBits`

```python
class AggregationBits(Bitlist):
    LIMIT = MAX_VALIDATORS_PER_COMMITTEE
```

#### `PendingAttestation`

```python
class PendingAttestation(Container):
    aggregation_bits: AggregationBits
    data: AttestationData
    inclusion_delay: Slot
    proposer_index: ValidatorIndex
```

#### `Eth1Data`

```python
class Eth1Data(Container):
    deposit_root: Root
    deposit_count: Uint64
    block_hash: Hash32
```

#### `BlockRoots`

```python
class BlockRoots(Vector[Root]):
    LENGTH = SLOTS_PER_HISTORICAL_ROOT
```

#### `StateRoots`

```python
class StateRoots(Vector[Root]):
    LENGTH = SLOTS_PER_HISTORICAL_ROOT
```

#### `HistoricalBatch`

```python
class HistoricalBatch(Container):
    block_roots: BlockRoots
    state_roots: StateRoots
```

#### `DepositMessage`

```python
class DepositMessage(Container):
    pubkey: BLSPubkey
    withdrawal_credentials: Bytes32
    amount: Gwei
```

#### `DepositData`

*Note*: `signature` is over `DepositMessage`.

```python
class DepositData(Container):
    pubkey: BLSPubkey
    withdrawal_credentials: Bytes32
    amount: Gwei
    signature: BLSSignature
```

#### `BeaconBlockHeader`

```python
class BeaconBlockHeader(Container):
    slot: Slot
    proposer_index: ValidatorIndex
    parent_root: Root
    state_root: Root
    body_root: Root
```

#### `SigningData`

```python
class SigningData(Container):
    object_root: Root
    domain: Domain
```

### Beacon operations

#### `ProposerSlashing`

```python
class ProposerSlashing(Container):
    signed_header_1: SignedBeaconBlockHeader
    signed_header_2: SignedBeaconBlockHeader
```

#### `AttesterSlashing`

```python
class AttesterSlashing(Container):
    attestation_1: IndexedAttestation
    attestation_2: IndexedAttestation
```

#### `Attestation`

```python
class Attestation(Container):
    aggregation_bits: AggregationBits
    data: AttestationData
    signature: BLSSignature
```

#### `DepositProof`

```python
class DepositProof(Vector[Bytes32]):
    LENGTH = DEPOSIT_CONTRACT_TREE_DEPTH + Uint64(1)
```

#### `Deposit`

*Note*: `proof` is the Merkle path to the deposit root.

```python
class Deposit(Container):
    proof: DepositProof
    data: DepositData
```

#### `VoluntaryExit`

```python
class VoluntaryExit(Container):
    epoch: Epoch
    validator_index: ValidatorIndex
```

### Beacon blocks

#### `ProposerSlashings`

```python
class ProposerSlashings(List[ProposerSlashing]):
    LIMIT = MAX_PROPOSER_SLASHINGS
```

#### `AttesterSlashings`

```python
class AttesterSlashings(List[AttesterSlashing]):
    LIMIT = MAX_ATTESTER_SLASHINGS
```

#### `Attestations`

```python
class Attestations(List[Attestation]):
    LIMIT = MAX_ATTESTATIONS
```

#### `Deposits`

```python
class Deposits(List[Deposit]):
    LIMIT = MAX_DEPOSITS
```

#### `VoluntaryExits`

```python
class VoluntaryExits(List[SignedVoluntaryExit]):
    LIMIT = MAX_VOLUNTARY_EXITS
```

#### `BeaconBlockBody`

```python
class BeaconBlockBody(Container):
    randao_reveal: BLSSignature
    eth1_data: Eth1Data
    graffiti: Bytes32
    proposer_slashings: ProposerSlashings
    attester_slashings: AttesterSlashings
    attestations: Attestations
    deposits: Deposits
    voluntary_exits: VoluntaryExits
```

#### `BeaconBlock`

```python
class BeaconBlock(Container):
    slot: Slot
    proposer_index: ValidatorIndex
    parent_root: Root
    state_root: Root
    body: BeaconBlockBody
```

### Beacon state

#### `HistoricalRoots`

```python
class HistoricalRoots(List[Root]):
    LIMIT = HISTORICAL_ROOTS_LIMIT
```

#### `Eth1DataVotes`

```python
class Eth1DataVotes(List[Eth1Data]):
    LIMIT = EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH
```

#### `Validators`

```python
class Validators(List[Validator]):
    LIMIT = VALIDATOR_REGISTRY_LIMIT
```

#### `Balances`

```python
class Balances(List[Gwei]):
    LIMIT = VALIDATOR_REGISTRY_LIMIT
```

#### `RandaoMixes`

```python
class RandaoMixes(Vector[Bytes32]):
    LENGTH = EPOCHS_PER_HISTORICAL_VECTOR
```

#### `Slashings`

```python
class Slashings(Vector[Gwei]):
    LENGTH = EPOCHS_PER_SLASHINGS_VECTOR
```

#### `PendingAttestations`

```python
class PendingAttestations(List[PendingAttestation]):
    LIMIT = MAX_ATTESTATIONS * SLOTS_PER_EPOCH
```

#### `JustificationBits`

```python
class JustificationBits(Bitvector):
    LENGTH = JUSTIFICATION_BITS_LENGTH
```

#### `BeaconState`

```python
class BeaconState(Container):
    genesis_time: Uint64
    genesis_validators_root: Root
    slot: Slot
    fork: Fork
    latest_block_header: BeaconBlockHeader
    block_roots: BlockRoots
    state_roots: StateRoots
    historical_roots: HistoricalRoots
    eth1_data: Eth1Data
    eth1_data_votes: Eth1DataVotes
    eth1_deposit_index: Uint64
    validators: Validators
    balances: Balances
    randao_mixes: RandaoMixes
    slashings: Slashings
    previous_epoch_attestations: PendingAttestations
    current_epoch_attestations: PendingAttestations
    justification_bits: JustificationBits
    previous_justified_checkpoint: Checkpoint
    current_justified_checkpoint: Checkpoint
    finalized_checkpoint: Checkpoint
```

### Signed envelopes

#### `SignedVoluntaryExit`

```python
class SignedVoluntaryExit(Container):
    message: VoluntaryExit
    signature: BLSSignature
```

#### `SignedBeaconBlock`

```python
class SignedBeaconBlock(Container):
    message: BeaconBlock
    signature: BLSSignature
```

#### `SignedBeaconBlockHeader`

```python
class SignedBeaconBlockHeader(Container):
    message: BeaconBlockHeader
    signature: BLSSignature
```

## Helpers

*Note*: The definitions below are for specification purposes and are not
necessarily optimal implementations.

### Math

#### `integer_squareroot`

```python
def integer_squareroot(n: Uint64) -> Uint64:
    """
    Return the largest integer ``x`` such that ``x**2 <= n``.
    """
    if n == UINT64_MAX:
        return UINT64_MAX_SQRT
    x = n
    y = (x + Uint64(1)) // Uint64(2)
    while y < x:
        x = y
        y = (x + n // x) // Uint64(2)
    return x
```

#### `xor`

```python
def xor(bytes_1: Bytes32, bytes_2: Bytes32) -> Bytes32:
    """
    Return the exclusive-or of two 32-byte strings.
    """
    return Bytes32(a ^ b for a, b in zip(bytes_1, bytes_2, strict=True))
```

#### `uint_to_bytes`

`def uint_to_bytes(n: Uint) -> bytes` is a function for serializing the `Uint`
type object to bytes in `ENDIANNESS`-endian. The expected length of the output
is the byte-length of the `Uint` type.

#### `bytes_to_uint64`

```python
def bytes_to_uint64(data: bytes) -> Uint64:
    """
    Return the integer deserialization of ``data`` interpreted as ``ENDIANNESS``-endian.
    """
    return Uint64(int.from_bytes(data, ENDIANNESS))
```

### Crypto

#### `hash`

`def hash(data: bytes) -> Bytes32` is SHA256.

#### `hash_tree_root`

`def hash_tree_root(object: SSZSerializable) -> Root` is a function for hashing
objects into a single root by utilizing a hash tree structure, as defined in the
[SSZ specification](../../ssz/simple-serialize.md#merkleization).

#### BLS signatures

The
[IETF BLS signature draft standard v4](https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04)
with ciphersuite `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` defines the
following functions:

- `def Sign(privkey: int, message: Bytes) -> BLSSignature`
- `def Verify(pubkey: BLSPubkey, message: Bytes, signature: BLSSignature) -> bool`
- `def Aggregate(signatures: Sequence[BLSSignature]) -> BLSSignature`
- `def FastAggregateVerify(pubkeys: Sequence[BLSPubkey], message: Bytes, signature: BLSSignature) -> bool`
- `def AggregateVerify(pubkeys: Sequence[BLSPubkey], messages: Sequence[Bytes], signature: BLSSignature) -> bool`
- `def KeyValidate(pubkey: BLSPubkey) -> bool`

The above functions are accessed through the `bls` module, e.g. `bls.Verify`.

### Predicates

#### `is_active_validator`

```python
def is_active_validator(validator: Validator, epoch: Epoch) -> bool:
    """
    Check if ``validator`` is active.
    """
    return validator.activation_epoch <= epoch < validator.exit_epoch
```

#### `is_eligible_for_activation_queue`

```python
def is_eligible_for_activation_queue(validator: Validator) -> bool:
    """
    Check if ``validator`` is eligible to be placed into the activation queue.
    """
    return (
        validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH
        and validator.effective_balance == MAX_EFFECTIVE_BALANCE
    )
```

#### `is_eligible_for_activation`

```python
def is_eligible_for_activation(state: BeaconState, validator: Validator) -> bool:
    """
    Check if ``validator`` is eligible for activation.
    """
    return (
        # Placement in queue is finalized
        validator.activation_eligibility_epoch <= state.finalized_checkpoint.epoch
        # Has not yet been activated
        and validator.activation_epoch == FAR_FUTURE_EPOCH
    )
```

#### `is_slashable_validator`

```python
def is_slashable_validator(validator: Validator, epoch: Epoch) -> bool:
    """
    Check if ``validator`` is slashable.
    """
    return (not validator.slashed) and (
        validator.activation_epoch <= epoch < validator.withdrawable_epoch
    )
```

#### `is_slashable_attestation_data`

```python
def is_slashable_attestation_data(data_1: AttestationData, data_2: AttestationData) -> bool:
    """
    Check if ``data_1`` and ``data_2`` are slashable according to Casper FFG rules.
    """
    return (
        # Double vote
        (data_1 != data_2 and data_1.target.epoch == data_2.target.epoch)
        or
        # Surround vote
        (data_1.source.epoch < data_2.source.epoch and data_2.target.epoch < data_1.target.epoch)
    )
```

#### `is_valid_indexed_attestation`

```python
def is_valid_indexed_attestation(
    state: BeaconState, indexed_attestation: IndexedAttestation
) -> bool:
    """
    Check if ``indexed_attestation`` is not empty, has sorted and unique indices and has a valid aggregate signature.
    """
    # Verify indices are sorted and unique
    indices = indexed_attestation.attesting_indices
    if len(indices) == 0 or indices != sorted(set(indices)):
        return False
    # Verify aggregate signature
    pubkeys = [state.validators[i].pubkey for i in indices]
    domain = get_domain(state, DOMAIN_BEACON_ATTESTER, indexed_attestation.data.target.epoch)
    signing_root = compute_signing_root(indexed_attestation.data, domain)
    return bls.FastAggregateVerify(pubkeys, signing_root, indexed_attestation.signature)
```

#### `compute_merkle_branch_root`

```python
def compute_merkle_branch_root(
    leaf: Bytes32, branch: Sequence[Bytes32], depth: Uint64, index: Uint64
) -> Root:
    """
    Return the Merkle root obtained by hashing ``leaf`` at ``index`` with ``branch``.
    """
    value = leaf
    for i in range(depth):
        if index // Uint64(2**i) % Uint64(2):
            value = hash(branch[i] + value)
        else:
            value = hash(value + branch[i])
    return Root(value)
```

#### `is_valid_merkle_branch`

```python
def is_valid_merkle_branch(
    leaf: Bytes32, branch: Sequence[Bytes32], depth: Uint64, index: Uint64, root: Root
) -> bool:
    """
    Check if ``leaf`` at ``index`` verifies against the Merkle ``root`` and ``branch``.
    """
    if int(depth) != len(branch):
        return False
    return compute_merkle_branch_root(leaf, branch, depth, index) == root
```

### Misc

#### `compute_shuffled_permutation`

```python
def compute_shuffled_permutation(index_count: Uint64, seed: Bytes32) -> Sequence[Uint64]:
    """
    Return the full shuffled permutation corresponding to ``seed`` (and ``index_count``).
    """
    # Swap or not (https://link.springer.com/content/pdf/10.1007%2F978-3-642-32009-5_1.pdf)
    # See the 'generalized domain' algorithm on page 3
    indices = [Uint64(i) for i in range(index_count)]
    for current_round in range(SHUFFLE_ROUND_COUNT):
        round_bytes = current_round.to_bytes(1, "little")
        pivot = Uint64(int.from_bytes(hash(seed + round_bytes)[0:8], "little")) % index_count
        source_by_bucket: Dict[Uint64, Bytes32] = {}
        for i in range(index_count):
            flip = (pivot + index_count - indices[i]) % index_count
            position = max(indices[i], flip)
            position_bucket = position // Uint64(256)
            if position_bucket not in source_by_bucket:
                source_by_bucket[position_bucket] = hash(
                    seed + round_bytes + position_bucket.to_bytes(4, "little")
                )
            source = source_by_bucket[position_bucket]
            byte_val = source[(position % Uint64(256)) // Uint64(8)]
            bit = (byte_val >> int(position % Uint64(8))) % 2
            indices[i] = flip if bit else indices[i]
    return indices
```

#### `compute_shuffled_index`

```python
def compute_shuffled_index(index: Uint64, index_count: Uint64, seed: Bytes32) -> Uint64:
    """
    Return the shuffled index corresponding to ``seed`` (and ``index_count``).
    """
    assert index < index_count
    return compute_shuffled_permutation(index_count, seed)[index]
```

#### `compute_proposer_index`

```python
def compute_proposer_index(
    state: BeaconState, indices: Sequence[ValidatorIndex], seed: Bytes32
) -> ValidatorIndex:
    """
    Return from ``indices`` a random index sampled by effective balance.
    """
    assert len(indices) > 0
    MAX_RANDOM_BYTE = 2**8 - 1
    i = Uint64(0)
    total = Uint64(len(indices))
    while True:
        candidate_index = indices[compute_shuffled_index(i % total, total, seed)]
        random_byte = hash(seed + uint_to_bytes(i // Uint64(32)))[i % Uint64(32)]
        effective_balance = state.validators[candidate_index].effective_balance
        if effective_balance * Gwei(MAX_RANDOM_BYTE) >= MAX_EFFECTIVE_BALANCE * Gwei(random_byte):
            return candidate_index
        i += Uint64(1)
```

#### `compute_committee`

```python
def compute_committee(
    indices: Sequence[ValidatorIndex], seed: Bytes32, index: Uint64, count: Uint64
) -> Sequence[ValidatorIndex]:
    """
    Return the committee corresponding to ``indices``, ``seed``, ``index``, and committee ``count``.
    """
    start = (Uint64(len(indices)) * index) // count
    end = (Uint64(len(indices)) * (index + Uint64(1))) // count
    return [
        indices[compute_shuffled_index(Uint64(i), Uint64(len(indices)), seed)]
        for i in range(start, end)
    ]
```

#### `compute_time_at_slot`

*Note*: This function is unsafe with respect to overflows and underflows.

```python
def compute_time_at_slot(state: BeaconState, slot: Slot) -> Uint64:
    slots_since_genesis = slot - GENESIS_SLOT
    return Uint64(
        state.genesis_time + Uint64(slots_since_genesis) * SLOT_DURATION_MS // Uint64(1000)
    )
```

#### `compute_epoch_at_slot`

```python
def compute_epoch_at_slot(slot: Slot) -> Epoch:
    """
    Return the epoch number at ``slot``.
    """
    return Epoch(Uint64(slot) // SLOTS_PER_EPOCH)
```

#### `compute_start_slot_at_epoch`

```python
def compute_start_slot_at_epoch(epoch: Epoch) -> Slot:
    """
    Return the start slot of ``epoch``.
    """
    return Slot(Uint64(epoch) * SLOTS_PER_EPOCH)
```

#### `compute_activation_exit_epoch`

```python
def compute_activation_exit_epoch(epoch: Epoch) -> Epoch:
    """
    Return the epoch during which validator activations and exits initiated in ``epoch`` take effect.
    """
    return epoch + Epoch(1) + Epoch(MAX_SEED_LOOKAHEAD)
```

#### `compute_fork_data_root`

```python
def compute_fork_data_root(current_version: Version, genesis_validators_root: Root) -> Root:
    """
    Return the 32-byte fork data root for the ``current_version`` and ``genesis_validators_root``.
    This is used primarily in signature domains to avoid collisions across forks/chains.
    """
    return hash_tree_root(
        ForkData(
            current_version=current_version,
            genesis_validators_root=genesis_validators_root,
        )
    )
```

#### `compute_domain`

```python
def compute_domain(
    domain_type: DomainType,
    fork_version: Optional[Version] = None,
    genesis_validators_root: Optional[Root] = None,
) -> Domain:
    """
    Return the domain for the ``domain_type`` and ``fork_version``.
    """
    if fork_version is None:
        fork_version = GENESIS_FORK_VERSION
    if genesis_validators_root is None:
        genesis_validators_root = Root()  # all bytes zero by default
    fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root)
    return Domain(domain_type + fork_data_root[:28])
```

#### `compute_signing_root`

```python
def compute_signing_root(ssz_object: SSZObject, domain: Domain) -> Root:
    """
    Return the signing root for the corresponding signing data.
    """
    return hash_tree_root(
        SigningData(
            object_root=hash_tree_root(ssz_object),
            domain=domain,
        )
    )
```

### Beacon state accessors

#### `get_current_epoch`

```python
def get_current_epoch(state: BeaconState) -> Epoch:
    """
    Return the current epoch.
    """
    return compute_epoch_at_slot(state.slot)
```

#### `get_previous_epoch`

```python
def get_previous_epoch(state: BeaconState) -> Epoch:
    """`
    Return the previous epoch (unless the current epoch is ``GENESIS_EPOCH``).
    """
    current_epoch = get_current_epoch(state)
    return GENESIS_EPOCH if current_epoch == GENESIS_EPOCH else current_epoch - Epoch(1)
```

#### `get_block_root`

```python
def get_block_root(state: BeaconState, epoch: Epoch) -> Root:
    """
    Return the block root at the start of a recent ``epoch``.
    """
    return get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch))
```

#### `get_block_root_at_slot`

```python
def get_block_root_at_slot(state: BeaconState, slot: Slot) -> Root:
    """
    Return the block root at a recent ``slot``.
    """
    assert slot < state.slot <= slot + Slot(SLOTS_PER_HISTORICAL_ROOT)
    return state.block_roots[Uint64(slot) % SLOTS_PER_HISTORICAL_ROOT]
```

#### `get_randao_mix`

```python
def get_randao_mix(state: BeaconState, epoch: Epoch) -> Bytes32:
    """
    Return the randao mix at a recent ``epoch``.
    """
    return state.randao_mixes[Uint64(epoch) % EPOCHS_PER_HISTORICAL_VECTOR]
```

#### `get_active_validator_indices`

```python
def get_active_validator_indices(state: BeaconState, epoch: Epoch) -> Sequence[ValidatorIndex]:
    """
    Return the sequence of active validator indices at ``epoch``.
    """
    return [
        ValidatorIndex(i) for i, v in enumerate(state.validators) if is_active_validator(v, epoch)
    ]
```

#### `get_validator_churn_limit`

```python
def get_validator_churn_limit(state: BeaconState) -> Uint64:
    """
    Return the validator churn limit for the current epoch.
    """
    active_validator_indices = get_active_validator_indices(state, get_current_epoch(state))
    return max(
        MIN_PER_EPOCH_CHURN_LIMIT, Uint64(len(active_validator_indices)) // CHURN_LIMIT_QUOTIENT
    )
```

#### `get_seed`

```python
def get_seed(state: BeaconState, epoch: Epoch, domain_type: DomainType) -> Bytes32:
    """
    Return the seed at ``epoch``.
    """
    mix = get_randao_mix(
        state,
        epoch + Epoch(EPOCHS_PER_HISTORICAL_VECTOR) - Epoch(MIN_SEED_LOOKAHEAD) - Epoch(1),
    )  # Avoid underflow
    return hash(domain_type + uint_to_bytes(epoch) + mix)
```

#### `get_committee_count_per_slot`

```python
def get_committee_count_per_slot(state: BeaconState, epoch: Epoch) -> Uint64:
    """
    Return the number of committees in each slot for the given ``epoch``.
    """
    return max(
        Uint64(1),
        min(
            MAX_COMMITTEES_PER_SLOT,
            Uint64(len(get_active_validator_indices(state, epoch)))
            // SLOTS_PER_EPOCH
            // TARGET_COMMITTEE_SIZE,
        ),
    )
```

#### `get_beacon_committee`

```python
def get_beacon_committee(
    state: BeaconState, slot: Slot, index: CommitteeIndex
) -> Sequence[ValidatorIndex]:
    """
    Return the beacon committee at ``slot`` for ``index``.
    """
    epoch = compute_epoch_at_slot(slot)
    committees_per_slot = get_committee_count_per_slot(state, epoch)
    return compute_committee(
        indices=get_active_validator_indices(state, epoch),
        seed=get_seed(state, epoch, DOMAIN_BEACON_ATTESTER),
        index=(Uint64(slot) % SLOTS_PER_EPOCH) * committees_per_slot + Uint64(index),
        count=committees_per_slot * SLOTS_PER_EPOCH,
    )
```

#### `get_beacon_proposer_index`

```python
def get_beacon_proposer_index(state: BeaconState) -> ValidatorIndex:
    """
    Return the beacon proposer index at the current slot.
    """
    epoch = get_current_epoch(state)
    seed = hash(get_seed(state, epoch, DOMAIN_BEACON_PROPOSER) + uint_to_bytes(state.slot))
    indices = get_active_validator_indices(state, epoch)
    return compute_proposer_index(state, indices, seed)
```

#### `get_total_balance`

```python
def get_total_balance(state: BeaconState, indices: Set[ValidatorIndex]) -> Gwei:
    """
    Return the combined effective balance of the ``indices``.
    ``EFFECTIVE_BALANCE_INCREMENT`` Gwei minimum to avoid divisions by zero.
    Math safe up to ~10B ETH, after which this overflows Uint64.
    """
    return Gwei(
        max(
            EFFECTIVE_BALANCE_INCREMENT,
            sum([state.validators[index].effective_balance for index in indices], Gwei(0)),
        )
    )
```

#### `get_total_active_balance`

```python
def get_total_active_balance(state: BeaconState) -> Gwei:
    """
    Return the combined effective balance of the active validators.
    Note: ``get_total_balance`` returns ``EFFECTIVE_BALANCE_INCREMENT`` Gwei minimum to avoid divisions by zero.
    """
    return get_total_balance(
        state, set(get_active_validator_indices(state, get_current_epoch(state)))
    )
```

#### `get_domain`

```python
def get_domain(
    state: BeaconState, domain_type: DomainType, epoch: Optional[Epoch] = None
) -> Domain:
    """
    Return the signature domain (fork version concatenated with domain type) of a message.
    """
    epoch = get_current_epoch(state) if epoch is None else epoch
    fork_version = (
        state.fork.previous_version if epoch < state.fork.epoch else state.fork.current_version
    )
    return compute_domain(domain_type, fork_version, state.genesis_validators_root)
```

#### `get_indexed_attestation`

```python
def get_indexed_attestation(state: BeaconState, attestation: Attestation) -> IndexedAttestation:
    """
    Return the indexed attestation corresponding to ``attestation``.
    """
    attesting_indices = get_attesting_indices(state, attestation)

    return IndexedAttestation(
        attesting_indices=sorted(attesting_indices),
        data=attestation.data,
        signature=attestation.signature,
    )
```

#### `get_attesting_indices`

```python
def get_attesting_indices(state: BeaconState, attestation: Attestation) -> Set[ValidatorIndex]:
    """
    Return the set of attesting indices corresponding to ``data`` and ``bits``.
    """
    committee = get_beacon_committee(state, attestation.data.slot, attestation.data.index)
    return {index for i, index in enumerate(committee) if attestation.aggregation_bits[i]}
```

### Beacon state mutators

#### `increase_balance`

```python
def increase_balance(state: BeaconState, index: ValidatorIndex, delta: Gwei) -> BeaconState:
    """
    Increase the validator balance at index ``index`` by ``delta``.
    """
    balances = list(state.balances)
    balances[index] = Gwei(balances[index] + delta)
    return replace(state, balances=balances)
```

#### `decrease_balance`

```python
def decrease_balance(state: BeaconState, index: ValidatorIndex, delta: Gwei) -> BeaconState:
    """
    Decrease the validator balance at index ``index`` by ``delta``, with underflow protection.
    """
    balances = list(state.balances)
    balances[index] = Gwei(0) if delta > balances[index] else Gwei(balances[index] - delta)
    return replace(state, balances=balances)
```

#### `initiate_validator_exit`

```python
def initiate_validator_exit(state: BeaconState, index: ValidatorIndex) -> BeaconState:
    """
    Initiate the exit of the validator with index ``index``.
    """
    # Return if validator already initiated exit
    validator = state.validators[index]
    if validator.exit_epoch != FAR_FUTURE_EPOCH:
        return state

    # Compute exit queue epoch
    exit_epochs = [v.exit_epoch for v in state.validators if v.exit_epoch != FAR_FUTURE_EPOCH]
    exit_queue_epoch = max(exit_epochs + [compute_activation_exit_epoch(get_current_epoch(state))])
    exit_queue_churn = len([v for v in state.validators if v.exit_epoch == exit_queue_epoch])
    if Uint64(exit_queue_churn) >= get_validator_churn_limit(state):
        exit_queue_epoch += Epoch(1)

    # Set validator exit epoch and withdrawable epoch
    validators = list(state.validators)
    validators[index] = replace(
        validator,
        exit_epoch=exit_queue_epoch,
        withdrawable_epoch=Epoch(Uint64(exit_queue_epoch) + MIN_VALIDATOR_WITHDRAWABILITY_DELAY),
    )
    return replace(state, validators=validators)
```

#### `slash_validator`

```python
def slash_validator(
    state: BeaconState,
    slashed_index: ValidatorIndex,
    whistleblower_index: Optional[ValidatorIndex] = None,
) -> BeaconState:
    """
    Slash the validator with index ``slashed_index``.
    """
    epoch = get_current_epoch(state)
    state = initiate_validator_exit(state, slashed_index)
    validator = state.validators[slashed_index]
    validators = list(state.validators)
    validators[slashed_index] = replace(
        validator,
        slashed=True,
        withdrawable_epoch=max(
            validator.withdrawable_epoch, epoch + Epoch(EPOCHS_PER_SLASHINGS_VECTOR)
        ),
    )
    slashings = list(state.slashings)
    slashings[Uint64(epoch) % EPOCHS_PER_SLASHINGS_VECTOR] = Gwei(
        slashings[Uint64(epoch) % EPOCHS_PER_SLASHINGS_VECTOR] + validator.effective_balance
    )
    state = replace(state, validators=validators, slashings=slashings)
    state = decrease_balance(
        state,
        slashed_index,
        Gwei(Uint64(validator.effective_balance) // MIN_SLASHING_PENALTY_QUOTIENT),
    )

    # Apply proposer and whistleblower rewards
    proposer_index = get_beacon_proposer_index(state)
    if whistleblower_index is None:
        whistleblower_index = proposer_index
    whistleblower_reward = Gwei(Uint64(validator.effective_balance) // WHISTLEBLOWER_REWARD_QUOTIENT)
    proposer_reward = Gwei(Uint64(whistleblower_reward) // PROPOSER_REWARD_QUOTIENT)
    state = increase_balance(state, proposer_index, proposer_reward)
    state = increase_balance(
        state, whistleblower_index, Gwei(whistleblower_reward - proposer_reward)
    )
    return state
```

## Genesis

Before the Ethereum beacon-chain genesis has been triggered, and for every
Ethereum proof-of-work block, let
`candidate_state = initialize_beacon_state_from_eth1(eth1_block_hash, eth1_timestamp, deposits)`
where:

- `eth1_block_hash` is the hash of the Ethereum proof-of-work block
- `eth1_timestamp` is the Unix timestamp corresponding to `eth1_block_hash`
- `deposits` is the sequence of all deposits, ordered chronologically, up to
  (and including) the block with hash `eth1_block_hash`

Proof-of-work blocks must only be considered once they are at least
`SECONDS_PER_ETH1_BLOCK * ETH1_FOLLOW_DISTANCE` seconds old (i.e.
`eth1_timestamp + SECONDS_PER_ETH1_BLOCK * ETH1_FOLLOW_DISTANCE <= current_unix_time`).
Due to this constraint, if
`GENESIS_DELAY < SECONDS_PER_ETH1_BLOCK * ETH1_FOLLOW_DISTANCE`, then the
`genesis_time` can happen before the time/state is first known. Values should be
configured to avoid this case.

```python
def initialize_beacon_state_from_eth1(
    eth1_block_hash: Hash32, eth1_timestamp: Uint64, deposits: Sequence[Deposit]
) -> BeaconState:
    fork = Fork(
        previous_version=GENESIS_FORK_VERSION,
        current_version=GENESIS_FORK_VERSION,
        epoch=GENESIS_EPOCH,
    )
    state = BeaconState(
        genesis_time=eth1_timestamp + GENESIS_DELAY,
        fork=fork,
        eth1_data=Eth1Data(deposit_count=Uint64(len(deposits)), block_hash=eth1_block_hash),
        latest_block_header=BeaconBlockHeader(body_root=hash_tree_root(BeaconBlockBody())),
        randao_mixes=[eth1_block_hash]
        * int(EPOCHS_PER_HISTORICAL_VECTOR),  # Seed RANDAO with Eth1 entropy
    )

    # Process deposits
    leaves = [deposit.data for deposit in deposits]
    for index, deposit in enumerate(deposits):
        deposit_data_list = List[DepositData, 2 ** int(DEPOSIT_CONTRACT_TREE_DEPTH)](
            *leaves[: index + 1]
        )
        state = replace(
            state,
            eth1_data=replace(state.eth1_data, deposit_root=hash_tree_root(deposit_data_list)),
        )
        state = process_deposit(state, deposit)

    # Process activations
    validators = list(state.validators)
    for index, validator in enumerate(validators):
        balance = state.balances[index]
        effective_balance = min(
            balance - balance % EFFECTIVE_BALANCE_INCREMENT, MAX_EFFECTIVE_BALANCE
        )
        activation_updates = {"effective_balance": effective_balance}
        if effective_balance == MAX_EFFECTIVE_BALANCE:
            activation_updates["activation_eligibility_epoch"] = GENESIS_EPOCH
            activation_updates["activation_epoch"] = GENESIS_EPOCH
        validators[index] = replace(validator, **activation_updates)
    state = replace(state, validators=validators)

    # Set genesis validators root for domain separation and chain versioning
    state = replace(state, genesis_validators_root=hash_tree_root(state.validators))

    return state
```

*Note*: The ETH1 block with `eth1_timestamp` meeting the minimum genesis active
validator count criteria can also occur before `MIN_GENESIS_TIME`.

### Genesis state

Let `genesis_state = candidate_state` whenever
`is_valid_genesis_state(candidate_state) is True` for the first time.

```python
def is_valid_genesis_state(state: BeaconState) -> bool:
    if state.genesis_time < MIN_GENESIS_TIME:
        return False
    if (
        Uint64(len(get_active_validator_indices(state, GENESIS_EPOCH)))
        < MIN_GENESIS_ACTIVE_VALIDATOR_COUNT
    ):
        return False
    return True
```

### Genesis block

Let `genesis_block = BeaconBlock(state_root=hash_tree_root(genesis_state))`.

## Beacon chain state transition function

The post-state corresponding to a pre-state `state` and a signed block
`signed_block` is defined as `state_transition(state, signed_block)`. State
transitions that trigger an unhandled exception (e.g. a failed `assert` or an
out-of-range list access) are considered invalid. State transitions that cause a
`Uint64` overflow or underflow are also considered invalid.

```python
def state_transition(
    state: BeaconState, signed_block: SignedBeaconBlock, validate_result: bool = True
) -> BeaconState:
    block = signed_block.message
    # Process slots (including those with no blocks) since block
    state = process_slots(state, block.slot)
    # Verify signature
    if validate_result:
        assert verify_block_signature(state, signed_block)
    # Process block
    state = process_block(state, block)
    # Verify state root
    if validate_result:
        assert block.state_root == hash_tree_root(state)
    return state
```

```python
def verify_block_signature(state: BeaconState, signed_block: SignedBeaconBlock) -> bool:
    proposer = state.validators[signed_block.message.proposer_index]
    signing_root = compute_signing_root(
        signed_block.message, get_domain(state, DOMAIN_BEACON_PROPOSER)
    )
    return bls.Verify(proposer.pubkey, signing_root, signed_block.signature)
```

```python
def process_slots(state: BeaconState, slot: Slot) -> BeaconState:
    assert state.slot < slot
    while state.slot < slot:
        state = process_slot(state)
        # Process epoch on the start slot of the next epoch
        if (Uint64(state.slot) + Uint64(1)) % SLOTS_PER_EPOCH == Uint64(0):
            state = process_epoch(state)
        state = replace(state, slot=state.slot + Slot(1))
    return state
```

```python
def process_slot(state: BeaconState) -> BeaconState:
    # Cache state root
    previous_state_root = hash_tree_root(state)
    state_roots = list(state.state_roots)
    state_roots[Uint64(state.slot) % SLOTS_PER_HISTORICAL_ROOT] = previous_state_root
    state = replace(state, state_roots=state_roots)
    # Cache latest block header state root
    if state.latest_block_header.state_root == Bytes32():
        state = replace(
            state,
            latest_block_header=replace(
                state.latest_block_header, state_root=previous_state_root
            ),
        )
    # Cache block root
    previous_block_root = hash_tree_root(state.latest_block_header)
    block_roots = list(state.block_roots)
    block_roots[Uint64(state.slot) % SLOTS_PER_HISTORICAL_ROOT] = previous_block_root
    return replace(state, block_roots=block_roots)
```

### Epoch processing

```python
def process_epoch(state: BeaconState) -> BeaconState:
    state = process_justification_and_finalization(state)
    state = process_rewards_and_penalties(state)
    state = process_registry_updates(state)
    state = process_slashings(state)
    state = process_eth1_data_reset(state)
    state = process_effective_balance_updates(state)
    state = process_slashings_reset(state)
    state = process_randao_mixes_reset(state)
    state = process_historical_roots_update(state)
    state = process_participation_record_updates(state)
    return state
```

#### Helpers

```python
def get_matching_source_attestations(
    state: BeaconState, epoch: Epoch
) -> Sequence[PendingAttestation]:
    assert epoch in (get_previous_epoch(state), get_current_epoch(state))
    return (
        state.current_epoch_attestations
        if epoch == get_current_epoch(state)
        else state.previous_epoch_attestations
    )
```

```python
def get_matching_target_attestations(
    state: BeaconState, epoch: Epoch
) -> Sequence[PendingAttestation]:
    return [
        a
        for a in get_matching_source_attestations(state, epoch)
        if a.data.target.root == get_block_root(state, epoch)
    ]
```

```python
def get_matching_head_attestations(
    state: BeaconState, epoch: Epoch
) -> Sequence[PendingAttestation]:
    return [
        a
        for a in get_matching_target_attestations(state, epoch)
        if a.data.beacon_block_root == get_block_root_at_slot(state, a.data.slot)
    ]
```

```python
def get_unslashed_attesting_indices(
    state: BeaconState, attestations: Sequence[PendingAttestation]
) -> Set[ValidatorIndex]:
    output: Set[ValidatorIndex] = set()
    for a in attestations:
        output = output.union(get_attesting_indices(state, a))
    return set(filter(lambda index: not state.validators[index].slashed, output))
```

```python
def get_attesting_balance(state: BeaconState, attestations: Sequence[PendingAttestation]) -> Gwei:
    """
    Return the combined effective balance of the set of unslashed validators participating in ``attestations``.
    Note: ``get_total_balance`` returns ``EFFECTIVE_BALANCE_INCREMENT`` Gwei minimum to avoid divisions by zero.
    """
    return get_total_balance(state, get_unslashed_attesting_indices(state, attestations))
```

#### Justification and finalization

```python
def process_justification_and_finalization(state: BeaconState) -> BeaconState:
    # Initial FFG checkpoint values have a `0x00` stub for `root`.
    # Skip FFG updates in the first two epochs to avoid corner cases that might result in modifying this stub.
    if get_current_epoch(state) <= GENESIS_EPOCH + Epoch(1):
        return state
    previous_attestations = get_matching_target_attestations(state, get_previous_epoch(state))
    current_attestations = get_matching_target_attestations(state, get_current_epoch(state))
    total_active_balance = get_total_active_balance(state)
    previous_target_balance = get_attesting_balance(state, previous_attestations)
    current_target_balance = get_attesting_balance(state, current_attestations)
    return weigh_justification_and_finalization(
        state, total_active_balance, previous_target_balance, current_target_balance
    )
```

```python
def weigh_justification_and_finalization(
    state: BeaconState,
    total_active_balance: Gwei,
    previous_epoch_target_balance: Gwei,
    current_epoch_target_balance: Gwei,
) -> BeaconState:
    previous_epoch = get_previous_epoch(state)
    current_epoch = get_current_epoch(state)
    old_previous_justified_checkpoint = state.previous_justified_checkpoint
    old_current_justified_checkpoint = state.current_justified_checkpoint

    # Process justifications
    previous_justified_checkpoint = state.current_justified_checkpoint
    current_justified_checkpoint = state.current_justified_checkpoint
    bits = list(state.justification_bits)
    bits[1:] = bits[: JUSTIFICATION_BITS_LENGTH - Uint64(1)]
    bits[0] = 0b0
    if Uint64(previous_epoch_target_balance) * Uint64(3) >= Uint64(total_active_balance) * Uint64(2):
        current_justified_checkpoint = Checkpoint(
            epoch=previous_epoch, root=get_block_root(state, previous_epoch)
        )
        bits[1] = 0b1
    if Uint64(current_epoch_target_balance) * Uint64(3) >= Uint64(total_active_balance) * Uint64(2):
        current_justified_checkpoint = Checkpoint(
            epoch=current_epoch, root=get_block_root(state, current_epoch)
        )
        bits[0] = 0b1

    # Process finalizations
    finalized_checkpoint = state.finalized_checkpoint
    # The 2nd/3rd/4th most recent epochs are justified, the 2nd using the 4th as source
    if all(bits[1:4]) and old_previous_justified_checkpoint.epoch + Epoch(3) == current_epoch:
        finalized_checkpoint = old_previous_justified_checkpoint
    # The 2nd/3rd most recent epochs are justified, the 2nd using the 3rd as source
    if all(bits[1:3]) and old_previous_justified_checkpoint.epoch + Epoch(2) == current_epoch:
        finalized_checkpoint = old_previous_justified_checkpoint
    # The 1st/2nd/3rd most recent epochs are justified, the 1st using the 3rd as source
    if all(bits[0:3]) and old_current_justified_checkpoint.epoch + Epoch(2) == current_epoch:
        finalized_checkpoint = old_current_justified_checkpoint
    # The 1st/2nd most recent epochs are justified, the 1st using the 2nd as source
    if all(bits[0:2]) and old_current_justified_checkpoint.epoch + Epoch(1) == current_epoch:
        finalized_checkpoint = old_current_justified_checkpoint

    return replace(
        state,
        previous_justified_checkpoint=previous_justified_checkpoint,
        current_justified_checkpoint=current_justified_checkpoint,
        justification_bits=bits,
        finalized_checkpoint=finalized_checkpoint,
    )
```

#### Rewards and penalties

##### Helpers

```python
def get_base_reward(state: BeaconState, index: ValidatorIndex) -> Gwei:
    total_balance = get_total_active_balance(state)
    effective_balance = state.validators[index].effective_balance
    return Gwei(
        Uint64(effective_balance)
        * BASE_REWARD_FACTOR
        // integer_squareroot(Uint64(total_balance))
        // BASE_REWARDS_PER_EPOCH
    )
```

```python
def get_proposer_reward(state: BeaconState, attesting_index: ValidatorIndex) -> Gwei:
    return Gwei(Uint64(get_base_reward(state, attesting_index)) // PROPOSER_REWARD_QUOTIENT)
```

```python
def get_finality_delay(state: BeaconState) -> Uint64:
    return Uint64(get_previous_epoch(state)) - Uint64(state.finalized_checkpoint.epoch)
```

```python
def is_in_inactivity_leak(state: BeaconState) -> bool:
    return get_finality_delay(state) > MIN_EPOCHS_TO_INACTIVITY_PENALTY
```

```python
def get_eligible_validator_indices(state: BeaconState) -> Sequence[ValidatorIndex]:
    previous_epoch = get_previous_epoch(state)
    return [
        ValidatorIndex(index)
        for index, v in enumerate(state.validators)
        if is_active_validator(v, previous_epoch)
        or (v.slashed and previous_epoch + Epoch(1) < v.withdrawable_epoch)
    ]
```

```python
def get_attestation_component_deltas(
    state: BeaconState, attestations: Sequence[PendingAttestation]
) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Helper with shared logic for use by get source, target, and head deltas functions
    """
    rewards = [Gwei(0)] * len(state.validators)
    penalties = [Gwei(0)] * len(state.validators)
    total_balance = get_total_active_balance(state)
    unslashed_attesting_indices = get_unslashed_attesting_indices(state, attestations)
    attesting_balance = get_total_balance(state, unslashed_attesting_indices)
    for index in get_eligible_validator_indices(state):
        if index in unslashed_attesting_indices:
            increment = Uint64(EFFECTIVE_BALANCE_INCREMENT)  # Factored out from balance totals to avoid Uint64 overflow
            if is_in_inactivity_leak(state):
                # Since full base reward will be canceled out by inactivity penalty deltas,
                # optimal participation receives full base reward compensation here.
                rewards[index] += get_base_reward(state, index)
            else:
                reward_numerator = Uint64(get_base_reward(state, index)) * (
                    Uint64(attesting_balance) // increment
                )
                rewards[index] += Gwei(reward_numerator // (Uint64(total_balance) // increment))
        else:
            penalties[index] += get_base_reward(state, index)
    return rewards, penalties
```

##### Components of attestation deltas

```python
def get_source_deltas(state: BeaconState) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Return attester micro-rewards/penalties for source-vote for each validator.
    """
    matching_source_attestations = get_matching_source_attestations(
        state, get_previous_epoch(state)
    )
    return get_attestation_component_deltas(state, matching_source_attestations)
```

```python
def get_target_deltas(state: BeaconState) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Return attester micro-rewards/penalties for target-vote for each validator.
    """
    matching_target_attestations = get_matching_target_attestations(
        state, get_previous_epoch(state)
    )
    return get_attestation_component_deltas(state, matching_target_attestations)
```

```python
def get_head_deltas(state: BeaconState) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Return attester micro-rewards/penalties for head-vote for each validator.
    """
    matching_head_attestations = get_matching_head_attestations(state, get_previous_epoch(state))
    return get_attestation_component_deltas(state, matching_head_attestations)
```

```python
def get_inclusion_delay_deltas(state: BeaconState) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Return proposer and inclusion delay micro-rewards/penalties for each validator.
    """
    rewards = [Gwei(0) for _ in range(len(state.validators))]
    matching_source_attestations = get_matching_source_attestations(
        state, get_previous_epoch(state)
    )
    for index in get_unslashed_attesting_indices(state, matching_source_attestations):
        attestation = min(
            [a for a in matching_source_attestations if index in get_attesting_indices(state, a)],
            key=lambda a: a.inclusion_delay,
        )
        rewards[attestation.proposer_index] += get_proposer_reward(state, index)
        max_attester_reward = Gwei(
            get_base_reward(state, index) - get_proposer_reward(state, index)
        )
        rewards[index] += Gwei(
            Uint64(max_attester_reward) // Uint64(attestation.inclusion_delay)
        )

    # No penalties associated with inclusion delay
    penalties = [Gwei(0) for _ in range(len(state.validators))]
    return rewards, penalties
```

```python
def get_inactivity_penalty_deltas(state: BeaconState) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Return inactivity reward/penalty deltas for each validator.
    """
    penalties = [Gwei(0) for _ in range(len(state.validators))]
    if is_in_inactivity_leak(state):
        matching_target_attestations = get_matching_target_attestations(
            state, get_previous_epoch(state)
        )
        matching_target_attesting_indices = get_unslashed_attesting_indices(
            state, matching_target_attestations
        )
        for index in get_eligible_validator_indices(state):
            # If validator is performing optimally this cancels all rewards for a neutral balance
            base_reward = get_base_reward(state, index)
            penalties[index] += Gwei(
                BASE_REWARDS_PER_EPOCH * Uint64(base_reward)
                - Uint64(get_proposer_reward(state, index))
            )
            if index not in matching_target_attesting_indices:
                effective_balance = state.validators[index].effective_balance
                penalties[index] += Gwei(
                    Uint64(effective_balance)
                    * get_finality_delay(state)
                    // INACTIVITY_PENALTY_QUOTIENT
                )

    # No rewards associated with inactivity penalties
    rewards = [Gwei(0) for _ in range(len(state.validators))]
    return rewards, penalties
```

##### `get_attestation_deltas`

```python
def get_attestation_deltas(state: BeaconState) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Return attestation reward/penalty deltas for each validator.
    """
    source_rewards, source_penalties = get_source_deltas(state)
    target_rewards, target_penalties = get_target_deltas(state)
    head_rewards, head_penalties = get_head_deltas(state)
    inclusion_delay_rewards, _ = get_inclusion_delay_deltas(state)
    _, inactivity_penalties = get_inactivity_penalty_deltas(state)

    rewards = [
        source_rewards[i] + target_rewards[i] + head_rewards[i] + inclusion_delay_rewards[i]
        for i in range(len(state.validators))
    ]

    penalties = [
        source_penalties[i] + target_penalties[i] + head_penalties[i] + inactivity_penalties[i]
        for i in range(len(state.validators))
    ]

    return rewards, penalties
```

##### `process_rewards_and_penalties`

```python
def process_rewards_and_penalties(state: BeaconState) -> BeaconState:
    # No rewards are applied at the end of `GENESIS_EPOCH` because rewards are for work done in the previous epoch
    if get_current_epoch(state) == GENESIS_EPOCH:
        return state

    rewards, penalties = get_attestation_deltas(state)
    for index in range(len(state.validators)):
        state = increase_balance(state, ValidatorIndex(index), rewards[index])
        state = decrease_balance(state, ValidatorIndex(index), penalties[index])
    return state
```

#### Registry updates

```python
def process_registry_updates(state: BeaconState) -> BeaconState:
    # Process activation eligibility and ejections
    for index, validator in enumerate(state.validators):
        if is_eligible_for_activation_queue(validator):
            validators = list(state.validators)
            validators[index] = replace(
                validator, activation_eligibility_epoch=get_current_epoch(state) + Epoch(1)
            )
            state = replace(state, validators=validators)

        if (
            is_active_validator(state.validators[index], get_current_epoch(state))
            and state.validators[index].effective_balance <= EJECTION_BALANCE
        ):
            state = initiate_validator_exit(state, ValidatorIndex(index))

    # Queue validators eligible for activation and not yet dequeued for activation
    activation_queue = sorted(
        [
            index
            for index, validator in enumerate(state.validators)
            if is_eligible_for_activation(state, validator)
        ],
        # Order by the sequence of activation_eligibility_epoch setting and then index
        key=lambda index: (state.validators[index].activation_eligibility_epoch, index),
    )
    # Dequeued validators for activation up to churn limit
    for index in activation_queue[: get_validator_churn_limit(state)]:
        validators = list(state.validators)
        validators[index] = replace(
            validators[index],
            activation_epoch=compute_activation_exit_epoch(get_current_epoch(state)),
        )
        state = replace(state, validators=validators)
    return state
```

#### Slashings

```python
def process_slashings(state: BeaconState) -> BeaconState:
    epoch = get_current_epoch(state)
    total_balance = get_total_active_balance(state)
    adjusted_total_slashing_balance = min(
        Uint64(sum(state.slashings, Gwei(0))) * PROPORTIONAL_SLASHING_MULTIPLIER,
        Uint64(total_balance),
    )
    for index, validator in enumerate(state.validators):
        if (
            validator.slashed
            and Uint64(epoch) + EPOCHS_PER_SLASHINGS_VECTOR // Uint64(2)
            == Uint64(validator.withdrawable_epoch)
        ):
            increment = Uint64(EFFECTIVE_BALANCE_INCREMENT)  # Factored out from penalty numerator to avoid Uint64 overflow
            penalty_numerator = (
                Uint64(validator.effective_balance) // increment * adjusted_total_slashing_balance
            )
            penalty = Gwei(penalty_numerator // Uint64(total_balance) * increment)
            state = decrease_balance(state, ValidatorIndex(index), penalty)
    return state
```

#### Eth1 data votes updates

```python
def process_eth1_data_reset(state: BeaconState) -> BeaconState:
    next_epoch = get_current_epoch(state) + Epoch(1)
    # Reset eth1 data votes
    if Uint64(next_epoch) % EPOCHS_PER_ETH1_VOTING_PERIOD == Uint64(0):
        state = replace(state, eth1_data_votes=[])
    return state
```

#### Effective balances updates

```python
def process_effective_balance_updates(state: BeaconState) -> BeaconState:
    # Update effective balances with hysteresis
    validators = list(state.validators)
    for index, validator in enumerate(validators):
        balance = state.balances[index]
        HYSTERESIS_INCREMENT = Uint64(EFFECTIVE_BALANCE_INCREMENT) // HYSTERESIS_QUOTIENT
        DOWNWARD_THRESHOLD = Gwei(HYSTERESIS_INCREMENT * HYSTERESIS_DOWNWARD_MULTIPLIER)
        UPWARD_THRESHOLD = Gwei(HYSTERESIS_INCREMENT * HYSTERESIS_UPWARD_MULTIPLIER)
        if (
            balance + DOWNWARD_THRESHOLD < validator.effective_balance
            or validator.effective_balance + UPWARD_THRESHOLD < balance
        ):
            validators[index] = replace(
                validator,
                effective_balance=min(
                    balance - Gwei(Uint64(balance) % EFFECTIVE_BALANCE_INCREMENT),
                    MAX_EFFECTIVE_BALANCE,
                ),
            )
    return replace(state, validators=validators)
```

#### Slashings balances updates

```python
def process_slashings_reset(state: BeaconState) -> BeaconState:
    next_epoch = get_current_epoch(state) + Epoch(1)
    # Reset slashings
    slashings = list(state.slashings)
    slashings[Uint64(next_epoch) % EPOCHS_PER_SLASHINGS_VECTOR] = Gwei(0)
    return replace(state, slashings=slashings)
```

#### Randao mixes updates

```python
def process_randao_mixes_reset(state: BeaconState) -> BeaconState:
    current_epoch = get_current_epoch(state)
    next_epoch = current_epoch + Epoch(1)
    # Set randao mix
    randao_mixes = list(state.randao_mixes)
    randao_mixes[Uint64(next_epoch) % EPOCHS_PER_HISTORICAL_VECTOR] = get_randao_mix(
        state, current_epoch
    )
    return replace(state, randao_mixes=randao_mixes)
```

#### Historical roots updates

```python
def process_historical_roots_update(state: BeaconState) -> BeaconState:
    # Set historical root accumulator
    next_epoch = get_current_epoch(state) + Epoch(1)
    if Uint64(next_epoch) % (SLOTS_PER_HISTORICAL_ROOT // SLOTS_PER_EPOCH) == Uint64(0):
        historical_batch = HistoricalBatch(
            block_roots=state.block_roots, state_roots=state.state_roots
        )
        state = replace(
            state,
            historical_roots=list(state.historical_roots) + [hash_tree_root(historical_batch)],
        )
    return state
```

#### Participation records rotation

```python
def process_participation_record_updates(state: BeaconState) -> BeaconState:
    # Rotate current/previous epoch attestations
    return replace(
        state,
        previous_epoch_attestations=state.current_epoch_attestations,
        current_epoch_attestations=[],
    )
```

### Block processing

```python
def process_block(state: BeaconState, block: BeaconBlock) -> BeaconState:
    state = process_block_header(state, block)
    state = process_randao(state, block.body)
    state = process_eth1_data(state, block.body)
    state = process_operations(state, block.body)
    return state
```

#### Block header

```python
def process_block_header(state: BeaconState, block: BeaconBlock) -> BeaconState:
    # Verify that the slots match
    assert block.slot == state.slot
    # Verify that the block is newer than latest block header
    assert block.slot > state.latest_block_header.slot
    # Verify that proposer index is the correct index
    assert block.proposer_index == get_beacon_proposer_index(state)
    # Verify that the parent matches
    assert block.parent_root == hash_tree_root(state.latest_block_header)
    # Cache current block as the new latest block
    state = replace(
        state,
        latest_block_header=BeaconBlockHeader(
            slot=block.slot,
            proposer_index=block.proposer_index,
            parent_root=block.parent_root,
            state_root=Bytes32(),  # Overwritten in the next process_slot call
            body_root=hash_tree_root(block.body),
        ),
    )

    # Verify proposer is not slashed
    proposer = state.validators[block.proposer_index]
    assert not proposer.slashed
    return state
```

#### RANDAO

```python
def process_randao(state: BeaconState, body: BeaconBlockBody) -> BeaconState:
    epoch = get_current_epoch(state)
    # Verify RANDAO reveal
    proposer = state.validators[get_beacon_proposer_index(state)]
    signing_root = compute_signing_root(epoch, get_domain(state, DOMAIN_RANDAO))
    assert bls.Verify(proposer.pubkey, signing_root, body.randao_reveal)
    # Mix in RANDAO reveal
    mix = xor(get_randao_mix(state, epoch), hash(body.randao_reveal))
    randao_mixes = list(state.randao_mixes)
    randao_mixes[Uint64(epoch) % EPOCHS_PER_HISTORICAL_VECTOR] = mix
    return replace(state, randao_mixes=randao_mixes)
```

#### Eth1 data

```python
def process_eth1_data(state: BeaconState, body: BeaconBlockBody) -> BeaconState:
    eth1_data_votes = list(state.eth1_data_votes) + [body.eth1_data]
    state = replace(state, eth1_data_votes=eth1_data_votes)
    if (
        Uint64(eth1_data_votes.count(body.eth1_data)) * Uint64(2)
        > EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH
    ):
        state = replace(state, eth1_data=body.eth1_data)
    return state
```

#### Operations

```python
def process_operations(state: BeaconState, body: BeaconBlockBody) -> BeaconState:
    # Verify that outstanding deposits are processed up to the maximum number of deposits
    assert Uint64(len(body.deposits)) == min(
        MAX_DEPOSITS, state.eth1_data.deposit_count - state.eth1_deposit_index
    )

    def for_ops(
        state: BeaconState,
        operations: Sequence[Any],
        fn: Callable[[BeaconState, Any], BeaconState],
    ) -> BeaconState:
        for operation in operations:
            state = fn(state, operation)
        return state

    state = for_ops(state, body.proposer_slashings, process_proposer_slashing)
    state = for_ops(state, body.attester_slashings, process_attester_slashing)
    state = for_ops(state, body.attestations, process_attestation)
    state = for_ops(state, body.deposits, process_deposit)
    state = for_ops(state, body.voluntary_exits, process_voluntary_exit)
    return state
```

##### Proposer slashings

```python
def process_proposer_slashing(
    state: BeaconState, proposer_slashing: ProposerSlashing
) -> BeaconState:
    header_1 = proposer_slashing.signed_header_1.message
    header_2 = proposer_slashing.signed_header_2.message

    # Verify header slots match
    assert header_1.slot == header_2.slot
    # Verify header proposer indices match
    assert header_1.proposer_index == header_2.proposer_index
    # Verify the headers are different
    assert header_1 != header_2
    # Verify the proposer is slashable
    proposer = state.validators[header_1.proposer_index]
    assert is_slashable_validator(proposer, get_current_epoch(state))
    # Verify signatures
    for signed_header in (proposer_slashing.signed_header_1, proposer_slashing.signed_header_2):
        domain = get_domain(
            state, DOMAIN_BEACON_PROPOSER, compute_epoch_at_slot(signed_header.message.slot)
        )
        signing_root = compute_signing_root(signed_header.message, domain)
        assert bls.Verify(proposer.pubkey, signing_root, signed_header.signature)

    return slash_validator(state, header_1.proposer_index)
```

##### Attester slashings

```python
def process_attester_slashing(
    state: BeaconState, attester_slashing: AttesterSlashing
) -> BeaconState:
    attestation_1 = attester_slashing.attestation_1
    attestation_2 = attester_slashing.attestation_2
    assert is_slashable_attestation_data(attestation_1.data, attestation_2.data)
    assert is_valid_indexed_attestation(state, attestation_1)
    assert is_valid_indexed_attestation(state, attestation_2)

    slashed_any = False
    indices = set(attestation_1.attesting_indices).intersection(attestation_2.attesting_indices)
    for index in sorted(indices):
        if is_slashable_validator(state.validators[index], get_current_epoch(state)):
            state = slash_validator(state, index)
            slashed_any = True
    assert slashed_any
    return state
```

##### Attestations

```python
def process_attestation(state: BeaconState, attestation: Attestation) -> BeaconState:
    data = attestation.data
    assert data.target.epoch in (get_previous_epoch(state), get_current_epoch(state))
    assert data.target.epoch == compute_epoch_at_slot(data.slot)
    assert (
        data.slot + Slot(MIN_ATTESTATION_INCLUSION_DELAY)
        <= state.slot
        <= data.slot + Slot(SLOTS_PER_EPOCH)
    )
    assert Uint64(data.index) < get_committee_count_per_slot(state, data.target.epoch)

    committee = get_beacon_committee(state, data.slot, data.index)
    assert len(attestation.aggregation_bits) == len(committee)

    pending_attestation = PendingAttestation(
        aggregation_bits=attestation.aggregation_bits,
        data=data,
        inclusion_delay=state.slot - data.slot,
        proposer_index=get_beacon_proposer_index(state),
    )

    if data.target.epoch == get_current_epoch(state):
        assert data.source == state.current_justified_checkpoint
        state = replace(
            state,
            current_epoch_attestations=list(state.current_epoch_attestations)
            + [pending_attestation],
        )
    else:
        assert data.source == state.previous_justified_checkpoint
        state = replace(
            state,
            previous_epoch_attestations=list(state.previous_epoch_attestations)
            + [pending_attestation],
        )

    # Verify signature
    assert is_valid_indexed_attestation(state, get_indexed_attestation(state, attestation))
    return state
```

##### Deposits

```python
def get_validator_from_deposit(
    pubkey: BLSPubkey, withdrawal_credentials: Bytes32, amount: Uint64
) -> Validator:
    effective_balance = min(amount - amount % EFFECTIVE_BALANCE_INCREMENT, MAX_EFFECTIVE_BALANCE)

    return Validator(
        pubkey=pubkey,
        withdrawal_credentials=withdrawal_credentials,
        effective_balance=effective_balance,
        slashed=False,
        activation_eligibility_epoch=FAR_FUTURE_EPOCH,
        activation_epoch=FAR_FUTURE_EPOCH,
        exit_epoch=FAR_FUTURE_EPOCH,
        withdrawable_epoch=FAR_FUTURE_EPOCH,
    )
```

```python
def add_validator_to_registry(
    state: BeaconState, pubkey: BLSPubkey, withdrawal_credentials: Bytes32, amount: Uint64
) -> BeaconState:
    validators = list(state.validators) + [
        get_validator_from_deposit(pubkey, withdrawal_credentials, amount)
    ]
    balances = list(state.balances) + [amount]
    return replace(state, validators=validators, balances=balances)
```

```python
def apply_deposit(
    state: BeaconState,
    pubkey: BLSPubkey,
    withdrawal_credentials: Bytes32,
    amount: Uint64,
    signature: BLSSignature,
) -> BeaconState:
    validator_pubkeys = [v.pubkey for v in state.validators]
    if pubkey not in validator_pubkeys:
        # Verify the deposit signature (proof of possession) which is not checked by the deposit contract
        deposit_message = DepositMessage(
            pubkey=pubkey,
            withdrawal_credentials=withdrawal_credentials,
            amount=amount,
        )
        # Fork-agnostic domain since deposits are valid across forks
        domain = compute_domain(DOMAIN_DEPOSIT)
        signing_root = compute_signing_root(deposit_message, domain)
        if bls.Verify(pubkey, signing_root, signature):
            state = add_validator_to_registry(state, pubkey, withdrawal_credentials, amount)
    else:
        # Increase balance by deposit amount
        index = ValidatorIndex(validator_pubkeys.index(pubkey))
        state = increase_balance(state, index, amount)
    return state
```

```python
def process_deposit(state: BeaconState, deposit: Deposit) -> BeaconState:
    # Verify the Merkle branch
    assert is_valid_merkle_branch(
        leaf=hash_tree_root(deposit.data),
        branch=deposit.proof,
        # Add 1 for the List length mix-in
        depth=DEPOSIT_CONTRACT_TREE_DEPTH + 1,
        index=state.eth1_deposit_index,
        root=state.eth1_data.deposit_root,
    )

    # Deposits must be processed in order
    state = replace(state, eth1_deposit_index=state.eth1_deposit_index + Uint64(1))

    return apply_deposit(
        state=state,
        pubkey=deposit.data.pubkey,
        withdrawal_credentials=deposit.data.withdrawal_credentials,
        amount=deposit.data.amount,
        signature=deposit.data.signature,
    )
```

##### Voluntary exits

```python
def process_voluntary_exit(
    state: BeaconState, signed_voluntary_exit: SignedVoluntaryExit
) -> BeaconState:
    voluntary_exit = signed_voluntary_exit.message
    validator = state.validators[voluntary_exit.validator_index]
    # Verify the validator is active
    assert is_active_validator(validator, get_current_epoch(state))
    # Verify exit has not been initiated
    assert validator.exit_epoch == FAR_FUTURE_EPOCH
    # Exits must specify an epoch when they become valid; they are not valid before then
    assert get_current_epoch(state) >= voluntary_exit.epoch
    # Verify the validator has been active long enough
    assert get_current_epoch(state) >= validator.activation_epoch + SHARD_COMMITTEE_PERIOD
    # Verify signature
    domain = get_domain(state, DOMAIN_VOLUNTARY_EXIT, voluntary_exit.epoch)
    signing_root = compute_signing_root(voluntary_exit, domain)
    assert bls.Verify(validator.pubkey, signing_root, signed_voluntary_exit.signature)
    # Initiate exit
    return initiate_validator_exit(state, voluntary_exit.validator_index)
```

<!-- eth_consensus_specs: parent=none -->

# Phase 0 -- The Beacon Chain

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Introduction](#introduction)
- [Notation](#notation)
- [Types](#types)
  - [`AggregationBits`](#aggregationbits)
  - [`Attestations`](#attestations)
  - [`AttesterSlashings`](#attesterslashings)
  - [`AttestingIndices`](#attestingindices)
  - [`Balances`](#balances)
  - [`BlockRoots`](#blockroots)
  - [`BLSPubkey`](#blspubkey)
  - [`BLSSignature`](#blssignature)
  - [`CommitteeIndex`](#committeeindex)
  - [`DepositDataList`](#depositdatalist)
  - [`DepositProof`](#depositproof)
  - [`Deposits`](#deposits)
  - [`Domain`](#domain)
  - [`DomainType`](#domaintype)
  - [`Epoch`](#epoch)
  - [`Eth1DataVotes`](#eth1datavotes)
  - [`ForkDigest`](#forkdigest)
  - [`Gwei`](#gwei)
  - [`Hash32`](#hash32)
  - [`HistoricalRoots`](#historicalroots)
  - [`JustificationBits`](#justificationbits)
  - [`PendingAttestations`](#pendingattestations)
  - [`ProposerSlashings`](#proposerslashings)
  - [`RandaoMixes`](#randaomixes)
  - [`Root`](#root)
  - [`Slashings`](#slashings)
  - [`Slot`](#slot)
  - [`StateRoots`](#stateroots)
  - [`ValidatorIndex`](#validatorindex)
  - [`Validators`](#validators)
  - [`Version`](#version)
  - [`VoluntaryExits`](#voluntaryexits)
- [Constants](#constants)
  - [Misc](#misc)
  - [Withdrawal prefixes](#withdrawal-prefixes)
  - [Domains](#domains)
- [Presets](#presets)
  - [Misc](#misc-1)
  - [Gwei values](#gwei-values)
  - [Time parameters](#time-parameters)
  - [State list lengths](#state-list-lengths)
  - [Rewards and penalties](#rewards-and-penalties)
  - [Max operations per block](#max-operations-per-block)
- [Configs](#configs)
  - [Network](#network)
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
    - [`IndexedAttestation`](#indexedattestation)
    - [`PendingAttestation`](#pendingattestation)
    - [`Eth1Data`](#eth1data)
    - [`HistoricalBatch`](#historicalbatch)
    - [`DepositMessage`](#depositmessage)
    - [`DepositData`](#depositdata)
    - [`BeaconBlockHeader`](#beaconblockheader)
    - [`SigningData`](#signingdata)
  - [Beacon operations](#beacon-operations)
    - [`ProposerSlashing`](#proposerslashing)
    - [`AttesterSlashing`](#attesterslashing)
    - [`Attestation`](#attestation)
    - [`Deposit`](#deposit)
    - [`VoluntaryExit`](#voluntaryexit)
  - [Beacon blocks](#beacon-blocks)
    - [`BeaconBlockBody`](#beaconblockbody)
    - [`BeaconBlock`](#beaconblock)
  - [Beacon state](#beacon-state)
    - [`BeaconState`](#beaconstate)
  - [Signed envelopes](#signed-envelopes)
    - [`SignedVoluntaryExit`](#signedvoluntaryexit)
    - [`SignedBeaconBlock`](#signedbeaconblock)
    - [`SignedBeaconBlockHeader`](#signedbeaconblockheader)
- [Helpers](#helpers)
  - [Math](#math)
    - [`get_set_bit_count`](#get_set_bit_count)
    - [`integer_squareroot`](#integer_squareroot)
    - [`xor`](#xor)
    - [`uint_to_bytes`](#uint_to_bytes)
    - [`bytes_to_uint64`](#bytes_to_uint64)
    - [`saturating_sub`](#saturating_sub)
  - [Crypto](#crypto)
    - [`sha256`](#sha256)
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
    - [`compute_slot_at_time`](#compute_slot_at_time)
    - [`compute_time_at_slot_ms`](#compute_time_at_slot_ms)
    - [`compute_slot_at_time_ms`](#compute_slot_at_time_ms)
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
    - [`get_pending_attesting_indices`](#get_pending_attesting_indices)
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

<!-- eth_consensus_specs: build
```python
from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256 as sha256_hash
from typing import Final, NamedTuple

from ssz.bitfields import BitList, BitVector
from ssz.boolean import Boolean
from ssz.collections import List, Vector
from ssz.container import Container
from ssz.ssz_base import SSZType
from ssz.uint import BaseUint as Uint, Byte, Uint8, Uint32, Uint64, Uint256

from eth_consensus_specs.utils import bls
from eth_consensus_specs.utils.ssz.bytes import Bytes1, Bytes4, Bytes20, Bytes32, Bytes48, Bytes96
from eth_consensus_specs.utils.ssz.ssz_impl import ssz_serialize
```
-->

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

### `AggregationBits`

```python
class AggregationBits(BitList):
    """
    The participation bits of a single committee, one bit per member in
    committee order.
    """

    LIMIT = MAX_VALIDATORS_PER_COMMITTEE
```

### `Attestations`

```python
class Attestations(List[Attestation]):
    """
    The attestations included in a beacon block.
    """

    LIMIT = MAX_ATTESTATIONS
```

### `AttesterSlashings`

```python
class AttesterSlashings(List[AttesterSlashing]):
    """
    The attester slashings included in a beacon block.
    """

    LIMIT = MAX_ATTESTER_SLASHINGS
```

### `AttestingIndices`

```python
class AttestingIndices(List[ValidatorIndex]):
    """
    The indices of the validators participating in an attestation.
    """

    LIMIT = MAX_VALIDATORS_PER_COMMITTEE
```

### `Balances`

```python
class Balances(List[Gwei]):
    """
    The balances of all validators.
    """

    LIMIT = VALIDATOR_REGISTRY_LIMIT
```

### `BlockRoots`

```python
class BlockRoots(Vector[Root]):
    """
    A rolling window of recent block roots, indexed by slot modulo
    ``SLOTS_PER_HISTORICAL_ROOT``.
    """

    LENGTH = SLOTS_PER_HISTORICAL_ROOT
```

### `BLSPubkey`

```python
class BLSPubkey(Bytes48):
    """
    A BLS12-381 public key, a compressed point in the ``G1`` group.
    """
```

### `BLSSignature`

```python
class BLSSignature(Bytes96):
    """
    A BLS12-381 signature, a compressed point in the ``G2`` group.
    """
```

### `CommitteeIndex`

```python
class CommitteeIndex(Uint64):
    """
    The index of a committee within a slot.
    """
```

### `DepositDataList`

```python
class DepositDataList(List[DepositData]):
    """
    The ``DepositData`` of deposits made to the deposit contract.
    """

    LIMIT = 2**DEPOSIT_CONTRACT_TREE_DEPTH
```

### `DepositProof`

```python
class DepositProof(Vector[Bytes32]):
    """
    A Merkle proof of a deposit in the deposit contract's tree. The node
    beyond the tree depth accounts for the deposit count mix-in.
    """

    LENGTH = DEPOSIT_CONTRACT_TREE_DEPTH + 1
```

### `Deposits`

```python
class Deposits(List[Deposit]):
    """
    The deposits included in a beacon block.
    """

    LIMIT = MAX_DEPOSITS
```

### `Domain`

```python
class Domain(Bytes32):
    """
    A signature domain.
    """
```

### `DomainType`

```python
class DomainType(Bytes4):
    """
    A signature domain type, identifying the kind of message being signed.
    """
```

### `Epoch`

```python
class Epoch(Uint64):
    """
    An epoch number. An epoch is a span of ``SLOTS_PER_EPOCH`` slots.
    """
```

### `Eth1DataVotes`

```python
class Eth1DataVotes(List[Eth1Data]):
    """
    The ``Eth1Data`` votes of the current voting period.
    """

    LIMIT = Uint64(EPOCHS_PER_ETH1_VOTING_PERIOD) * Uint64(SLOTS_PER_EPOCH)
```

### `ForkDigest`

```python
class ForkDigest(Bytes4):
    """
    A short digest of the current fork data.
    """
```

### `Gwei`

```python
class Gwei(Uint64):
    """
    An amount in Gwei, the smallest unit of Ether on the beacon chain. One
    Ether is equal to ``10**9`` Gwei, and one Gwei is equal to ``10**9`` Wei.
    """
```

### `Hash32`

```python
class Hash32(Bytes32):
    """
    A 256-bit hash that is not a Merkle root, like the hash of an
    execution-layer block.
    """
```

### `HistoricalRoots`

```python
class HistoricalRoots(List[Root]):
    """
    The roots of ``HistoricalBatch`` objects.
    """

    LIMIT = HISTORICAL_ROOTS_LIMIT
```

### `JustificationBits`

```python
class JustificationBits(BitVector):
    """
    The justification status of the last ``JUSTIFICATION_BITS_LENGTH`` epochs.
    """

    LENGTH = JUSTIFICATION_BITS_LENGTH
```

### `PendingAttestations`

```python
class PendingAttestations(List[PendingAttestation]):
    """
    The attestations included in blocks during an epoch.
    """

    LIMIT = MAX_ATTESTATIONS * SLOTS_PER_EPOCH
```

### `ProposerSlashings`

```python
class ProposerSlashings(List[ProposerSlashing]):
    """
    The proposer slashings included in a beacon block.
    """

    LIMIT = MAX_PROPOSER_SLASHINGS
```

### `RandaoMixes`

```python
class RandaoMixes(Vector[Bytes32]):
    """
    A rolling window of accumulated RANDAO mixes, indexed by epoch modulo
    ``EPOCHS_PER_HISTORICAL_VECTOR``.
    """

    LENGTH = EPOCHS_PER_HISTORICAL_VECTOR
```

### `Root`

```python
class Root(Bytes32):
    """
    A Merkle root, usually the hash tree root of an SSZ object.
    """
```

### `Slashings`

```python
class Slashings(Vector[Gwei]):
    """
    Per-epoch sums of slashed effective balances, indexed by epoch modulo
    ``EPOCHS_PER_SLASHINGS_VECTOR``.
    """

    LENGTH = EPOCHS_PER_SLASHINGS_VECTOR
```

### `Slot`

```python
class Slot(Uint64):
    """
    A slot number. Time is divided into fixed-length slots.
    """
```

### `StateRoots`

```python
class StateRoots(Vector[Root]):
    """
    A rolling window of recent state roots, indexed by slot modulo
    ``SLOTS_PER_HISTORICAL_ROOT``.
    """

    LENGTH = SLOTS_PER_HISTORICAL_ROOT
```

### `ValidatorIndex`

```python
class ValidatorIndex(Uint64):
    """
    The index of a validator in the validator registry.
    """
```

### `Validators`

```python
class Validators(List[Validator]):
    """
    The validator registry.
    """

    LIMIT = VALIDATOR_REGISTRY_LIMIT
```

### `Version`

```python
class Version(Bytes4):
    """
    A fork version number.
    """
```

### `VoluntaryExits`

```python
class VoluntaryExits(List[SignedVoluntaryExit]):
    """
    The signed voluntary exits included in a beacon block.
    """

    LIMIT = MAX_VOLUNTARY_EXITS
```

## Constants

The following values are (non-configurable) constants used throughout the
specification.

### Misc

| Name                        | Value                |
| --------------------------- | -------------------- |
| `UINT64_MAX`                | `Uint64(2**64 - 1)`  |
| `UINT64_MAX_SQRT`           | `Uint64(4294967295)` |
| `GENESIS_SLOT`              | `Slot(0)`            |
| `GENESIS_EPOCH`             | `Epoch(0)`           |
| `FAR_FUTURE_EPOCH`          | `Epoch(2**64 - 1)`   |
| `BASE_REWARDS_PER_EPOCH`    | `Uint64(4)`          |
| `JUSTIFICATION_BITS_LENGTH` | `Uint64(4)`          |
| `ENDIANNESS`                | `"little"`           |

### Withdrawal prefixes

| Name                             | Value            |
| -------------------------------- | ---------------- |
| `BLS_WITHDRAWAL_PREFIX`          | `Bytes1("0x00")` |
| `ETH1_ADDRESS_WITHDRAWAL_PREFIX` | `Bytes1("0x01")` |

### Domains

| Name                         | Value                      |
| ---------------------------- | -------------------------- |
| `DOMAIN_BEACON_PROPOSER`     | `DomainType("0x00000000")` |
| `DOMAIN_BEACON_ATTESTER`     | `DomainType("0x01000000")` |
| `DOMAIN_RANDAO`              | `DomainType("0x02000000")` |
| `DOMAIN_DEPOSIT`             | `DomainType("0x03000000")` |
| `DOMAIN_VOLUNTARY_EXIT`      | `DomainType("0x04000000")` |
| `DOMAIN_SELECTION_PROOF`     | `DomainType("0x05000000")` |
| `DOMAIN_AGGREGATE_AND_PROOF` | `DomainType("0x06000000")` |
| `DOMAIN_APPLICATION_MASK`    | `DomainType("0x00000001")` |

*Note*: `DOMAIN_APPLICATION_MASK` reserves the rest of the bitspace in
`DomainType` for application usage. This means for some `DomainType`
`DOMAIN_SOME_APPLICATION`, `DOMAIN_SOME_APPLICATION & DOMAIN_APPLICATION_MASK`
**MUST** be non-zero. This expression for any other `DomainType` in the
consensus-layer specifications **MUST** be zero.

## Presets

*Note*: The below configuration is bundled as a preset: a bundle of
configuration variables which are expected to differ between different modes of
operation, e.g. testing, but not generally between different networks.

### Misc

| Name                             | Mainnet                   | Minimal              |
| -------------------------------- | ------------------------- | -------------------- |
| `MAX_COMMITTEES_PER_SLOT`        | `Uint64(2**6)` (= 64)     | `Uint64(2**2)` (= 4) |
| `TARGET_COMMITTEE_SIZE`          | `Uint64(2**7)` (= 128)    | `Uint64(2**2)` (= 4) |
| `MAX_VALIDATORS_PER_COMMITTEE`   | `Uint64(2**11)` (= 2,048) | *same*               |
| `SHUFFLE_ROUND_COUNT`            | `Uint64(90)`              | `Uint64(10)`         |
| `HYSTERESIS_QUOTIENT`            | `Uint64(4)`               | *same*               |
| `HYSTERESIS_DOWNWARD_MULTIPLIER` | `Uint64(1)`               | *same*               |
| `HYSTERESIS_UPWARD_MULTIPLIER`   | `Uint64(5)`               | *same*               |

- For the safety of committees, `TARGET_COMMITTEE_SIZE` exceeds
  [the recommended minimum committee size of 111](http://web.archive.org/web/20190504131341/https://vitalik.ca/files/Ithaca201807_Sharding.pdf);
  with sufficient active validators (at least
  `SLOTS_PER_EPOCH * TARGET_COMMITTEE_SIZE`), the shuffling algorithm ensures
  committee sizes of at least `TARGET_COMMITTEE_SIZE`. (Unbiasable randomness
  with a Verifiable Delay Function (VDF) will improve committee robustness and
  lower the safe minimum committee size.)

### Gwei values

| Name                          | Mainnet                                 | Minimal |
| ----------------------------- | --------------------------------------- | ------- |
| `MIN_DEPOSIT_AMOUNT`          | `Gwei(2**0 * 10**9)` (= 1,000,000,000)  | *same*  |
| `MAX_EFFECTIVE_BALANCE`       | `Gwei(2**5 * 10**9)` (= 32,000,000,000) | *same*  |
| `EFFECTIVE_BALANCE_INCREMENT` | `Gwei(2**0 * 10**9)` (= 1,000,000,000)  | *same*  |

### Time parameters

| Name                               | Mainnet                 | Minimal             |
| ---------------------------------- | ----------------------- | ------------------- |
| `MIN_ATTESTATION_INCLUSION_DELAY`  | `Slot(2**0)` (= 1)      | *same*              |
| `SLOTS_PER_EPOCH`                  | `Slot(2**5)` (= 32)     | `Slot(2**3)` (= 8)  |
| `MIN_SEED_LOOKAHEAD`               | `Epoch(2**0)` (= 1)     | *same*              |
| `MAX_SEED_LOOKAHEAD`               | `Epoch(2**2)` (= 4)     | *same*              |
| `MIN_EPOCHS_TO_INACTIVITY_PENALTY` | `Epoch(2**2)` (= 4)     | *same*              |
| `EPOCHS_PER_ETH1_VOTING_PERIOD`    | `Epoch(2**6)` (= 64)    | `Epoch(2**2)` (= 4) |
| `SLOTS_PER_HISTORICAL_ROOT`        | `Slot(2**13)` (= 8,192) | `Slot(2**6)` (= 64) |

### State list lengths

| Name                           | Mainnet                               | Minimal              |
| ------------------------------ | ------------------------------------- | -------------------- |
| `EPOCHS_PER_HISTORICAL_VECTOR` | `Epoch(2**16)` (= 65,536)             | `Epoch(2**6)` (= 64) |
| `EPOCHS_PER_SLASHINGS_VECTOR`  | `Epoch(2**13)` (= 8,192)              | `Epoch(2**6)` (= 64) |
| `HISTORICAL_ROOTS_LIMIT`       | `Uint64(2**24)` (= 16,777,216)        | *same*               |
| `VALIDATOR_REGISTRY_LIMIT`     | `Uint64(2**40)` (= 1,099,511,627,776) | *same*               |

### Rewards and penalties

| Name                               | Mainnet                        | Minimal                        |
| ---------------------------------- | ------------------------------ | ------------------------------ |
| `BASE_REWARD_FACTOR`               | `Uint64(2**6)` (= 64)          | *same*                         |
| `WHISTLEBLOWER_REWARD_QUOTIENT`    | `Uint64(2**9)` (= 512)         | *same*                         |
| `PROPOSER_REWARD_QUOTIENT`         | `Uint64(2**3)` (= 8)           | *same*                         |
| `INACTIVITY_PENALTY_QUOTIENT`      | `Uint64(2**26)` (= 67,108,864) | `Uint64(2**25)` (= 33,554,432) |
| `MIN_SLASHING_PENALTY_QUOTIENT`    | `Uint64(2**7)` (= 128)         | `Uint64(2**6)` (= 64)          |
| `PROPORTIONAL_SLASHING_MULTIPLIER` | `Uint64(1)`                    | `Uint64(2)`                    |

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

| Name                     | Mainnet                | Minimal |
| ------------------------ | ---------------------- | ------- |
| `MAX_PROPOSER_SLASHINGS` | `Uint64(2**4)` (= 16)  | *same*  |
| `MAX_ATTESTER_SLASHINGS` | `Uint64(2**1)` (= 2)   | *same*  |
| `MAX_ATTESTATIONS`       | `Uint64(2**7)` (= 128) | *same*  |
| `MAX_DEPOSITS`           | `Uint64(2**4)` (= 16)  | *same*  |
| `MAX_VOLUNTARY_EXITS`    | `Uint64(2**4)` (= 16)  | *same*  |

## Configs

*Note*: The default mainnet configuration values are included here for
illustrative purposes. Defaults for this more dynamic type of configuration are
available with presets. Testnets and other types of chain instances may use a
different configuration.

### Network

| Name          | Mainnet     | Minimal     | Description                                             |
| ------------- | ----------- | ----------- | ------------------------------------------------------- |
| `PRESET_BASE` | `"mainnet"` | `"minimal"` | The preset that this configuration extends              |
| `CONFIG_NAME` | `"mainnet"` | `"minimal"` | The short name of the network this configuration is for |

### Genesis settings

| Name                                 | Mainnet                                      | Minimal                 |
| ------------------------------------ | -------------------------------------------- | ----------------------- |
| `MIN_GENESIS_ACTIVE_VALIDATOR_COUNT` | `Uint64(2**14)` (= 16,384)                   | `Uint64(2**6)` (= 64)   |
| `MIN_GENESIS_TIME`                   | `Uint64(1606824000)` (Dec 1, 2020, 12pm UTC) | `Uint64(1578009600)`    |
| `GENESIS_FORK_VERSION`               | `Version("0x00000000")`                      | `Version("0x00000001")` |
| `GENESIS_DELAY`                      | `Uint64(604800)` (7 days)                    | `Uint64(300)`           |

### Time parameters

| Name                                  | Mainnet                   | Minimal               |
| ------------------------------------- | ------------------------- | --------------------- |
| `SLOT_DURATION_MS`                    | `Uint64(12000)`           | `Uint64(6000)`        |
| `SECONDS_PER_ETH1_BLOCK`              | `Uint64(14)`              | *same*                |
| `MIN_VALIDATOR_WITHDRAWABILITY_DELAY` | `Epoch(2**8)` (= 256)     | *same*                |
| `SHARD_COMMITTEE_PERIOD`              | `Epoch(2**8)` (= 256)     | `Epoch(2**6)` (= 64)  |
| `ETH1_FOLLOW_DISTANCE`                | `Uint64(2**11)` (= 2,048) | `Uint64(2**4)` (= 16) |

### Validator cycle

| Name                        | Mainnet                                 | Minimal               |
| --------------------------- | --------------------------------------- | --------------------- |
| `EJECTION_BALANCE`          | `Gwei(2**4 * 10**9)` (= 16,000,000,000) | *same*                |
| `MIN_PER_EPOCH_CHURN_LIMIT` | `Uint64(2**2)` (= 4)                    | `Uint64(2**1)` (= 2)  |
| `CHURN_LIMIT_QUOTIENT`      | `Uint64(2**16)` (= 65,536)              | `Uint64(2**5)` (= 32) |

## Containers

The following types are
[SimpleSerialize (SSZ)](https://github.com/ethereum/ssz-specs) containers.

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

#### `IndexedAttestation`

```python
class IndexedAttestation(Container):
    attesting_indices: AttestingIndices
    data: AttestationData
    signature: BLSSignature
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

#### `get_set_bit_count`

```lean
def get_set_bit_count
    (bits : Array Bool)
    : Uint64 :=
  bits.count true
```

#### `integer_squareroot`

```lean
def integer_squareroot
    (n : Uint64)
    : Uint64 :=
  Nat.sqrt n
```

#### `xor`

```lean
def xor
    (bytes_1 : Bytes32)
    (bytes_2 : Bytes32)
    : Bytes32 :=
  ByteArray.mk <|
    Array.zipWith (fun byte_1 byte_2 => byte_1 ^^^ byte_2) bytes_1.data bytes_2.data
```

#### `uint_to_bytes`

```python
def uint_to_bytes(n: Uint) -> bytes:
    """
    Return the SSZ serialization of ``n``, a ``Uint``.
    """
    return ssz_serialize(n)
```

#### `bytes_to_uint64`

*Note*: `data` may be shorter than eight bytes.

```python
def bytes_to_uint64(data: bytes) -> Uint64:
    """
    Return the integer deserialization of ``data`` as a ``Uint64``.
    """
    return Uint64(int.from_bytes(data, ENDIANNESS))
```

#### `saturating_sub`

```lean
def saturating_sub
    (a : Uint64)
    (b : Nat)
    : Uint64 :=
  if a > b then a - b else 0
```

<!-- eth_consensus_specs: build
```python
SSZObject = SSZType
```
-->

<!-- eth_consensus_specs: build
```lean
def ceillog2
    (x : Nat)
    : Result Uint64 := do
  require (x >= 1)
  return if x == 1 then 0 else Nat.log2 (x - 1) + 1
```
-->

<!-- eth_consensus_specs: build
```lean
def floorlog2
    (x : Nat)
    : Result Uint64 := do
  require (x >= 1)
  return Nat.log2 x
```
-->

### Crypto

#### `sha256`

```python
def sha256(data: bytes) -> Bytes32:
    """
    Return the SHA256 hash of ``data``.
    """
    return Bytes32(sha256_hash(data).digest())
```

#### `hash_tree_root`

Objects are hashed into a single root by utilizing a hash tree structure, as
defined in the [SSZ specification](https://github.com/ethereum/ssz-specs).

```python
def hash_tree_root(object: SSZObject) -> Root:
    """
    Return the hash tree root of ``object``.
    """
    return Root(object.hash_tree_root())
```

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

```lean
def is_active_validator
    (validator : Validator)
    (epoch : Epoch)
    : Bool :=
  validator.activation_epoch <= epoch && epoch < validator.exit_epoch
```

#### `is_eligible_for_activation_queue`

```lean
def is_eligible_for_activation_queue
    (validator : Validator)
    : Bool :=
  validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH
    && validator.effective_balance == MAX_EFFECTIVE_BALANCE
```

#### `is_eligible_for_activation`

```lean
def is_eligible_for_activation
    (state : BeaconState)
    (validator : Validator)
    : Bool :=
  validator.activation_eligibility_epoch <= state.finalized_checkpoint.epoch
    && validator.activation_epoch == FAR_FUTURE_EPOCH
```

#### `is_slashable_validator`

```lean
def is_slashable_validator
    (validator : Validator)
    (epoch : Epoch)
    : Bool :=
  !validator.slashed
    && validator.activation_epoch <= epoch
    && epoch < validator.withdrawable_epoch
```

#### `is_slashable_attestation_data`

```lean
def is_slashable_attestation_data
    (data_1 : AttestationData)
    (data_2 : AttestationData)
    : Bool :=
  let source_1 := data_1.source.epoch
  let source_2 := data_2.source.epoch
  let target_1 := data_1.target.epoch
  let target_2 := data_2.target.epoch
  let double_vote := data_1 != data_2 && target_1 == target_2
  let surround_vote := source_1 < source_2 && target_2 < target_1
  double_vote || surround_vote
```

#### `is_valid_indexed_attestation`

```lean
def is_valid_indexed_attestation
    (state : BeaconState)
    (indexed_attestation : IndexedAttestation)
    : Result Bool := do
  let indices := indexed_attestation.attesting_indices
  let unique := (Std.HashSet.ofList indices.toList).toArray
  if indices.size == 0 || indices != unique.qsort (fun a b => a < b) then
    return false
  let pubkeys <- indices.mapM fun index => do
    let validator <- state.validators[index]?
    return validator.pubkey
  let epoch := indexed_attestation.data.target.epoch
  let domain <- get_domain state DOMAIN_BEACON_ATTESTER (some epoch)
  let signing_root <- compute_signing_root indexed_attestation.data domain
  bls.FastAggregateVerify pubkeys signing_root indexed_attestation.signature
```

#### `compute_merkle_branch_root`

```lean
def compute_merkle_branch_root
    (leaf : Bytes32)
    (branch : Array Bytes32)
    (depth : Uint64)
    (index : Uint64)
    : Result Root := do
  let mut value := leaf
  for i in [0:depth] do
    let node <- branch[i]?
    if index / 2 ^ i % 2 == 1 then
      value := sha256 (node ++ value)
    else
      value := sha256 (value ++ node)
  return value
```

#### `is_valid_merkle_branch`

```lean
def is_valid_merkle_branch
    (leaf : Bytes32)
    (branch : Array Bytes32)
    (depth : Uint64)
    (index : Uint64)
    (root : Root)
    : Result Bool := do
  if depth != branch.size then
    return false
  let computed_root <- compute_merkle_branch_root leaf branch depth index
  return computed_root == root
```

### Misc

#### `compute_shuffled_permutation`

```lean
def compute_shuffled_permutation
    (index_count : Uint64)
    (seed : Bytes32)
    : Result (Array Uint64) := do
  let mut indices := Array.range index_count
  for current_round in [0:SHUFFLE_ROUND_COUNT] do
    let round_bytes := uint_to_bytes 1 current_round
    let pivot :=
      bytes_to_uint64 ((sha256 (seed ++ round_bytes)).extract 0 8) % index_count
    let mut source_by_bucket : Std.HashMap Uint64 Bytes32 := {}
    for i in [0:index_count] do
      let index <- indices[i]?
      let flip := (pivot + index_count - index) % index_count
      let position := max index flip
      let position_bucket := position / 256
      if !source_by_bucket.contains position_bucket then
        let bucket_bytes := uint_to_bytes 4 position_bucket
        let source := sha256 (seed ++ round_bytes ++ bucket_bytes)
        source_by_bucket := source_by_bucket.insert position_bucket source
      let source <- source_by_bucket.get? position_bucket
      let byte_val <- source[position % 256 / 8]?
      let bit := (byte_val.toNat >>> (position % 8)) % 2
      if bit == 1 then
        indices := indices.set! i flip
  return indices
```

#### `compute_shuffled_index`

```lean
def compute_shuffled_index
    (index : Uint64)
    (index_count : Uint64)
    (seed : Bytes32)
    : Result Uint64 := do
  require (index < index_count)
  let permutation <- compute_shuffled_permutation index_count seed
  return (<- permutation[index]?)
```

#### `compute_proposer_index`

```lean
def compute_proposer_index
    (state : BeaconState)
    (indices : Array ValidatorIndex)
    (seed : Bytes32)
    : Result ValidatorIndex := do
  require (indices.size > 0)
  let MAX_RANDOM_BYTE := 2 ^ 8 - 1
  let mut i := 0
  let total := indices.size
  while true do
    let candidate_index <- indices[<- compute_shuffled_index (i % total) total seed]?
    let random_byte <- (sha256 (seed ++ uint_to_bytes 8 (i / 32)))[i % 32]?
    let validator <- state.validators[candidate_index]?
    let effective_balance := validator.effective_balance
    if effective_balance * MAX_RANDOM_BYTE
        >= MAX_EFFECTIVE_BALANCE * random_byte.toNat then
      return candidate_index
    i := i + 1
  unreachable!
```

#### `compute_committee`

```lean
def compute_committee
    (indices : Array ValidatorIndex)
    (seed : Bytes32)
    (index : Uint64)
    (count : Uint64)
    : Result (Array ValidatorIndex) := do
  let start := indices.size * index / count
  let stop := indices.size * (index + 1) / count
  let mut committee := #[]
  for i in [start:stop] do
    let shuffled_index <- compute_shuffled_index i indices.size seed
    committee := committee.push (<- indices[shuffled_index]?)
  return committee
```

#### `compute_time_at_slot`

*Note*: This function is unsafe with respect to overflows and underflows.

```lean
def compute_time_at_slot
    (genesis_time : Uint64)
    (slot : Slot)
    : Uint64 :=
  let genesis_time_ms := seconds_to_milliseconds genesis_time
  let time_ms := compute_time_at_slot_ms genesis_time_ms slot
  milliseconds_to_seconds time_ms
```

#### `compute_slot_at_time`

```lean
def compute_slot_at_time
    (genesis_time : Uint64)
    (time : Uint64)
    : Slot :=
  let genesis_time_ms := seconds_to_milliseconds genesis_time
  let time_ms := seconds_to_milliseconds time
  compute_slot_at_time_ms genesis_time_ms time_ms
```

#### `compute_time_at_slot_ms`

```lean
def compute_time_at_slot_ms
    (genesis_time_ms : Uint64)
    (slot : Slot)
    : Uint64 :=
  genesis_time_ms + slot * SLOT_DURATION_MS
```

#### `compute_slot_at_time_ms`

```lean
def compute_slot_at_time_ms
    (genesis_time_ms : Uint64)
    (time_ms : Uint64)
    : Slot :=
  (time_ms - genesis_time_ms) / SLOT_DURATION_MS
```

#### `compute_epoch_at_slot`

```lean
def compute_epoch_at_slot
    (slot : Slot)
    : Epoch :=
  slot / SLOTS_PER_EPOCH
```

#### `compute_start_slot_at_epoch`

```lean
def compute_start_slot_at_epoch
    (epoch : Epoch)
    : Slot :=
  epoch * SLOTS_PER_EPOCH
```

#### `compute_activation_exit_epoch`

```lean
def compute_activation_exit_epoch
    (epoch : Epoch)
    : Epoch :=
  epoch + 1 + MAX_SEED_LOOKAHEAD
```

#### `compute_fork_data_root`

```lean
def compute_fork_data_root
    (current_version : Version)
    (genesis_validators_root : Root)
    : Result Root :=
  let fork_data : ForkData := {
    current_version
    genesis_validators_root
  }
  hash_tree_root fork_data
```

#### `compute_domain`

```lean
def compute_domain
    (domain_type : DomainType)
    (fork_version : Option Version := none)
    (genesis_validators_root : Option Root := none)
    : Result Domain := do
  let fork_version := fork_version.getD GENESIS_FORK_VERSION
  let genesis_validators_root := genesis_validators_root.getD (zeroBytes 32)
  let fork_data_root <- compute_fork_data_root fork_version genesis_validators_root
  return domain_type ++ fork_data_root.extract 0 28
```

#### `compute_signing_root`

```lean
def compute_signing_root
    {SSZObject : Type}
    [Merkleizable SSZObject]
    (ssz_object : SSZObject)
    (domain : Domain)
    : Result Root := do
  let signing_data : SigningData := {
    object_root := (<- hash_tree_root ssz_object)
    domain
  }
  hash_tree_root signing_data
```

### Beacon state accessors

#### `get_current_epoch`

```lean
def get_current_epoch
    (state : BeaconState)
    : Epoch :=
  compute_epoch_at_slot state.slot
```

#### `get_previous_epoch`

```lean
def get_previous_epoch
    (state : BeaconState)
    : Epoch :=
  saturating_sub (get_current_epoch state) 1
```

#### `get_block_root`

```lean
def get_block_root
    (state : BeaconState)
    (epoch : Epoch)
    : Result Root :=
  get_block_root_at_slot state (compute_start_slot_at_epoch epoch)
```

#### `get_block_root_at_slot`

```lean
def get_block_root_at_slot
    (state : BeaconState)
    (slot : Slot)
    : Result Root := do
  require (slot < state.slot && state.slot <= slot + SLOTS_PER_HISTORICAL_ROOT)
  return (<- state.block_roots[slot % SLOTS_PER_HISTORICAL_ROOT]?)
```

#### `get_randao_mix`

```lean
def get_randao_mix
    (state : BeaconState)
    (epoch : Epoch)
    : Result Bytes32 := do
  return (<- state.randao_mixes[epoch % EPOCHS_PER_HISTORICAL_VECTOR]?)
```

#### `get_active_validator_indices`

```lean
def get_active_validator_indices
    (state : BeaconState)
    (epoch : Epoch)
    : Array ValidatorIndex := Id.run do
  let mut indices := #[]
  for (validator, index) in state.validators.zipIdx do
    if is_active_validator validator epoch then
      indices := indices.push index
  return indices
```

#### `get_validator_churn_limit`

```lean
def get_validator_churn_limit
    (state : BeaconState)
    : Uint64 :=
  let active_validator_indices :=
    get_active_validator_indices state (get_current_epoch state)
  max MIN_PER_EPOCH_CHURN_LIMIT (active_validator_indices.size / CHURN_LIMIT_QUOTIENT)
```

#### `get_seed`

```lean
def get_seed
    (state : BeaconState)
    (epoch : Epoch)
    (domain_type : DomainType)
    : Result Bytes32 := do
  let mix <- get_randao_mix state
    (epoch + EPOCHS_PER_HISTORICAL_VECTOR - MIN_SEED_LOOKAHEAD - 1)
  return sha256 (domain_type ++ uint_to_bytes 8 epoch ++ mix)
```

#### `get_committee_count_per_slot`

```lean
def get_committee_count_per_slot
    (state : BeaconState)
    (epoch : Epoch)
    : Uint64 :=
  let active_validator_count := (get_active_validator_indices state epoch).size
  max 1 (min MAX_COMMITTEES_PER_SLOT
    (active_validator_count / SLOTS_PER_EPOCH / TARGET_COMMITTEE_SIZE))
```

#### `get_beacon_committee`

```lean
def get_beacon_committee
    (state : BeaconState)
    (slot : Slot)
    (index : CommitteeIndex)
    : Result (Array ValidatorIndex) := do
  let epoch := compute_epoch_at_slot slot
  let committees_per_slot := get_committee_count_per_slot state epoch
  compute_committee
    (indices := get_active_validator_indices state epoch)
    (seed := (<- get_seed state epoch DOMAIN_BEACON_ATTESTER))
    (index := slot % SLOTS_PER_EPOCH * committees_per_slot + index)
    (count := committees_per_slot * SLOTS_PER_EPOCH)
```

#### `get_beacon_proposer_index`

```lean
def get_beacon_proposer_index
    (state : BeaconState)
    : Result ValidatorIndex := do
  let epoch := get_current_epoch state
  let seed := sha256
    ((<- get_seed state epoch DOMAIN_BEACON_PROPOSER) ++ uint_to_bytes 8 state.slot)
  let indices := get_active_validator_indices state epoch
  compute_proposer_index state indices seed
```

#### `get_total_balance`

```lean
def get_total_balance
    (state : BeaconState)
    (indices : Std.HashSet ValidatorIndex)
    : Result Gwei := do
  let mut total := 0
  for index in indices do
    let validator <- state.validators[index]?
    total := total + validator.effective_balance
  return max EFFECTIVE_BALANCE_INCREMENT total
```

#### `get_total_active_balance`

```lean
def get_total_active_balance
    (state : BeaconState)
    : Result Gwei :=
  let indices := get_active_validator_indices state (get_current_epoch state)
  get_total_balance state (Std.HashSet.ofList indices.toList)
```

#### `get_domain`

```lean
def get_domain
    (state : BeaconState)
    (domain_type : DomainType)
    (epoch : Option Epoch := none)
    : Result Domain :=
  let epoch := epoch.getD (get_current_epoch state)
  let fork_version :=
    if epoch < state.fork.epoch then
      state.fork.previous_version
    else
      state.fork.current_version
  compute_domain domain_type (some fork_version) (some state.genesis_validators_root)
```

#### `get_indexed_attestation`

```lean
def get_indexed_attestation
    (state : BeaconState)
    (attestation : Attestation)
    : Result IndexedAttestation := do
  let attesting_indices <- get_attesting_indices state attestation
  return {
    attesting_indices := attesting_indices.toArray.qsort (fun a b => a < b)
    data := attestation.data
    signature := attestation.signature
  }
```

#### `get_attesting_indices`

```lean
def get_attesting_indices
    (state : BeaconState)
    (attestation : Attestation)
    : Result (Std.HashSet ValidatorIndex) := do
  let committee <- get_beacon_committee state attestation.data.slot attestation.data.index
  let mut indices : Std.HashSet ValidatorIndex := {}
  for (validator_index, index) in committee.zipIdx do
    if (<- attestation.aggregation_bits[index]?) then
      indices := indices.insert validator_index
  return indices
```

#### `get_pending_attesting_indices`

```lean
def get_pending_attesting_indices
    (state : BeaconState)
    (attestation : PendingAttestation)
    : Result (Std.HashSet ValidatorIndex) := do
  let committee <- get_beacon_committee state attestation.data.slot attestation.data.index
  let mut indices : Std.HashSet ValidatorIndex := {}
  for (validator_index, index) in committee.zipIdx do
    if (<- attestation.aggregation_bits[index]?) then
      indices := indices.insert validator_index
  return indices
```

### Beacon state mutators

#### `increase_balance`

```lean
def increase_balance
    (state : BeaconState)
    (index : ValidatorIndex)
    (delta : Gwei)
    : Result BeaconState := do
  let balance <- state.balances[index]?
  return { state with balances := state.balances.set! index (balance + delta) }
```

#### `decrease_balance`

```lean
def decrease_balance
    (state : BeaconState)
    (index : ValidatorIndex)
    (delta : Gwei)
    : Result BeaconState := do
  let balance <- state.balances[index]?
  let balance := saturating_sub balance delta
  return { state with balances := state.balances.set! index balance }
```

#### `initiate_validator_exit`

```lean
def initiate_validator_exit
    (state : BeaconState)
    (index : ValidatorIndex)
    : Result BeaconState := do
  let validator <- state.validators[index]?
  if validator.exit_epoch != FAR_FUTURE_EPOCH then
    return state
  let exit_epochs := (state.validators.map fun validator => validator.exit_epoch).filter
    fun exit_epoch => exit_epoch != FAR_FUTURE_EPOCH
  let mut exit_queue_epoch :=
    exit_epochs.foldl max (compute_activation_exit_epoch (get_current_epoch state))
  let exit_queue_churn := (state.validators.filter fun validator =>
    validator.exit_epoch == exit_queue_epoch).size
  if exit_queue_churn >= get_validator_churn_limit state then
    exit_queue_epoch := exit_queue_epoch + 1
  let validator := { validator with
    exit_epoch := exit_queue_epoch
    withdrawable_epoch := exit_queue_epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY
  }
  return { state with validators := state.validators.set! index validator }
```

#### `slash_validator`

```lean
def slash_validator
    (state : BeaconState)
    (slashed_index : ValidatorIndex)
    (whistleblower_index : Option ValidatorIndex := none)
    : Result BeaconState := do
  let epoch := get_current_epoch state
  let mut state <- initiate_validator_exit state slashed_index
  let validator <- state.validators[slashed_index]?
  let validator := { validator with
    slashed := true
    withdrawable_epoch :=
      max validator.withdrawable_epoch (epoch + EPOCHS_PER_SLASHINGS_VECTOR)
  }
  let slashing_index := epoch % EPOCHS_PER_SLASHINGS_VECTOR
  let slashing := (<- state.slashings[slashing_index]?) + validator.effective_balance
  state := { state with
    validators := state.validators.set! slashed_index validator
    slashings := state.slashings.set! slashing_index slashing
  }
  state <- decrease_balance state slashed_index
    (validator.effective_balance / MIN_SLASHING_PENALTY_QUOTIENT)
  let proposer_index <- get_beacon_proposer_index state
  let whistleblower_index := whistleblower_index.getD proposer_index
  let whistleblower_reward := validator.effective_balance / WHISTLEBLOWER_REWARD_QUOTIENT
  let proposer_reward := whistleblower_reward / PROPOSER_REWARD_QUOTIENT
  state <- increase_balance state proposer_index proposer_reward
  increase_balance state whistleblower_index (whistleblower_reward - proposer_reward)
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

```lean
def initialize_beacon_state_from_eth1
    (eth1_block_hash : Hash32)
    (eth1_timestamp : Uint64)
    (deposits : Array Deposit)
    : Result BeaconState := do
  let empty_body : BeaconBlockBody := default
  let mut state : BeaconState := { (default : BeaconState) with
    genesis_time := eth1_timestamp + GENESIS_DELAY
    fork := {
      previous_version := GENESIS_FORK_VERSION
      current_version := GENESIS_FORK_VERSION
      epoch := GENESIS_EPOCH
    }
    eth1_data := { (default : Eth1Data) with
      deposit_count := deposits.size
      block_hash := eth1_block_hash
    }
    latest_block_header := { (default : BeaconBlockHeader) with
      body_root := (<- hash_tree_root empty_body)
    }
    randao_mixes := Array.replicate EPOCHS_PER_HISTORICAL_VECTOR eth1_block_hash
  }
  let leaves := deposits.map fun deposit => deposit.data
  for (deposit, index) in deposits.zipIdx do
    let deposit_data_list : DepositDataList := leaves.extract 0 (index + 1)
    let eth1_data := { state.eth1_data with
      deposit_root := (<- DepositDataList.hash_tree_root deposit_data_list)
    }
    state <- process_deposit { state with eth1_data } deposit
  let mut validators := state.validators
  for index in [0:validators.size] do
    let balance <- state.balances[index]?
    let rounded_balance := balance - balance % EFFECTIVE_BALANCE_INCREMENT
    let mut validator := { (<- validators[index]?) with
      effective_balance := min rounded_balance MAX_EFFECTIVE_BALANCE
    }
    if validator.effective_balance == MAX_EFFECTIVE_BALANCE then
      validator := { validator with
        activation_eligibility_epoch := GENESIS_EPOCH
        activation_epoch := GENESIS_EPOCH
      }
    validators := validators.set! index validator
  state := { state with validators }
  let genesis_validators_root <- Validators.hash_tree_root state.validators
  return { state with genesis_validators_root }
```

*Note*: The ETH1 block with `eth1_timestamp` meeting the minimum genesis active
validator count criteria can also occur before `MIN_GENESIS_TIME`.

### Genesis state

Let `genesis_state = candidate_state` whenever
`is_valid_genesis_state(candidate_state) is True` for the first time.

```lean
def is_valid_genesis_state
    (state : BeaconState)
    : Bool := Id.run do
  if state.genesis_time < MIN_GENESIS_TIME then
    return false
  let active_validator_count := (get_active_validator_indices state GENESIS_EPOCH).size
  if active_validator_count < MIN_GENESIS_ACTIVE_VALIDATOR_COUNT then
    return false
  return true
```

### Genesis block

Let `genesis_block = BeaconBlock(state_root=hash_tree_root(genesis_state))`.

## Beacon chain state transition function

The post-state corresponding to a pre-state `state` and a signed block
`signed_block` is defined as `state_transition(state, signed_block)`. State
transitions that trigger an unhandled exception (e.g. a failed `assert` or an
out-of-range list access) are considered invalid. State transitions that cause a
`Uint64` overflow or underflow are also considered invalid.

```lean
def state_transition
    (state : BeaconState)
    (signed_block : SignedBeaconBlock)
    (validate_result : Bool := true)
    : Result BeaconState := do
  let block := signed_block.message
  let mut state <- process_slots state block.slot
  if validate_result then
    require (<- verify_block_signature state signed_block)
  state <- process_block state block
  if validate_result then
    require (block.state_root == (<- hash_tree_root state))
  return state
```

```lean
def verify_block_signature
    (state : BeaconState)
    (signed_block : SignedBeaconBlock)
    : Result Bool := do
  let proposer <- state.validators[signed_block.message.proposer_index]?
  let domain <- get_domain state DOMAIN_BEACON_PROPOSER
  let signing_root <- compute_signing_root signed_block.message domain
  bls.Verify proposer.pubkey signing_root signed_block.signature
```

```lean
def process_slots
    (state : BeaconState)
    (slot : Slot)
    : Result BeaconState := do
  require (state.slot < slot)
  let mut state := state
  while state.slot < slot do
    state <- process_slot state
    if (state.slot + 1) % SLOTS_PER_EPOCH == 0 then
      state <- process_epoch state
    state := { state with slot := state.slot + 1 }
  return state
```

```lean
def process_slot
    (state : BeaconState)
    : Result BeaconState := do
  let slot_index := state.slot % SLOTS_PER_HISTORICAL_ROOT
  let previous_state_root <- hash_tree_root state
  let mut state := { state with
    state_roots := state.state_roots.set! slot_index previous_state_root
  }
  if state.latest_block_header.state_root == zeroBytes 32 then
    let latest_block_header := { state.latest_block_header with
      state_root := previous_state_root
    }
    state := { state with latest_block_header }
  let previous_block_root <- hash_tree_root state.latest_block_header
  let block_roots := state.block_roots.set! slot_index previous_block_root
  return { state with block_roots }
```

### Epoch processing

```lean
def process_epoch
    (state : BeaconState)
    : Result BeaconState := do
  let mut state := state
  state <- process_justification_and_finalization state
  state <- process_rewards_and_penalties state
  state <- process_registry_updates state
  state <- process_slashings state
  state <- process_eth1_data_reset state
  state <- process_effective_balance_updates state
  state <- process_slashings_reset state
  state <- process_randao_mixes_reset state
  state <- process_historical_roots_update state
  state <- process_participation_record_updates state
  return state
```

#### Helpers

```lean
def get_matching_source_attestations
    (state : BeaconState)
    (epoch : Epoch)
    : Result (Array PendingAttestation) := do
  require (#[get_previous_epoch state, get_current_epoch state].contains epoch)
  if epoch == get_current_epoch state then
    return state.current_epoch_attestations
  return state.previous_epoch_attestations
```

```lean
def get_matching_target_attestations
    (state : BeaconState)
    (epoch : Epoch)
    : Result (Array PendingAttestation) := do
  (<- get_matching_source_attestations state epoch).filterM fun attestation => do
    return attestation.data.target.root == (<- get_block_root state epoch)
```

```lean
def get_matching_head_attestations
    (state : BeaconState)
    (epoch : Epoch)
    : Result (Array PendingAttestation) := do
  (<- get_matching_target_attestations state epoch).filterM fun attestation => do
    let block_root <- get_block_root_at_slot state attestation.data.slot
    return attestation.data.beacon_block_root == block_root
```

```lean
def get_unslashed_attesting_indices
    (state : BeaconState)
    (attestations : Array PendingAttestation)
    : Result (Std.HashSet ValidatorIndex) := do
  let mut output : Std.HashSet ValidatorIndex := {}
  for a in attestations do
    output := output.union (<- get_pending_attesting_indices state a)
  let mut unslashed : Std.HashSet ValidatorIndex := {}
  for index in output do
    if !(<- state.validators[index]?).slashed then
      unslashed := unslashed.insert index
  return unslashed
```

```lean
def get_attesting_balance
    (state : BeaconState)
    (attestations : Array PendingAttestation)
    : Result Gwei := do
  get_total_balance state (<- get_unslashed_attesting_indices state attestations)
```

#### Justification and finalization

```lean
def process_justification_and_finalization
    (state : BeaconState)
    : Result BeaconState := do
  if get_current_epoch state <= GENESIS_EPOCH + 1 then
    return state
  let previous_attestations <-
    get_matching_target_attestations state (get_previous_epoch state)
  let current_attestations <-
    get_matching_target_attestations state (get_current_epoch state)
  let total_active_balance <- get_total_active_balance state
  let previous_target_balance <- get_attesting_balance state previous_attestations
  let current_target_balance <- get_attesting_balance state current_attestations
  weigh_justification_and_finalization
    state total_active_balance previous_target_balance current_target_balance
```

```lean
def weigh_justification_and_finalization
    (state : BeaconState)
    (total_active_balance : Gwei)
    (previous_epoch_target_balance : Gwei)
    (current_epoch_target_balance : Gwei)
    : Result BeaconState := do
  let previous_epoch := get_previous_epoch state
  let current_epoch := get_current_epoch state
  let old_previous_justified_checkpoint := state.previous_justified_checkpoint
  let old_current_justified_checkpoint := state.current_justified_checkpoint
  let shifted := state.justification_bits.extract 0 (JUSTIFICATION_BITS_LENGTH - 1)
  let mut state := { state with
    previous_justified_checkpoint := state.current_justified_checkpoint
    justification_bits := #[false] ++ shifted
  }
  if previous_epoch_target_balance * 3 >= total_active_balance * 2 then
    state := { state with
      current_justified_checkpoint := {
        epoch := previous_epoch
        root := (<- get_block_root state previous_epoch)
      }
      justification_bits := state.justification_bits.set! 1 true
    }
  if current_epoch_target_balance * 3 >= total_active_balance * 2 then
    state := { state with
      current_justified_checkpoint := {
        epoch := current_epoch
        root := (<- get_block_root state current_epoch)
      }
      justification_bits := state.justification_bits.set! 0 true
    }
  let bits := state.justification_bits
  if (bits.extract 1 4).all id
      && old_previous_justified_checkpoint.epoch + 3 == current_epoch then
    state := { state with finalized_checkpoint := old_previous_justified_checkpoint }
  if (bits.extract 1 3).all id
      && old_previous_justified_checkpoint.epoch + 2 == current_epoch then
    state := { state with finalized_checkpoint := old_previous_justified_checkpoint }
  if (bits.extract 0 3).all id
      && old_current_justified_checkpoint.epoch + 2 == current_epoch then
    state := { state with finalized_checkpoint := old_current_justified_checkpoint }
  if (bits.extract 0 2).all id
      && old_current_justified_checkpoint.epoch + 1 == current_epoch then
    state := { state with finalized_checkpoint := old_current_justified_checkpoint }
  return state
```

#### Rewards and penalties

##### Helpers

```lean
def get_base_reward
    (state : BeaconState)
    (index : ValidatorIndex)
    : Result Gwei := do
  let total_balance <- get_total_active_balance state
  let effective_balance := (<- state.validators[index]?).effective_balance
  return effective_balance * BASE_REWARD_FACTOR / integer_squareroot total_balance
    / BASE_REWARDS_PER_EPOCH
```

```lean
def get_proposer_reward
    (state : BeaconState)
    (attesting_index : ValidatorIndex)
    : Result Gwei := do
  return (<- get_base_reward state attesting_index) / PROPOSER_REWARD_QUOTIENT
```

```lean
def get_finality_delay
    (state : BeaconState)
    : Epoch :=
  get_previous_epoch state - state.finalized_checkpoint.epoch
```

```lean
def is_in_inactivity_leak
    (state : BeaconState)
    : Bool :=
  get_finality_delay state > MIN_EPOCHS_TO_INACTIVITY_PENALTY
```

```lean
def get_eligible_validator_indices
    (state : BeaconState)
    : Array ValidatorIndex := Id.run do
  let previous_epoch := get_previous_epoch state
  let mut indices := #[]
  for (validator, index) in state.validators.zipIdx do
    if is_active_validator validator previous_epoch
        || (validator.slashed && previous_epoch + 1 < validator.withdrawable_epoch) then
      indices := indices.push index
  return indices
```

```lean
def get_attestation_component_deltas
    (state : BeaconState)
    (attestations : Array PendingAttestation)
    : Result (Prod (Array Gwei) (Array Gwei)) := do
  let mut rewards := Array.replicate state.validators.size 0
  let mut penalties := Array.replicate state.validators.size 0
  let total_balance <- get_total_active_balance state
  let unslashed_attesting_indices <- get_unslashed_attesting_indices state attestations
  let attesting_balance <- get_total_balance state unslashed_attesting_indices
  for index in get_eligible_validator_indices state do
    let base_reward <- get_base_reward state index
    if unslashed_attesting_indices.contains index then
      let increment := EFFECTIVE_BALANCE_INCREMENT
      if is_in_inactivity_leak state then
        rewards := rewards.modify index fun reward => reward + base_reward
      else
        let reward_numerator := base_reward * (attesting_balance / increment)
        rewards := rewards.modify index fun reward =>
          reward + reward_numerator / (total_balance / increment)
    else
      penalties := penalties.modify index fun penalty => penalty + base_reward
  return (rewards, penalties)
```

##### Components of attestation deltas

```lean
def get_source_deltas
    (state : BeaconState)
    : Result (Prod (Array Gwei) (Array Gwei)) := do
  let matching_source_attestations <-
    get_matching_source_attestations state (get_previous_epoch state)
  get_attestation_component_deltas state matching_source_attestations
```

```lean
def get_target_deltas
    (state : BeaconState)
    : Result (Prod (Array Gwei) (Array Gwei)) := do
  let matching_target_attestations <-
    get_matching_target_attestations state (get_previous_epoch state)
  get_attestation_component_deltas state matching_target_attestations
```

```lean
def get_head_deltas
    (state : BeaconState)
    : Result (Prod (Array Gwei) (Array Gwei)) := do
  let matching_head_attestations <-
    get_matching_head_attestations state (get_previous_epoch state)
  get_attestation_component_deltas state matching_head_attestations
```

```lean
def get_inclusion_delay_deltas
    (state : BeaconState)
    : Result (Prod (Array Gwei) (Array Gwei)) := do
  let mut rewards := Array.replicate state.validators.size 0
  let matching_source_attestations <-
    get_matching_source_attestations state (get_previous_epoch state)
  for index in (<- get_unslashed_attesting_indices state matching_source_attestations) do
    let attestations <- matching_source_attestations.filterM fun attestation => do
      return (<- get_pending_attesting_indices state attestation).contains index
    let attestation := attestations.foldl (init := (<- attestations[0]?))
      fun earliest attestation =>
        if attestation.inclusion_delay < earliest.inclusion_delay then
          attestation
        else
          earliest
    let proposer_reward <- get_proposer_reward state index
    rewards := rewards.modify attestation.proposer_index fun reward =>
      reward + proposer_reward
    let max_attester_reward := (<- get_base_reward state index) - proposer_reward
    rewards := rewards.modify index fun reward =>
      reward + max_attester_reward / attestation.inclusion_delay
  let penalties := Array.replicate state.validators.size 0
  return (rewards, penalties)
```

```lean
def get_inactivity_penalty_deltas
    (state : BeaconState)
    : Result (Prod (Array Gwei) (Array Gwei)) := do
  let mut penalties := Array.replicate state.validators.size 0
  if is_in_inactivity_leak state then
    let matching_target_attestations <-
      get_matching_target_attestations state (get_previous_epoch state)
    let matching_target_attesting_indices <-
      get_unslashed_attesting_indices state matching_target_attestations
    for index in get_eligible_validator_indices state do
      let base_reward <- get_base_reward state index
      let proposer_reward <- get_proposer_reward state index
      penalties := penalties.modify index fun penalty =>
        penalty + BASE_REWARDS_PER_EPOCH * base_reward - proposer_reward
      if !matching_target_attesting_indices.contains index then
        let effective_balance := (<- state.validators[index]?).effective_balance
        let finality_delay := get_finality_delay state
        penalties := penalties.modify index fun penalty =>
          penalty + effective_balance * finality_delay / INACTIVITY_PENALTY_QUOTIENT
  let rewards := Array.replicate state.validators.size 0
  return (rewards, penalties)
```

##### `get_attestation_deltas`

```lean
def get_attestation_deltas
    (state : BeaconState)
    : Result (Prod (Array Gwei) (Array Gwei)) := do
  let (source_rewards, source_penalties) <- get_source_deltas state
  let (target_rewards, target_penalties) <- get_target_deltas state
  let (head_rewards, head_penalties) <- get_head_deltas state
  let (inclusion_delay_rewards, _) <- get_inclusion_delay_deltas state
  let (_, inactivity_penalties) <- get_inactivity_penalty_deltas state
  let rewards <- (Array.range state.validators.size).mapM fun index => do
    return (<- source_rewards[index]?)
      + (<- target_rewards[index]?)
      + (<- head_rewards[index]?)
      + (<- inclusion_delay_rewards[index]?)
  let penalties <- (Array.range state.validators.size).mapM fun index => do
    return (<- source_penalties[index]?)
      + (<- target_penalties[index]?)
      + (<- head_penalties[index]?)
      + (<- inactivity_penalties[index]?)
  return (rewards, penalties)
```

##### `process_rewards_and_penalties`

```lean
def process_rewards_and_penalties
    (state : BeaconState)
    : Result BeaconState := do
  if get_current_epoch state == GENESIS_EPOCH then
    return state
  let (rewards, penalties) <- get_attestation_deltas state
  let mut state := state
  for index in [0:state.validators.size] do
    state <- increase_balance state index (<- rewards[index]?)
    state <- decrease_balance state index (<- penalties[index]?)
  return state
```

#### Registry updates

```lean
def process_registry_updates
    (state : BeaconState)
    : Result BeaconState := do
  let mut state := state
  for index in [0:state.validators.size] do
    let validator <- state.validators[index]?
    if is_eligible_for_activation_queue validator then
      let validator := { validator with
        activation_eligibility_epoch := get_current_epoch state + 1
      }
      state := { state with validators := state.validators.set! index validator }
    let validator <- state.validators[index]?
    if is_active_validator validator (get_current_epoch state)
        && validator.effective_balance <= EJECTION_BALANCE then
      state <- initiate_validator_exit state index
  let mut queue := #[]
  for (validator, index) in state.validators.zipIdx do
    if is_eligible_for_activation state validator then
      queue := queue.push (validator.activation_eligibility_epoch, index)
  let activation_queue := (queue.qsort fun (epoch_1, index_1) (epoch_2, index_2) =>
    epoch_1 < epoch_2 || (epoch_1 == epoch_2 && index_1 < index_2)).map Prod.snd
  for index in activation_queue.extract 0 (get_validator_churn_limit state) do
    let validator := { (<- state.validators[index]?) with
      activation_epoch := compute_activation_exit_epoch (get_current_epoch state)
    }
    state := { state with validators := state.validators.set! index validator }
  return state
```

#### Slashings

```lean
def process_slashings
    (state : BeaconState)
    : Result BeaconState := do
  let epoch := get_current_epoch state
  let total_balance <- get_total_active_balance state
  let adjusted_total_slashing_balance :=
    min (state.slashings.sum * PROPORTIONAL_SLASHING_MULTIPLIER) total_balance
  let mut state := state
  for (validator, index) in state.validators.zipIdx do
    if validator.slashed
        && epoch + EPOCHS_PER_SLASHINGS_VECTOR / 2 == validator.withdrawable_epoch then
      let increment := EFFECTIVE_BALANCE_INCREMENT
      let penalty_numerator :=
        validator.effective_balance / increment * adjusted_total_slashing_balance
      let penalty := penalty_numerator / total_balance * increment
      state <- decrease_balance state index penalty
  return state
```

#### Eth1 data votes updates

```lean
def process_eth1_data_reset
    (state : BeaconState)
    : Result BeaconState := do
  let next_epoch := get_current_epoch state + 1
  if next_epoch % EPOCHS_PER_ETH1_VOTING_PERIOD == 0 then
    return { state with eth1_data_votes := #[] }
  return state
```

#### Effective balances updates

```lean
def process_effective_balance_updates
    (state : BeaconState)
    : Result BeaconState := do
  let HYSTERESIS_INCREMENT := EFFECTIVE_BALANCE_INCREMENT / HYSTERESIS_QUOTIENT
  let DOWNWARD_THRESHOLD := HYSTERESIS_INCREMENT * HYSTERESIS_DOWNWARD_MULTIPLIER
  let UPWARD_THRESHOLD := HYSTERESIS_INCREMENT * HYSTERESIS_UPWARD_MULTIPLIER
  let mut validators := state.validators
  for index in [0:validators.size] do
    let validator <- validators[index]?
    let balance <- state.balances[index]?
    if balance + DOWNWARD_THRESHOLD < validator.effective_balance
        || validator.effective_balance + UPWARD_THRESHOLD < balance then
      let rounded_balance := balance - balance % EFFECTIVE_BALANCE_INCREMENT
      let effective_balance := min rounded_balance MAX_EFFECTIVE_BALANCE
      validators := validators.set! index { validator with effective_balance }
  return { state with validators }
```

#### Slashings balances updates

```lean
def process_slashings_reset
    (state : BeaconState)
    : Result BeaconState := do
  let next_epoch := get_current_epoch state + 1
  let index := next_epoch % EPOCHS_PER_SLASHINGS_VECTOR
  return { state with slashings := state.slashings.set! index 0 }
```

#### Randao mixes updates

```lean
def process_randao_mixes_reset
    (state : BeaconState)
    : Result BeaconState := do
  let current_epoch := get_current_epoch state
  let next_epoch := current_epoch + 1
  let index := next_epoch % EPOCHS_PER_HISTORICAL_VECTOR
  let mix <- get_randao_mix state current_epoch
  return { state with randao_mixes := state.randao_mixes.set! index mix }
```

#### Historical roots updates

```lean
def process_historical_roots_update
    (state : BeaconState)
    : Result BeaconState := do
  let next_epoch := get_current_epoch state + 1
  if next_epoch % (SLOTS_PER_HISTORICAL_ROOT / SLOTS_PER_EPOCH) == 0 then
    let historical_batch : HistoricalBatch := {
      block_roots := state.block_roots
      state_roots := state.state_roots
    }
    let root <- hash_tree_root historical_batch
    return { state with historical_roots := state.historical_roots.push root }
  return state
```

#### Participation records rotation

```lean
def process_participation_record_updates
    (state : BeaconState)
    : Result BeaconState := do
  return { state with
    previous_epoch_attestations := state.current_epoch_attestations
    current_epoch_attestations := #[]
  }
```

### Block processing

```lean
def process_block
    (state : BeaconState)
    (block : BeaconBlock)
    : Result BeaconState := do
  let mut state := state
  state <- process_block_header state block
  state <- process_randao state block.body
  state <- process_eth1_data state block.body
  state <- process_operations state block.body
  return state
```

#### Block header

```lean
def process_block_header
    (state : BeaconState)
    (block : BeaconBlock)
    : Result BeaconState := do
  require (block.slot == state.slot)
  require (block.slot > state.latest_block_header.slot)
  require (block.proposer_index == (<- get_beacon_proposer_index state))
  require (block.parent_root == (<- hash_tree_root state.latest_block_header))
  let state := { state with
    latest_block_header := {
      slot := block.slot
      proposer_index := block.proposer_index
      parent_root := block.parent_root
      state_root := zeroBytes 32
      body_root := (<- hash_tree_root block.body)
    }
  }
  let proposer <- state.validators[block.proposer_index]?
  require (!proposer.slashed)
  return state
```

#### RANDAO

```lean
def process_randao
    (state : BeaconState)
    (body : BeaconBlockBody)
    : Result BeaconState := do
  let epoch := get_current_epoch state
  let proposer <- state.validators[<- get_beacon_proposer_index state]?
  let signing_root <- compute_signing_root epoch (<- get_domain state DOMAIN_RANDAO)
  require (<- bls.Verify proposer.pubkey signing_root body.randao_reveal)
  let mix := xor (<- get_randao_mix state epoch) (sha256 body.randao_reveal)
  let index := epoch % EPOCHS_PER_HISTORICAL_VECTOR
  return { state with randao_mixes := state.randao_mixes.set! index mix }
```

#### Eth1 data

```lean
def process_eth1_data
    (state : BeaconState)
    (body : BeaconBlockBody)
    : Result BeaconState := do
  let state := { state with eth1_data_votes := state.eth1_data_votes.push body.eth1_data }
  if state.eth1_data_votes.count body.eth1_data * 2
      > EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH then
    return { state with eth1_data := body.eth1_data }
  return state
```

#### Operations

```lean
def process_operations
    (state : BeaconState)
    (body : BeaconBlockBody)
    : Result BeaconState := do
  require (body.deposits.size
    == min MAX_DEPOSITS (state.eth1_data.deposit_count - state.eth1_deposit_index))
  let mut state := state
  state <- body.proposer_slashings.foldlM process_proposer_slashing state
  state <- body.attester_slashings.foldlM process_attester_slashing state
  state <- body.attestations.foldlM process_attestation state
  state <- body.deposits.foldlM process_deposit state
  state <- body.voluntary_exits.foldlM process_voluntary_exit state
  return state
```

##### Proposer slashings

```lean
def process_proposer_slashing
    (state : BeaconState)
    (proposer_slashing : ProposerSlashing)
    : Result BeaconState := do
  let header_1 := proposer_slashing.signed_header_1.message
  let header_2 := proposer_slashing.signed_header_2.message
  require (header_1.slot == header_2.slot)
  require (header_1.proposer_index == header_2.proposer_index)
  require (header_1 != header_2)
  let proposer <- state.validators[header_1.proposer_index]?
  require (is_slashable_validator proposer (get_current_epoch state))
  for signed_header in
      #[proposer_slashing.signed_header_1, proposer_slashing.signed_header_2] do
    let epoch := compute_epoch_at_slot signed_header.message.slot
    let domain <- get_domain state DOMAIN_BEACON_PROPOSER (some epoch)
    let signing_root <- compute_signing_root signed_header.message domain
    require (<- bls.Verify proposer.pubkey signing_root signed_header.signature)
  slash_validator state header_1.proposer_index
```

##### Attester slashings

```lean
def process_attester_slashing
    (state : BeaconState)
    (attester_slashing : AttesterSlashing)
    : Result BeaconState := do
  let attestation_1 := attester_slashing.attestation_1
  let attestation_2 := attester_slashing.attestation_2
  require (is_slashable_attestation_data attestation_1.data attestation_2.data)
  require (<- is_valid_indexed_attestation state attestation_1)
  require (<- is_valid_indexed_attestation state attestation_2)
  let mut slashed_any := false
  let indices := (Std.HashSet.ofList attestation_1.attesting_indices.toList).filter
    fun index => attestation_2.attesting_indices.contains index
  let mut state := state
  for index in indices.toArray.qsort (fun a b => a < b) do
    if is_slashable_validator (<- state.validators[index]?) (get_current_epoch state) then
      state <- slash_validator state index
      slashed_any := true
  require slashed_any
  return state
```

##### Attestations

```lean
def process_attestation
    (state : BeaconState)
    (attestation : Attestation)
    : Result BeaconState := do
  let data := attestation.data
  require
    (#[get_previous_epoch state, get_current_epoch state].contains data.target.epoch)
  require (data.target.epoch == compute_epoch_at_slot data.slot)
  require (data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= state.slot
    && state.slot <= data.slot + SLOTS_PER_EPOCH)
  require (data.index < get_committee_count_per_slot state data.target.epoch)
  let committee <- get_beacon_committee state data.slot data.index
  require (attestation.aggregation_bits.size == committee.size)
  let pending_attestation : PendingAttestation := {
    aggregation_bits := attestation.aggregation_bits
    data
    inclusion_delay := state.slot - data.slot
    proposer_index := (<- get_beacon_proposer_index state)
  }
  let mut state := state
  if data.target.epoch == get_current_epoch state then
    require (data.source == state.current_justified_checkpoint)
    state := { state with
      current_epoch_attestations :=
        state.current_epoch_attestations.push pending_attestation
    }
  else
    require (data.source == state.previous_justified_checkpoint)
    state := { state with
      previous_epoch_attestations :=
        state.previous_epoch_attestations.push pending_attestation
    }
  let indexed_attestation <- get_indexed_attestation state attestation
  require (<- is_valid_indexed_attestation state indexed_attestation)
  return state
```

##### Deposits

```lean
def get_validator_from_deposit
    (pubkey : BLSPubkey)
    (withdrawal_credentials : Bytes32)
    (amount : Gwei)
    : Validator :=
  let rounded_amount := amount - amount % EFFECTIVE_BALANCE_INCREMENT
  let effective_balance := min rounded_amount MAX_EFFECTIVE_BALANCE
  {
    pubkey
    withdrawal_credentials
    effective_balance
    slashed := false
    activation_eligibility_epoch := FAR_FUTURE_EPOCH
    activation_epoch := FAR_FUTURE_EPOCH
    exit_epoch := FAR_FUTURE_EPOCH
    withdrawable_epoch := FAR_FUTURE_EPOCH
  }
```

```lean
def add_validator_to_registry
    (state : BeaconState)
    (pubkey : BLSPubkey)
    (withdrawal_credentials : Bytes32)
    (amount : Gwei)
    : Result BeaconState := do
  let validator := get_validator_from_deposit pubkey withdrawal_credentials amount
  return { state with
    validators := state.validators.push validator
    balances := state.balances.push amount
  }
```

```lean
def apply_deposit
    (state : BeaconState)
    (pubkey : BLSPubkey)
    (withdrawal_credentials : Bytes32)
    (amount : Gwei)
    (signature : BLSSignature)
    : Result BeaconState := do
  let validator_pubkeys := state.validators.map fun validator => validator.pubkey
  if !validator_pubkeys.contains pubkey then
    let deposit_message : DepositMessage := {
      pubkey
      withdrawal_credentials
      amount
    }
    let domain <- compute_domain DOMAIN_DEPOSIT
    let signing_root <- compute_signing_root deposit_message domain
    if (<- bls.Verify pubkey signing_root signature) then
      add_validator_to_registry state pubkey withdrawal_credentials amount
    else
      return state
  else
    let index <- validator_pubkeys.idxOf? pubkey
    increase_balance state index amount
```

```lean
def process_deposit
    (state : BeaconState)
    (deposit : Deposit)
    : Result BeaconState := do
  require (<- is_valid_merkle_branch
    (leaf := (<- hash_tree_root deposit.data))
    (branch := deposit.proof)
    (depth := DEPOSIT_CONTRACT_TREE_DEPTH + 1)
    (index := state.eth1_deposit_index)
    (root := state.eth1_data.deposit_root))
  let state := { state with eth1_deposit_index := state.eth1_deposit_index + 1 }
  apply_deposit
    (state := state)
    (pubkey := deposit.data.pubkey)
    (withdrawal_credentials := deposit.data.withdrawal_credentials)
    (amount := deposit.data.amount)
    (signature := deposit.data.signature)
```

##### Voluntary exits

```lean
def process_voluntary_exit
    (state : BeaconState)
    (signed_voluntary_exit : SignedVoluntaryExit)
    : Result BeaconState := do
  let voluntary_exit := signed_voluntary_exit.message
  let validator <- state.validators[voluntary_exit.validator_index]?
  require (is_active_validator validator (get_current_epoch state))
  require (validator.exit_epoch == FAR_FUTURE_EPOCH)
  require (get_current_epoch state >= voluntary_exit.epoch)
  require (get_current_epoch state >= validator.activation_epoch + SHARD_COMMITTEE_PERIOD)
  let domain <- get_domain state DOMAIN_VOLUNTARY_EXIT (some voluntary_exit.epoch)
  let signing_root <- compute_signing_root voluntary_exit domain
  require (<- bls.Verify validator.pubkey signing_root signed_voluntary_exit.signature)
  initiate_validator_exit state voluntary_exit.validator_index
```

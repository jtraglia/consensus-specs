# Fulu -- Fork Logic

*Note*: This document is a work-in-progress for researchers and implementers.

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Introduction](#introduction)
- [Configuration](#configuration)
  - [New `initialize_proposer_lookahead`](#new-initialize_proposer_lookahead)
- [Fork to Fulu](#fork-to-fulu)
  - [Fork trigger](#fork-trigger)
  - [Upgrading the state](#upgrading-the-state)

<!-- mdformat-toc end -->

## Introduction

This document describes the process of the Fulu upgrade.

## Configuration

Warning: this configuration is not definitive.

| Name                | Value                                 |
| ------------------- | ------------------------------------- |
| `FULU_FORK_VERSION` | `Version('0x06000000')`               |
| `FULU_FORK_EPOCH`   | `Epoch(18446744073709551615)` **TBD** |

#### New `initialize_proposer_lookahead`

```python
def initialize_proposer_lookahead(
    state: electra.BeaconState,
) -> Vector[ValidatorIndex, (MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH]:
    """
    Return the proposer indices for the full available lookahead starting from current epoch.
    Used to initialize the ``proposer_lookahead`` field in the beacon state at genesis and after forks.
    """
    current_epoch = get_current_epoch(state)
    lookahead = []

    # Compute proposer indices for all epochs in the lookahead period
    for epoch_offset in range(MIN_SEED_LOOKAHEAD + 1):
        epoch = Epoch(current_epoch + epoch_offset)
        indices = get_active_validator_indices(state, epoch)
        seed = get_seed(state, epoch, DOMAIN_BEACON_PROPOSER)
        start_slot = compute_start_slot_at_epoch(epoch)

        # Add proposer for each slot in this epoch
        for slot_offset in range(SLOTS_PER_EPOCH):
            slot_seed = hash(seed + uint_to_bytes(Slot(start_slot + slot_offset)))
            proposer = compute_proposer_index(state, indices, slot_seed)
            lookahead.append(proposer)

    return lookahead
```

## Fork to Fulu

### Fork trigger

The fork is triggered at epoch `FULU_FORK_EPOCH`.

Note that for the pure Fulu networks, we don't apply `upgrade_to_fulu` since it
starts with Fulu version logic.

### Upgrading the state

If `state.slot % SLOTS_PER_EPOCH == 0` and
`compute_epoch_at_slot(state.slot) == FULU_FORK_EPOCH`, an irregular state
change is made to upgrade to Fulu.

```python
def upgrade_to_fulu(pre: electra.BeaconState) -> BeaconState:
    epoch = electra.get_current_epoch(pre)
    post = BeaconState(
        genesis_time=pre.genesis_time,
        genesis_validators_root=pre.genesis_validators_root,
        slot=pre.slot,
        fork=Fork(
            previous_version=pre.fork.current_version,
            # [Modified in Fulu]
            current_version=FULU_FORK_VERSION,
            epoch=epoch,
        ),
        latest_block_header=pre.latest_block_header,
        block_roots=pre.block_roots,
        state_roots=pre.state_roots,
        historical_roots=pre.historical_roots,
        eth1_data=pre.eth1_data,
        eth1_data_votes=pre.eth1_data_votes,
        eth1_deposit_index=pre.eth1_deposit_index,
        validators=pre.validators,
        balances=pre.balances,
        randao_mixes=pre.randao_mixes,
        slashings=pre.slashings,
        previous_epoch_participation=pre.previous_epoch_participation,
        current_epoch_participation=pre.current_epoch_participation,
        justification_bits=pre.justification_bits,
        previous_justified_checkpoint=pre.previous_justified_checkpoint,
        current_justified_checkpoint=pre.current_justified_checkpoint,
        finalized_checkpoint=pre.finalized_checkpoint,
        inactivity_scores=pre.inactivity_scores,
        current_sync_committee=pre.current_sync_committee,
        next_sync_committee=pre.next_sync_committee,
        latest_execution_payload_header=pre.latest_execution_payload_header,
        next_withdrawal_index=pre.next_withdrawal_index,
        next_withdrawal_validator_index=pre.next_withdrawal_validator_index,
        historical_summaries=pre.historical_summaries,
        deposit_requests_start_index=pre.deposit_requests_start_index,
        deposit_balance_to_consume=pre.deposit_balance_to_consume,
        exit_balance_to_consume=pre.exit_balance_to_consume,
        earliest_exit_epoch=pre.earliest_exit_epoch,
        consolidation_balance_to_consume=pre.consolidation_balance_to_consume,
        earliest_consolidation_epoch=pre.earliest_consolidation_epoch,
        pending_deposits=pre.pending_deposits,
        pending_partial_withdrawals=pre.pending_partial_withdrawals,
        pending_consolidations=pre.pending_consolidations,
        # [New in Fulu:EIP7917]
        proposer_lookahead=initialize_proposer_lookahead(pre),
    )

    return post
```

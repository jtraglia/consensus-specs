# PQ -- Fork Logic

*Note*: This document is a work-in-progress for researchers and implementers.

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Introduction](#introduction)
- [Configs](#configs)
- [Helpers](#helpers)
  - [New `compute_pq_validators`](#new-compute_pq_validators)
  - [New `compute_pq_builders`](#new-compute_pq_builders)
  - [New `compute_fork_withdrawals`](#new-compute_fork_withdrawals)
  - [New `compute_pq_execution_payload_bid`](#new-compute_pq_execution_payload_bid)
- [Fork to PQ](#fork-to-pq)
  - [Fork trigger](#fork-trigger)
  - [Upgrading the state](#upgrading-the-state)

<!-- mdformat-toc end -->

## Introduction

This document describes the process of the PQ upgrade.

Before the fork, validators register their XMSS public key and VRF data, and
builders their XMSS public key, through [PQReg](../pqreg/beacon-chain.md)
registrations. At the fork, only the validators and builders that registered
move to `state.pq_validators` and `state.pq_builders`, with their registered
material. Each keeps its index, which its record stores. A validator's record
also takes its balance, participation flags, and inactivity score.
`state.validators`, `state.balances`, and `state.builders` are removed.

The fork pays out the others through `state.pending_fork_withdrawals`, which
withdrawals process before any other queue. A validator that did not register is
withdrawn in full to its withdrawal address. A validator with `0x00` withdrawal
credentials has no withdrawal address to register from, so its balance is
burned. A builder that did not register first pays its settled builder payments
to their fee recipients, and the rest of its balance is withdrawn to its
execution address. Its unsettled payments are dropped.

Deposits name their validator by BLS public key, which the state no longer
holds, so the fork refunds each pending deposit. A top-up is refunded to the
withdrawal address of the validator it tops up, since a top-up need not set its
own withdrawal credentials. A deposit for a new validator is refunded to the
address in its withdrawal credentials. A deposit is burned if those credentials
have no address.

The fork also drops the pending partial withdrawals of validators that did not
register, and the pending consolidations that involve one. It recomputes the PTC
window from the new registry. The proposer lookahead is kept, so the slots it
assigns to validators that did not register are missed.

## Configs

Warning: this configuration is not definitive.

| Name              | Value                                 |
| ----------------- | ------------------------------------- |
| `PQ_FORK_VERSION` | `Version("0xe0000000")`               |
| `PQ_FORK_EPOCH`   | `Epoch(18446744073709551615)` **TBD** |

## Helpers

### New `compute_pq_validators`

```python
def compute_pq_validators(pre: pqreg.BeaconState) -> PQValidators:
    registrations = sorted(
        pre.validator_pq_registrations, key=lambda registration: registration.validator_index
    )
    pq_validators = PQValidators()
    for registration in registrations:
        index = registration.validator_index
        validator = pre.validators[index]
        pq_validators.append(
            PQValidator(
                pubkey=XMSSPubkey(registration.pq_data[:32]),
                vrf_data=Root(registration.pq_data[32:]),
                withdrawal_credentials=validator.withdrawal_credentials,
                index=index,
                balance=pre.balances[index],
                effective_balance=validator.effective_balance,
                previous_epoch_participation=pre.previous_epoch_participation[index],
                current_epoch_participation=pre.current_epoch_participation[index],
                inactivity_score=pre.inactivity_scores[index],
                activation_eligibility_epoch=validator.activation_eligibility_epoch,
                activation_epoch=validator.activation_epoch,
                exit_epoch=validator.exit_epoch,
                withdrawable_epoch=validator.withdrawable_epoch,
                slashed=validator.slashed,
            )
        )
    return pq_validators
```

### New `compute_pq_builders`

```python
def compute_pq_builders(pre: pqreg.BeaconState) -> PQBuilders:
    registered = {
        registration.builder_pubkey: registration.pq_data
        for registration in pre.builder_pq_registrations
    }
    pq_builders = PQBuilders()
    for index, builder in enumerate(pre.builders):
        if builder.pubkey not in registered:
            continue
        pq_builders.append(
            PQBuilder(
                index=BuilderIndex(index),
                pubkey=XMSSPubkey(registered[builder.pubkey]),
                version=builder.version,
                execution_address=builder.execution_address,
                balance=builder.balance,
                deposit_epoch=builder.deposit_epoch,
                withdrawable_epoch=builder.withdrawable_epoch,
            )
        )
    return pq_builders
```

### New `compute_fork_withdrawals`

```python
def compute_fork_withdrawals(pre: pqreg.BeaconState) -> PendingForkWithdrawals:
    validator_indices = [
        registration.validator_index for registration in pre.validator_pq_registrations
    ]
    builder_pubkeys = [registration.builder_pubkey for registration in pre.builder_pq_registrations]
    withdrawals = PendingForkWithdrawals()

    # Withdraw validators that did not register, and burn those without an address
    for index, validator in enumerate(pre.validators):
        if ValidatorIndex(index) in validator_indices:
            continue
        balance = pre.balances[index]
        if pqreg.has_execution_withdrawal_credential(validator) and balance > 0:
            address = ExecutionAddress(validator.withdrawal_credentials[12:])
            withdrawals.append(PendingForkWithdrawal(address=address, amount=balance))

    # Pay the settled payments of builders that did not register
    builder_balances: dict[BuilderIndex, Gwei] = {}
    for index, builder in enumerate(pre.builders):
        if builder.pubkey not in builder_pubkeys:
            builder_balances[BuilderIndex(index)] = builder.balance
    for withdrawal in pre.builder_pending_withdrawals:
        if withdrawal.builder_index in builder_balances:
            balance = builder_balances[withdrawal.builder_index]
            amount = min(withdrawal.amount, balance)
            builder_balances[withdrawal.builder_index] = balance - amount
            if amount > 0:
                withdrawals.append(
                    PendingForkWithdrawal(address=withdrawal.fee_recipient, amount=amount)
                )

    # Withdraw the rest of their balances
    for builder_index, balance in builder_balances.items():
        if balance > 0:
            address = pre.builders[builder_index].execution_address
            withdrawals.append(PendingForkWithdrawal(address=address, amount=balance))

    # Refund pending deposits, and burn those without an address
    validator_pubkeys = [validator.pubkey for validator in pre.validators]
    for deposit in pre.pending_deposits:
        if deposit.pubkey in validator_pubkeys:
            validator = pre.validators[validator_pubkeys.index(deposit.pubkey)]
            withdrawal_credentials = validator.withdrawal_credentials
        else:
            withdrawal_credentials = deposit.withdrawal_credentials
        prefix = withdrawal_credentials[:1]
        if prefix in (ETH1_ADDRESS_WITHDRAWAL_PREFIX, COMPOUNDING_WITHDRAWAL_PREFIX):
            address = ExecutionAddress(withdrawal_credentials[12:])
            withdrawals.append(PendingForkWithdrawal(address=address, amount=deposit.amount))

    return withdrawals
```

### New `compute_pq_execution_payload_bid`

*Note*: When the parent's payload is older than the previous epoch,
`apply_parent_execution_payload` charges the bid's value to its builder. A
builder that did not register is no longer in the registry, so its bid is
carried over with no value.

```python
def compute_pq_execution_payload_bid(pre: pqreg.BeaconState) -> ExecutionPayloadBid:
    bid = pre.latest_execution_payload_bid.copy()
    builder_pubkeys = [registration.builder_pubkey for registration in pre.builder_pq_registrations]
    if (
        bid.builder_index != BUILDER_INDEX_SELF_BUILD
        and pre.builders[bid.builder_index].pubkey not in builder_pubkeys
    ):
        bid.value = Gwei(0)
    return bid
```

## Fork to PQ

### Fork trigger

The fork is triggered at epoch `PQ_FORK_EPOCH`.

### Upgrading the state

If `state.slot % SLOTS_PER_EPOCH == 0` and
`compute_epoch_at_slot(state.slot) == PQ_FORK_EPOCH`, an irregular state change
is made to upgrade to PQ.

*Note*: `latest_execution_payload_bid` keeps its `execution_requests_root`,
which may commit to the pre-fork `ExecutionRequests` type, whose root differs
from the PQ type even for identical content. The upgrade cannot recompute it
because the state stores only the commitment.

```python
def upgrade_to_pq(pre: pqreg.BeaconState) -> BeaconState:
    epoch = pqreg.get_current_epoch(pre)
    pq_validators = compute_pq_validators(pre)
    validator_indices = [validator.index for validator in pq_validators]
    pq_builders = compute_pq_builders(pre)
    builder_indices = [builder.index for builder in pq_builders]

    post = BeaconState(
        genesis_time=pre.genesis_time,
        genesis_validators_root=pre.genesis_validators_root,
        slot=pre.slot,
        fork=Fork(
            previous_version=pre.fork.current_version,
            # [Modified in PQ]
            current_version=PQ_FORK_VERSION,
            epoch=epoch,
        ),
        latest_block_header=pre.latest_block_header,
        block_roots=pre.block_roots,
        state_roots=pre.state_roots,
        historical_roots=pre.historical_roots,
        eth1_data=pre.eth1_data,
        eth1_data_votes=pre.eth1_data_votes,
        eth1_deposit_index=pre.eth1_deposit_index,
        # [Modified in PQ]
        # Removed `validators`
        # [Modified in PQ]
        # Removed `balances`
        randao_mixes=pre.randao_mixes,
        slashings=pre.slashings,
        # [Modified in PQ]
        # Removed `previous_epoch_participation`
        # [Modified in PQ]
        # Removed `current_epoch_participation`
        justification_bits=pre.justification_bits,
        previous_justified_checkpoint=pre.previous_justified_checkpoint,
        current_justified_checkpoint=pre.current_justified_checkpoint,
        finalized_checkpoint=pre.finalized_checkpoint,
        # [Modified in PQ]
        # Removed `inactivity_scores`
        # [Modified in PQ]
        # Removed `current_sync_committee`
        # [Modified in PQ]
        # Removed `next_sync_committee`
        latest_block_hash=pre.latest_block_hash,
        next_withdrawal_index=pre.next_withdrawal_index,
        next_withdrawal_validator_index=pre.next_withdrawal_validator_index,
        historical_summaries=pre.historical_summaries,
        deposit_requests_start_index=pre.deposit_requests_start_index,
        deposit_balance_to_consume=pre.deposit_balance_to_consume,
        exit_balance_to_consume=pre.exit_balance_to_consume,
        earliest_exit_epoch=pre.earliest_exit_epoch,
        consolidation_balance_to_consume=pre.consolidation_balance_to_consume,
        earliest_consolidation_epoch=pre.earliest_consolidation_epoch,
        # [Modified in PQ]
        pending_deposits=PendingDeposits(),
        # [Modified in PQ]
        pending_partial_withdrawals=PendingPartialWithdrawals(
            data=[
                withdrawal
                for withdrawal in pre.pending_partial_withdrawals
                if withdrawal.validator_index in validator_indices
            ]
        ),
        # [Modified in PQ]
        pending_consolidations=PendingConsolidations(
            data=[
                consolidation
                for consolidation in pre.pending_consolidations
                if consolidation.source_index in validator_indices
                and consolidation.target_index in validator_indices
            ]
        ),
        proposer_lookahead=pre.proposer_lookahead,
        # [Modified in PQ]
        # Removed `builders`
        next_withdrawal_builder_index=pre.next_withdrawal_builder_index,
        execution_payload_availability=pre.execution_payload_availability,
        # [Modified in PQ]
        builder_pending_payments=BuilderPendingPayments(
            data=[
                payment
                if payment.withdrawal.builder_index in builder_indices
                else BuilderPendingPayment.empty()
                for payment in pre.builder_pending_payments
            ]
        ),
        # [Modified in PQ]
        builder_pending_withdrawals=BuilderPendingWithdrawals(
            data=[
                withdrawal
                for withdrawal in pre.builder_pending_withdrawals
                if withdrawal.builder_index in builder_indices
            ]
        ),
        # [Modified in PQ]
        latest_execution_payload_bid=compute_pq_execution_payload_bid(pre),
        payload_expected_withdrawals=pre.payload_expected_withdrawals,
        ptc_window=pre.ptc_window,
        # [Modified in PQ]
        # Removed `validator_pq_registrations`
        # [Modified in PQ]
        # Removed `builder_pq_registrations`
        # [New in PQ]
        pq_validators=pq_validators,
        # [New in PQ]
        pq_builders=pq_builders,
        # [New in PQ]
        next_validator_index=ValidatorIndex(len(pre.validators)),
        # [New in PQ]
        pending_fork_withdrawals=compute_fork_withdrawals(pre),
    )

    # [New in PQ]
    post.ptc_window = initialize_ptc_window(post)

    return post
```

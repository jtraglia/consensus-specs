<!-- eth_consensus_specs: parent=none -->

# Phase 0 -- Fast Confirmation

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Introduction](#introduction)
- [Fast Confirmation Rule](#fast-confirmation-rule)
  - [Constants](#constants)
  - [Configs](#configs)
  - [Helpers](#helpers)
    - [`FastConfirmationStore`](#fastconfirmationstore)
    - [`get_fast_confirmation_store`](#get_fast_confirmation_store)
    - [Misc helper functions](#misc-helper-functions)
      - [`get_node_for_root`](#get_node_for_root)
      - [`get_block_slot`](#get_block_slot)
      - [`get_block_epoch`](#get_block_epoch)
      - [`get_checkpoint_for_block`](#get_checkpoint_for_block)
      - [`get_current_target`](#get_current_target)
      - [`is_start_slot_at_epoch`](#is_start_slot_at_epoch)
      - [`get_ancestor_roots`](#get_ancestor_roots)
    - [State helpers](#state-helpers)
      - [`get_slot_committee`](#get_slot_committee)
      - [`get_pulled_up_head_state`](#get_pulled_up_head_state)
      - [`get_previous_balance_source`](#get_previous_balance_source)
      - [`get_current_balance_source`](#get_current_balance_source)
    - [LMD-GHOST helpers](#lmd-ghost-helpers)
      - [`get_node_support_between_slots`](#get_node_support_between_slots)
      - [`is_full_validator_set_covered`](#is_full_validator_set_covered)
      - [`adjust_committee_weight_estimate_to_ensure_safety`](#adjust_committee_weight_estimate_to_ensure_safety)
      - [`estimate_committee_weight_between_slots`](#estimate_committee_weight_between_slots)
      - [`get_equivocation_score`](#get_equivocation_score)
      - [`compute_adversarial_weight`](#compute_adversarial_weight)
      - [`get_adversarial_weight`](#get_adversarial_weight)
      - [`compute_empty_slot_support_discount`](#compute_empty_slot_support_discount)
      - [`get_support_discount`](#get_support_discount)
      - [`compute_safety_threshold`](#compute_safety_threshold)
      - [`is_one_confirmed`](#is_one_confirmed)
      - [`is_confirmed_chain_safe`](#is_confirmed_chain_safe)
    - [FFG helpers](#ffg-helpers)
      - [`get_current_target_score`](#get_current_target_score)
      - [`compute_honest_ffg_support_for_current_target`](#compute_honest_ffg_support_for_current_target)
      - [`will_no_conflicting_checkpoint_be_justified`](#will_no_conflicting_checkpoint_be_justified)
      - [`will_current_target_be_justified`](#will_current_target_be_justified)
    - [`update_fast_confirmation_variables`](#update_fast_confirmation_variables)
    - [`find_latest_confirmed_descendant`](#find_latest_confirmed_descendant)
    - [`get_latest_confirmed`](#get_latest_confirmed)
    - [`get_restart_resilient_confirmed_root`](#get_restart_resilient_confirmed_root)
  - [Handlers](#handlers)
    - [`on_fast_confirmation`](#on_fast_confirmation)

<!-- mdformat-toc end -->

## Introduction

This document specifies a fast block confirmation rule (a.k.a. FCR) for the
Ethereum protocol.

The research paper for this rule can be found
[here](https://arxiv.org/abs/2405.00549).

A shorter explainer is available
[here](https://www.overleaf.com/read/cvfzznvcwffh#057762).

This rule makes the following network synchrony assumption: starting from the
current slot, attestations created by honest validators in any slot are received
by the end of that slot. Consequently, this rule provides confirmations to users
who believe in the above assumption. If this assumption is broken, confirmed
blocks can be reorged without any adversarial behavior and without slashing.

## Fast Confirmation Rule

### Constants

| Name                                            | Value       | Description                                                                                                                                                                                                                                                                                                                     |
| ----------------------------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR` | `Uint64(5)` | Per mille value to add to the estimation of the committee weight across a range of slots not covering a full epoch in order to ensure the safety of the confirmation rule with high probability. See [here](https://gist.github.com/saltiniroberto/9ee53d29c33878d79417abb2b4468c20) for an explanation about the value chosen. |

### Configs

| Name                               | Mainnet      | Minimal | Max. Value   | Description                                                                |
| ---------------------------------- | ------------ | ------- | ------------ | -------------------------------------------------------------------------- |
| `CONFIRMATION_BYZANTINE_THRESHOLD` | `Uint64(25)` | *same*  | `Uint64(25)` | Assumed maximum percentage of Byzantine validators among the validator set |

### Helpers

#### `FastConfirmationStore`

The `FastConfirmationStore` is responsible for tracking information required for
the fast confirmation rule. The fields being tracked are described below:

- `store`: read-only instance of the fork choice `Store`, added for convenience.
- `confirmed_root`: root of the most recent confirmed block.
- `previous_epoch_observed_justified_checkpoint`: a justified checkpoint that
  has been observed by all honest nodes at the beginning of the previous epoch
  assuming synchrony.
- `current_epoch_observed_justified_checkpoint`: a justified checkpoint that has
  been observed by all honest nodes at the beginning of the current epoch
  assuming synchrony.
- `previous_epoch_greatest_unrealized_checkpoint`: a greatest unrealized
  justified checkpoint at the start of the last slot of the previous epoch
  according to a local view.
- `previous_slot_head`: the head at the start of the previous slot.
- `current_slot_head`: the head at the start of the current slot.

```python
@dataclass
class FastConfirmationStore:
    store: Store
    confirmed_root: Root
    previous_epoch_observed_justified_checkpoint: Checkpoint
    current_epoch_observed_justified_checkpoint: Checkpoint
    previous_epoch_greatest_unrealized_checkpoint: Checkpoint
    previous_slot_head: Root
    current_slot_head: Root
```

#### `get_fast_confirmation_store`

Initialization of the fast confirmation store should happen at the same time as
initialization of the fork choice store and use the same trusted checkpoint.

*Note*: This function conservatively uses `store.finalized_checkpoint` for all
fast confirmation variables. Confirmed block will be advanced at any future
epoch boundary when the starting conditions are met, before that the finalized
block will be returned as the confirmed one.

```lean
def get_fast_confirmation_store
    (store : Store)
    : FastConfirmationStore :=
  {
    store
    confirmed_root := store.finalized_checkpoint.root
    previous_epoch_observed_justified_checkpoint := store.finalized_checkpoint
    current_epoch_observed_justified_checkpoint := store.finalized_checkpoint
    previous_epoch_greatest_unrealized_checkpoint := store.finalized_checkpoint
    previous_slot_head := store.finalized_checkpoint.root
    current_slot_head := store.finalized_checkpoint.root
  }
```

#### Misc helper functions

##### `get_node_for_root`

```lean
def get_node_for_root
    (block_root : Root)
    : ForkChoiceNode :=
  { root := block_root }
```

##### `get_block_slot`

```lean
def get_block_slot
    (store : Store)
    (block_root : Root)
    : Result Slot := do
  return (<- store.blocks.get? block_root).slot
```

##### `get_block_epoch`

```lean
def get_block_epoch
    (store : Store)
    (block_root : Root)
    : Result Epoch := do
  return compute_epoch_at_slot (<- store.blocks.get? block_root).slot
```

##### `get_checkpoint_for_block`

```lean
def get_checkpoint_for_block
    (store : Store)
    (block_root : Root)
    (epoch : Epoch)
    : Result Checkpoint := do
  return { epoch, root := (<- get_checkpoint_block store block_root epoch) }
```

##### `get_current_target`

```lean
def get_current_target
    (store : Store)
    : Result Checkpoint := do
  let head := (<- get_head store).root
  let current_epoch := get_current_store_epoch store
  get_checkpoint_for_block store head current_epoch
```

##### `is_start_slot_at_epoch`

```lean
def is_start_slot_at_epoch
    (slot : Slot)
    : Bool :=
  compute_slots_since_epoch_start slot == 0
```

##### `get_ancestor_roots`

```lean
def get_ancestor_roots
    (store : Store)
    (block_root : Root)
    (terminal_root : Root)
    : Result (Array Root) := do
  let mut root := block_root
  let mut ancestor_roots := #[]
  while (<- store.blocks.get? root).slot > (<- store.blocks.get? terminal_root).slot do
    ancestor_roots := #[root] ++ ancestor_roots
    root := (<- store.blocks.get? root).parent_root
    if root == terminal_root then
      return ancestor_roots
  return #[]
```

#### State helpers

This section encapsulates reads from different beacon states used by the Fast
Confirmation Rule.

Implementations MAY override the logic of each of these functions but the
semantics MUST be preserved.

##### `get_slot_committee`

*Note*: This function returns the committee for a specific slot. It MUST support
committees of epochs starting from `current_epoch - 2`.

```lean
def get_slot_committee
    (store : Store)
    (slot : Slot)
    : Result (Std.HashSet ValidatorIndex) := do
  let head := (<- get_head store).root
  let shuffling_source <- store.block_states.get? head
  let committees_count :=
    get_committee_count_per_slot shuffling_source (compute_epoch_at_slot slot)
  let mut participants : Std.HashSet ValidatorIndex := {}
  for i in [0:committees_count] do
    let committee <- get_beacon_committee shuffling_source slot i
    participants := participants.insertMany committee
  return participants
```

##### `get_pulled_up_head_state`

```lean
def get_pulled_up_head_state
    (store : Store)
    : Result BeaconState := do
  let head := (<- get_head store).root
  let head_state <- store.block_states.get? head
  if get_current_epoch head_state < get_current_store_epoch store then
    process_slots head_state (compute_start_slot_at_epoch (get_current_store_epoch store))
  else
    return head_state
```

##### `get_previous_balance_source`

*Note*: Reconfirmation is the only place where previous balance source is used.
Implementations MAY switch to the current epoch balance source after they run
reconfirmation and before the logic to confirm new blocks is called. In this
case implementations will need to keep only a single balance source around.

```lean
def get_previous_balance_source
    (fcr_store : FastConfirmationStore)
    : Result BeaconState := do
  let store := fcr_store.store
  let checkpoint := fcr_store.previous_epoch_observed_justified_checkpoint
  return (<- store.checkpoint_states.get? checkpoint)
```

##### `get_current_balance_source`

```lean
def get_current_balance_source
    (fcr_store : FastConfirmationStore)
    : Result BeaconState := do
  let store := fcr_store.store
  let checkpoint := fcr_store.current_epoch_observed_justified_checkpoint
  return (<- store.checkpoint_states.get? checkpoint)
```

#### LMD-GHOST helpers

##### `get_node_support_between_slots`

*Notes:*

Validator votes from slots before `start_slot` and after `end_slot` might not be
distinguished from votes submitted by that same validator in
`[start_slot, end_slot]` interval. Due to committee shuffling near epoch
boundary the following cases are possible:

1. Validator assigned to `start_slot - 1` and `end_slot` votes for `node` in
   `start_slot - 1` but does not vote in `end_slot`.
2. Validator assigned to `start_slot` and `end_slot + 1` misses a vote in
   `start_slot`, but votes for `node` in `end_slot + 1`.

In both cases the support would count a vote outside of the
`[start_slot, end_slot]` range. This inaccuracy is acceptable as it does not
affect safety.

Due to the algorithm logic, maximum distance between `balance_source` and
`start_slot` or `end_slot` is two epochs, which is less than
`MAX_SEED_LOOKAHEAD`. Therefore, participants of the committees from that span
of slots are consistent with the `balance_source` validator set.

```lean
def get_node_support_between_slots
    (store : Store)
    (balance_source : BeaconState)
    (node : ForkChoiceNode)
    (start_slot : Slot)
    (end_slot : Slot)
    : Result Gwei := do
  let mut participants : Std.HashSet ValidatorIndex := {}
  for slot in [start_slot:end_slot + 1] do
    participants := participants.union (<- get_slot_committee store slot)
  let mut unslashed_and_active_indices := #[]
  for index in participants do
    let validator <- balance_source.validators[index]?
    if !validator.slashed
        && is_active_validator validator (get_current_epoch balance_source) then
      unslashed_and_active_indices := unslashed_and_active_indices.push index
  let mut support := 0
  for index in unslashed_and_active_indices do
    if let some latest_message := store.latest_messages.get? index then
      if get_supported_node store latest_message == node
          && !store.equivocating_indices.contains index then
        support := support + (<- balance_source.validators[index]?).effective_balance
  return support
```

##### `is_full_validator_set_covered`

```lean
def is_full_validator_set_covered
    (start_slot : Slot)
    (end_slot : Slot)
    : Bool :=
  let start_full_epoch := compute_epoch_at_slot (start_slot + SLOTS_PER_EPOCH - 1)
  let end_full_epoch := compute_epoch_at_slot (end_slot + 1)
  start_full_epoch < end_full_epoch
```

##### `adjust_committee_weight_estimate_to_ensure_safety`

*Note*: This function adjusts the estimate of the weight of a committee for a
sequence of slots spanning an epoch boundary that does not cover any full epoch
to ensure the safety of FCR with high probability. The sequence may be longer
than SLOTS_PER_EPOCH. See
https://gist.github.com/saltiniroberto/9ee53d29c33878d79417abb2b4468c20 for an
explanation of why this is required.

```lean
def adjust_committee_weight_estimate_to_ensure_safety
    (estimate : Gwei)
    : Gwei :=
  let ceil := (estimate + 999) / 1000
  ceil * (1000 + COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR)
```

##### `estimate_committee_weight_between_slots`

```lean
def estimate_committee_weight_between_slots
    (total_active_balance : Gwei)
    (start_slot : Slot)
    (end_slot : Slot)
    : Gwei := Id.run do
  if start_slot > end_slot then
    return 0
  if is_full_validator_set_covered start_slot end_slot then
    return total_active_balance
  let start_epoch := compute_epoch_at_slot start_slot
  let end_epoch := compute_epoch_at_slot end_slot
  let committee_weight := total_active_balance / SLOTS_PER_EPOCH
  if start_epoch == end_epoch then
    return committee_weight * (end_slot - start_slot + 1)
  else
    let num_slots_in_end_epoch := compute_slots_since_epoch_start end_slot + 1
    let remaining_slots_in_end_epoch := SLOTS_PER_EPOCH - num_slots_in_end_epoch
    let num_slots_in_start_epoch :=
      SLOTS_PER_EPOCH - compute_slots_since_epoch_start start_slot
    let start_epoch_weight := committee_weight * num_slots_in_start_epoch
    let end_epoch_weight := committee_weight * num_slots_in_end_epoch
    let start_epoch_weight_pro_rated :=
      start_epoch_weight / SLOTS_PER_EPOCH * remaining_slots_in_end_epoch
    return adjust_committee_weight_estimate_to_ensure_safety
      (start_epoch_weight_pro_rated + end_epoch_weight)
```

##### `get_equivocation_score`

*Notes:*

For simplicity, this function does not seek `balance_source` for slashed
validators as those validators are very likely already in
`store.equivocating_indices`.

Due to the algorithm logic, maximum distance between `balance_source` and
`start_slot` or `end_slot` is two epochs, which is less than
`MAX_SEED_LOOKAHEAD`. Therefore, participants of the committees from that span
of slots are consistent with the `balance_source` validator set.

```lean
def get_equivocation_score
    (store : Store)
    (balance_source : BeaconState)
    (start_slot : Slot)
    (end_slot : Slot)
    : Result Gwei := do
  let mut committee_indices : Std.HashSet ValidatorIndex := {}
  for slot in [start_slot:end_slot + 1] do
    committee_indices := committee_indices.union (<- get_slot_committee store slot)
  let equivocating_indices := committee_indices.filter fun index =>
    store.equivocating_indices.contains index
  let mut active_equivocating_indices := #[]
  for index in equivocating_indices do
    let validator <- balance_source.validators[index]?
    if is_active_validator validator (get_current_epoch balance_source) then
      active_equivocating_indices := active_equivocating_indices.push index
  let mut score := 0
  for index in active_equivocating_indices do
    score := score + (<- balance_source.validators[index]?).effective_balance
  return score
```

##### `compute_adversarial_weight`

*Note*: This function computes maximum possible weight that can be adversarial
in the committees of the span of slots assuming
`CONFIRMATION_BYZANTINE_THRESHOLD` and discounting already equivocated
validators.

```lean
def compute_adversarial_weight
    (store : Store)
    (balance_source : BeaconState)
    (start_slot : Slot)
    (end_slot : Slot)
    : Result Gwei := do
  let total_active_balance <- get_total_active_balance balance_source
  let maximum_weight :=
    estimate_committee_weight_between_slots total_active_balance start_slot end_slot
  let max_adversarial_weight := maximum_weight / 100 * CONFIRMATION_BYZANTINE_THRESHOLD
  let equivocation_score <-
    get_equivocation_score store balance_source start_slot end_slot
  if max_adversarial_weight > equivocation_score then
    return max_adversarial_weight - equivocation_score
  else
    return 0
```

##### `get_adversarial_weight`

```lean
def get_adversarial_weight
    (store : Store)
    (balance_source : BeaconState)
    (block_root : Root)
    : Result Gwei := do
  let current_slot := get_current_slot store
  let block <- store.blocks.get? block_root
  let block_epoch <- get_block_epoch store block_root
  if block_epoch > (<- get_block_epoch store block.parent_root) then
    let start_slot := compute_start_slot_at_epoch block_epoch
    compute_adversarial_weight store balance_source start_slot (current_slot - 1)
  else
    compute_adversarial_weight store balance_source block.slot (current_slot - 1)
```

##### `compute_empty_slot_support_discount`

*Note*: This function MAY compute parent's block support and adversarial weight
for empty slots belonging to `current_epoch - 2`. It can only happen in
reconfirmation, in all other cases the earliest possible epoch is
`current_epoch - 1`.

```lean
def compute_empty_slot_support_discount
    (store : Store)
    (balance_source : BeaconState)
    (block_root : Root)
    : Result Gwei := do
  let block <- store.blocks.get? block_root
  let parent_block <- store.blocks.get? block.parent_root
  if parent_block.slot + 1 == block.slot then
    return 0
  let parent_node <- get_ancestor store (get_node_for_root block_root) parent_block.slot
  let parent_support_in_empty_slots <- get_node_support_between_slots
    store balance_source parent_node (parent_block.slot + 1) (block.slot - 1)
  let adversarial_weight <- compute_adversarial_weight
    store balance_source (parent_block.slot + 1) (block.slot - 1)
  if parent_support_in_empty_slots > adversarial_weight then
    return parent_support_in_empty_slots - adversarial_weight
  else
    return 0
```

##### `get_support_discount`

```lean
def get_support_discount
    (store : Store)
    (balance_source : BeaconState)
    (block_root : Root)
    : Result Gwei :=
  compute_empty_slot_support_discount store balance_source block_root
```

##### `compute_safety_threshold`

```lean
def compute_safety_threshold
    (store : Store)
    (block_root : Root)
    (balance_source : BeaconState)
    : Result Gwei := do
  let current_slot := get_current_slot store
  let block <- store.blocks.get? block_root
  let parent_block <- store.blocks.get? block.parent_root
  let total_active_balance <- get_total_active_balance balance_source
  let proposer_score <- compute_proposer_score balance_source
  let maximum_support := estimate_committee_weight_between_slots
    total_active_balance (parent_block.slot + 1) (current_slot - 1)
  let support_discount <- get_support_discount store balance_source block_root
  let adversarial_weight <- get_adversarial_weight store balance_source block_root
  if support_discount < maximum_support + proposer_score + 2 * adversarial_weight then
    let weight := maximum_support + proposer_score + 2 * adversarial_weight
    return (weight - support_discount) / 2
  else
    return 0
```

##### `is_one_confirmed`

*Notes:*

This function checks if a single block is LMD-GHOST safe by computing LMD-GHOST
safety indicator and comparing its value to the safety threshold.

At a high level the computation checks whether the actual score of the block
outweighs potential score of any block conflicting with it considering total
weight of the committees and maximal adversarial weight.

If this check passes the block is deemed LMD-GHOST safe, but it is not enough to
say that the block will remain canonical. To ensure the latter, each ancestor of
the block would also have to pass this check.

More details on this check can be found in the
[paper](https://arxiv.org/abs/2405.00549).

This function **MUST** return `False` if `block_root` status is **not** `VALID`
according to the [Optimistic sync](../bellatrix/optimistic-sync.md)
specification.

```lean
def is_one_confirmed
    (store : Store)
    (balance_source : BeaconState)
    (block_root : Root)
    : Result Bool := do
  let support <- get_attestation_score store (get_node_for_root block_root) balance_source
  let safety_threshold <- compute_safety_threshold store block_root balance_source
  return support > safety_threshold
```

##### `is_confirmed_chain_safe`

*Notes*:

This function should be called at the start of each epoch to ensure that the
confirmed chain starting from
`fcr_store.current_epoch_observed_justified_checkpoint.root` remains LMD-GHOST
safe.

This check relaxes synchrony assumption by allowing GST to start from the
beginning of the previous slot. If such check was not run, GST start would have
to be assumed from the time of the first run of the algorithm which could have
been many epochs ago.

```lean
def is_confirmed_chain_safe
    (fcr_store : FastConfirmationStore)
    (confirmed_root : Root)
    : Result Bool := do
  let store := fcr_store.store
  let checkpoint := fcr_store.current_epoch_observed_justified_checkpoint
  if checkpoint
      != (<- get_checkpoint_for_block store confirmed_root checkpoint.epoch) then
    return false
  let current_epoch := get_current_store_epoch store
  let start_root_exclusive <-
    if checkpoint.epoch + 1 >= current_epoch then
      pure checkpoint.root
    else do
      let node := get_node_for_root confirmed_root
      let slot := compute_start_slot_at_epoch (current_epoch - 1)
      let ancestor_at_previous_epoch_start := (<- get_ancestor store node slot).root
      let ancestor_epoch <- get_block_epoch store ancestor_at_previous_epoch_start
      if ancestor_epoch + 1 == current_epoch then
        pure (<- store.blocks.get? ancestor_at_previous_epoch_start).parent_root
      else
        pure ancestor_at_previous_epoch_start
  let chain_roots <- get_ancestor_roots store confirmed_root start_root_exclusive
  chain_roots.allM fun root => do
    is_one_confirmed store (<- get_previous_balance_source fcr_store) root
```

#### FFG helpers

##### `get_current_target_score`

*Note*: This function uses LMD-GHOST votes to estimate the FFG support of the
current epoch target. Due to the way the computation happens, it MUST be used no
later than the end of the current epoch.

```lean
def get_current_target_score
    (store : Store)
    : Result Gwei := do
  let target <- get_current_target store
  let state <- get_pulled_up_head_state store
  let unslashed_and_active_indices <-
    (get_active_validator_indices state (get_current_epoch state)).filterM fun index => do
      return !(<- state.validators[index]?).slashed
  let mut score := 0
  for index in unslashed_and_active_indices do
    if let some latest_message := store.latest_messages.get? index then
      if !store.equivocating_indices.contains index then
        let epoch := get_latest_message_epoch latest_message
        if target == (<- get_checkpoint_for_block store latest_message.root epoch) then
          score := score + (<- state.validators[index]?).effective_balance
  return score
```

##### `compute_honest_ffg_support_for_current_target`

*Note*: This function computes honest FFG support of the current epoch target by
assuming `CONFIRMATION_BYZANTINE_THRESHOLD` and network synchrony, and taking
into account votes supporting the target that have been received thus far.

```lean
def compute_honest_ffg_support_for_current_target
    (store : Store)
    : Result Gwei := do
  let current_slot := get_current_slot store
  let current_epoch := compute_epoch_at_slot current_slot
  let balance_source <- get_pulled_up_head_state store
  let total_active_balance <- get_total_active_balance balance_source
  let ffg_support_for_checkpoint <- get_current_target_score store
  let ffg_weight_till_now := estimate_committee_weight_between_slots
    total_active_balance (compute_start_slot_at_epoch current_epoch) (current_slot - 1)
  let remaining_ffg_weight := total_active_balance - ffg_weight_till_now
  let remaining_honest_ffg_weight :=
    remaining_ffg_weight / 100 * (100 - CONFIRMATION_BYZANTINE_THRESHOLD)
  let adversarial_weight <- compute_adversarial_weight
    store balance_source (compute_start_slot_at_epoch current_epoch) (current_slot - 1)
  let min_honest_ffg_support :=
    saturating_sub ffg_support_for_checkpoint adversarial_weight
  return min_honest_ffg_support + remaining_honest_ffg_weight
```

##### `will_no_conflicting_checkpoint_be_justified`

*Note*: This function assumes that all honest validators will be voting in
support of the current epoch target starting from the current moment in time.

```lean
def will_no_conflicting_checkpoint_be_justified
    (store : Store)
    : Result Bool := do
  if (<- get_current_target store) == store.unrealized_justified_checkpoint then
    return true
  let state <- get_pulled_up_head_state store
  let total_active_balance <- get_total_active_balance state
  let honest_ffg_support <- compute_honest_ffg_support_for_current_target store
  return 3 * honest_ffg_support > 1 * total_active_balance
```

##### `will_current_target_be_justified`

*Note*: This function assumes that all honest validators will be voting in
support of the current epoch target starting from the current moment in time.

```lean
def will_current_target_be_justified
    (store : Store)
    : Result Bool := do
  let state <- get_pulled_up_head_state store
  let total_active_balance <- get_total_active_balance state
  let honest_ffg_support <- compute_honest_ffg_support_for_current_target store
  return 3 * honest_ffg_support >= 2 * total_active_balance
```

#### `update_fast_confirmation_variables`

*Note*: This function updates variables used by the fast confirmation rule.

```lean
def update_fast_confirmation_variables
    (fcr_store : FastConfirmationStore)
    : Result FastConfirmationStore := do
  let store := fcr_store.store
  let mut fcr_store := { fcr_store with
    previous_slot_head := fcr_store.current_slot_head
    current_slot_head := (<- get_head store).root
  }
  if is_start_slot_at_epoch (get_current_slot store + 1) then
    fcr_store := { fcr_store with
      previous_epoch_greatest_unrealized_checkpoint :=
        store.unrealized_justified_checkpoint
    }
  if is_start_slot_at_epoch (get_current_slot store) then
    fcr_store := { fcr_store with
      previous_epoch_observed_justified_checkpoint :=
        fcr_store.current_epoch_observed_justified_checkpoint
      current_epoch_observed_justified_checkpoint :=
        fcr_store.previous_epoch_greatest_unrealized_checkpoint
    }
  return fcr_store
```

#### `find_latest_confirmed_descendant`

*Notes*:

This function examines canonical chain blocks starting from
`latest_confirmed_root` and returns the most recent block that satisfies FCR
conditions:

1. Each block in its chain is LMD-GHOST safe, i.e. will be the winner of the
   LMD-GHOST fork choice rule starting from the current moment in time.
2. The block will not be filtered out during the current and the next epochs.

Assuming synchrony and `CONFIRMATION_BYZANTINE_THRESHOLD` value, the above
criteria ensures that the block returned by this function will remain canonical
in the view of all honest validators starting from the current moment in time.

This function works correctly only if the `latest_confirmed_root` belongs to the
canonical chain and is either from the previous or from the current epoch.

```lean
def find_latest_confirmed_descendant
    (fcr_store : FastConfirmationStore)
    (latest_confirmed_root : Root)
    : Result Root := do
  let store := fcr_store.store
  let head := (<- get_head store).root
  let current_epoch := get_current_store_epoch store
  let mut confirmed_root := latest_confirmed_root
  let is_epoch_start : Result Bool :=
    pure (is_start_slot_at_epoch (get_current_slot store))
  let is_confirmed_from_previous_epoch : Result Bool := do
    return (<- get_block_epoch store confirmed_root) + 1 == current_epoch
  let is_previous_head_source_recent : Result Bool := do
    let voting_source <- get_voting_source store fcr_store.previous_slot_head
    return voting_source.epoch + 2 >= current_epoch
  let is_previous_head_justified_recently : Result Bool := do
    let checkpoint <- store.unrealized_justifications.get? fcr_store.previous_slot_head
    return checkpoint.epoch + 1 >= current_epoch
  let is_head_justified_recently : Result Bool := do
    return (<- store.unrealized_justifications.get? head).epoch + 1 >= current_epoch
  if (<- is_confirmed_from_previous_epoch
      <&&> is_previous_head_source_recent
      <&&> (is_epoch_start
        <||> (will_no_conflicting_checkpoint_be_justified store
          <&&> (is_previous_head_justified_recently
            <||> is_head_justified_recently)))) then
    let canonical_roots <- get_ancestor_roots store head confirmed_root
    for block_root in canonical_roots do
      let block_epoch <- get_block_epoch store block_root
      if block_epoch == current_epoch then
        break
      let previous_head := get_node_for_root fcr_store.previous_slot_head
      if !(<- is_ancestor store previous_head (get_node_for_root block_root)) then
        break
      let balance_source <- get_current_balance_source fcr_store
      if !(<- is_one_confirmed store balance_source block_root) then
        break
      confirmed_root := block_root
  if (<- is_epoch_start <||> is_head_justified_recently) then
    let canonical_roots <- get_ancestor_roots store head confirmed_root
    let mut tentative_confirmed_root := confirmed_root
    for block_root in canonical_roots do
      let block_epoch <- get_block_epoch store block_root
      let tentative_confirmed_epoch <- get_block_epoch store tentative_confirmed_root
      if block_epoch > tentative_confirmed_epoch then
        if !(<- will_current_target_be_justified store) then
          break
      let balance_source <- get_current_balance_source fcr_store
      if !(<- is_one_confirmed store balance_source block_root) then
        break
      tentative_confirmed_root := block_root
    let is_tentative_from_current_epoch : Result Bool := do
      return (<- get_block_epoch store tentative_confirmed_root) == current_epoch
    let is_tentative_source_recent : Result Bool := do
      let voting_source <- get_voting_source store tentative_confirmed_root
      return voting_source.epoch + 2 >= current_epoch
    if (<- is_tentative_from_current_epoch
        <||> (is_tentative_source_recent
          <&&> (is_epoch_start
            <||> will_no_conflicting_checkpoint_be_justified store))) then
      confirmed_root := tentative_confirmed_root
  return confirmed_root
```

#### `get_latest_confirmed`

*Notes:*

This function executes the FCR algorithm which takes the following sequence of
actions:

1. Check if the `fcr_store.confirmed_root` belongs to the canonical chain and is
   not older than the previous epoch.
2. Check if the confirmed chain starting from the
   `fcr_store.current_epoch_observed_justified_checkpoint` can be re-confirmed
   at the start of the current epoch which resets GST to the start of the
   current epoch.
3. If any of the above checks fail, set `fcr_store.confirmed_root` to the
   `store.finalized_checkpoint.root`. Either of the above conditions signify
   that FCR assumptions (at least synchrony) are broken and the confirmed block
   might not be safe.
4. Restart the confirmation chain by setting `fcr_store.confirmed_root` to
   `fcr_store.current_epoch_observed_justified_checkpoint.root` if the restart
   conditions are met. Under synchrony, such a checkpoint is for sure now the
   greatest justified checkpoint in the view of any honest validator and,
   therefore, any honest validator will keep voting for it for the entire epoch.
5. Attempt to advance the `fcr_store.confirmed_root` by calling
   `find_latest_confirmed_descendant`.

```lean
def get_latest_confirmed
    (fcr_store : FastConfirmationStore)
    : Result Root := do
  let store := fcr_store.store
  let mut confirmed_root := fcr_store.confirmed_root
  let current_epoch := get_current_store_epoch store
  let head := (<- get_head store).root
  let is_epoch_start : Result Bool :=
    pure (is_start_slot_at_epoch (get_current_slot store))
  let is_confirmed_too_old : Result Bool := do
    return (<- get_block_epoch store confirmed_root) + 1 < current_epoch
  let is_confirmed_not_canonical : Result Bool := do
    let confirmed_node := get_node_for_root confirmed_root
    return !(<- is_ancestor store (get_node_for_root head) confirmed_node)
  let is_confirmed_chain_unsafe : Result Bool := do
    return !(<- is_confirmed_chain_safe fcr_store confirmed_root)
  if (<- is_confirmed_too_old
      <||> is_confirmed_not_canonical
      <||> (is_epoch_start <&&> is_confirmed_chain_unsafe)) then
    confirmed_root := store.finalized_checkpoint.root
  let is_epoch_start := is_start_slot_at_epoch (get_current_slot store)
  let observed_justified_block_slot <-
    get_block_slot store fcr_store.current_epoch_observed_justified_checkpoint.root
  let is_observed_justified_block_epoch_ok :=
    compute_epoch_at_slot observed_justified_block_slot + 1 == current_epoch
  let is_head_unrealized_justified_ok :=
    fcr_store.current_epoch_observed_justified_checkpoint
      == (<- store.unrealized_justifications.get? head)
  let is_confirmed_block_stale :=
    (<- get_block_slot store confirmed_root) < observed_justified_block_slot
  if is_epoch_start
      && is_observed_justified_block_epoch_ok
      && is_head_unrealized_justified_ok
      && is_confirmed_block_stale then
    confirmed_root := fcr_store.current_epoch_observed_justified_checkpoint.root
  if (<- get_block_epoch store confirmed_root) + 1 >= current_epoch then
    find_latest_confirmed_descendant fcr_store confirmed_root
  else
    return confirmed_root
```

#### `get_restart_resilient_confirmed_root`

*Note*: Implementations MAY use the mechanism below to restore the confirmed
root after a restart. This mechanism is safe as long as synchrony has been
maintained for at least three epochs since the node went offline. If used,
`get_restart_resilient_confirmed_root` MUST be called once the node is fully
synced and `on_fast_confirmation` has been called. The body of
`get_root_confirmed_before_restart` is implementation dependent.

```lean
def block_should_be_finalized
    (store : Store)
    (block_root : Root)
    : Result Bool := do
  let block_slot <- get_block_slot store block_root
  let next_checkpoint_epoch := compute_epoch_at_slot (block_slot + SLOTS_PER_EPOCH - 1)
  let earliest_finality_slot := compute_start_slot_at_epoch (next_checkpoint_epoch + 2)
  return earliest_finality_slot <= get_current_slot store
```

```lean
def get_restart_resilient_confirmed_root
    (fcr_store : FastConfirmationStore)
    : Result Root := do
  let store := fcr_store.store
  let root_before_restart := get_root_confirmed_before_restart
  let root_before_restart_slot <- get_block_slot store root_before_restart
  if root_before_restart_slot <= (<- get_block_slot store fcr_store.confirmed_root) then
    return fcr_store.confirmed_root
  if (<- block_should_be_finalized store root_before_restart) then
    return fcr_store.confirmed_root
  let head <- get_head store
  if !(<- is_ancestor store head (get_node_for_root root_before_restart)) then
    return fcr_store.confirmed_root
  return root_before_restart
```

<!-- eth_consensus_specs: build
```lean
def get_root_confirmed_before_restart
    : Root :=
  zeroBytes 32
```
-->

### Handlers

#### `on_fast_confirmation`

*Notes:*

This handler calls `update_fast_confirmation_variables` and then
`get_latest_confirmed` to update `fcr_store.confirmed_root` with the response of
that call.

Implementations MUST strictly follow the call sequence:

1. `update_fast_confirmation_variables`
2. `get_latest_confirmed`

Implementations MUST call `update_fast_confirmation_variables` in the first part
of a slot after attestations from past slots have been applied and before
`get_attestation_due_ms(epoch)` milliseconds has transpired since the start of
the slot.

Implementations MAY call `update_fast_confirmation_variables` after a valid
block from the expected block proposer for the assigned `slot` has been received
and processed if this happens before `get_attestation_due_ms(epoch)`
milliseconds has transpired since the start of the `slot`. Regardless of the
time of the call, `update_fast_confirmation_variables` MUST be called only once
per slot.

Implementations MAY call `get_latest_confirmed` at any point in time throughout
a slot.

```lean
def on_fast_confirmation
    (fcr_store : FastConfirmationStore)
    : Result FastConfirmationStore := do
  let fcr_store <- update_fast_confirmation_variables fcr_store
  return { fcr_store with confirmed_root := (<- get_latest_confirmed fcr_store) }
```

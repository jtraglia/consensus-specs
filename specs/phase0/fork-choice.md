<!-- eth_consensus_specs: parent=none -->

# Phase 0 -- Beacon Chain Fork Choice

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Introduction](#introduction)
- [Fork choice](#fork-choice)
  - [Constants](#constants)
  - [Configs](#configs)
    - [Time parameters](#time-parameters)
  - [Helpers](#helpers)
    - [`ForkChoiceNode`](#forkchoicenode)
    - [`LatestMessage`](#latestmessage)
    - [`Store`](#store)
    - [`get_forkchoice_store`](#get_forkchoice_store)
    - [`get_time_into_slot_ms`](#get_time_into_slot_ms)
    - [`get_slots_since_genesis`](#get_slots_since_genesis)
    - [`get_current_slot`](#get_current_slot)
    - [`get_current_store_epoch`](#get_current_store_epoch)
    - [`compute_slots_since_epoch_start`](#compute_slots_since_epoch_start)
    - [`get_ancestor`](#get_ancestor)
    - [`is_ancestor`](#is_ancestor)
    - [`calculate_committee_fraction`](#calculate_committee_fraction)
    - [`get_checkpoint_block`](#get_checkpoint_block)
    - [`get_supported_node`](#get_supported_node)
    - [`get_attestation_score`](#get_attestation_score)
    - [`compute_proposer_score`](#compute_proposer_score)
    - [`get_proposer_score`](#get_proposer_score)
    - [`get_weight`](#get_weight)
    - [`get_voting_source`](#get_voting_source)
    - [`get_node_children`](#get_node_children)
    - [`filter_node_tree`](#filter_node_tree)
    - [`get_filtered_node_tree`](#get_filtered_node_tree)
    - [`get_head`](#get_head)
    - [`update_checkpoints`](#update_checkpoints)
    - [`update_unrealized_checkpoints`](#update_unrealized_checkpoints)
    - [`get_latest_message_epoch`](#get_latest_message_epoch)
    - [`seconds_to_milliseconds`](#seconds_to_milliseconds)
    - [`milliseconds_to_seconds`](#milliseconds_to_seconds)
    - [`get_slot_component_duration_ms`](#get_slot_component_duration_ms)
    - [`get_attestation_due_ms`](#get_attestation_due_ms)
    - [`get_proposer_reorg_cutoff_ms`](#get_proposer_reorg_cutoff_ms)
    - [`get_aggregate_due_ms`](#get_aggregate_due_ms)
    - [Proposer head and reorg helpers](#proposer-head-and-reorg-helpers)
      - [`is_head_late`](#is_head_late)
      - [`is_shuffling_stable`](#is_shuffling_stable)
      - [`is_ffg_competitive`](#is_ffg_competitive)
      - [`is_finalization_ok`](#is_finalization_ok)
      - [`is_proposing_on_time`](#is_proposing_on_time)
      - [`is_head_weak`](#is_head_weak)
      - [`is_parent_strong`](#is_parent_strong)
      - [`is_proposer_equivocation`](#is_proposer_equivocation)
      - [`get_proposer_head`](#get_proposer_head)
    - [Pull-up tip helpers](#pull-up-tip-helpers)
      - [`compute_pulled_up_tip`](#compute_pulled_up_tip)
    - [`on_tick` helpers](#on_tick-helpers)
      - [`on_tick_per_slot`](#on_tick_per_slot)
    - [`on_attestation` helpers](#on_attestation-helpers)
      - [`validate_target_epoch_against_current_time`](#validate_target_epoch_against_current_time)
      - [`validate_on_attestation`](#validate_on_attestation)
      - [`store_target_checkpoint_state`](#store_target_checkpoint_state)
      - [`update_latest_messages`](#update_latest_messages)
    - [`on_block` helpers](#on_block-helpers)
      - [`record_block_timeliness`](#record_block_timeliness)
      - [`compute_shuffling_lookahead_start_slot`](#compute_shuffling_lookahead_start_slot)
      - [`compute_shuffling_dependent_slot`](#compute_shuffling_dependent_slot)
      - [`get_shuffling_dependent_root`](#get_shuffling_dependent_root)
      - [`update_proposer_boost_root`](#update_proposer_boost_root)
  - [Handlers](#handlers)
    - [`on_tick`](#on_tick)
    - [`on_block`](#on_block)
    - [`on_attestation`](#on_attestation)
    - [`on_attester_slashing`](#on_attester_slashing)

<!-- mdformat-toc end -->

## Introduction

This document is the beacon-chain fork choice specification, part of Phase 0. It
assumes the
[beacon-chain state transition function specification](./beacon-chain.md).

## Fork choice

The head block node associated with a `store` is defined as `get_head(store)`.
At genesis, let `store = get_forkchoice_store(genesis_state, genesis_block)` and
update `store` by running:

- `on_tick(store, time_ms)` whenever `time_ms > store.time_ms` where `time_ms`
  is the current Unix time in milliseconds
- `on_block(store, block)` whenever a block `block: SignedBeaconBlock` is
  received
- `on_attestation(store, attestation)` whenever an attestation `attestation` is
  received
- `on_attester_slashing(store, attester_slashing)` whenever an attester slashing
  `attester_slashing` is received

Any of the above handlers that trigger an unhandled exception (e.g. a failed
assert or an out-of-range list access) are considered invalid. Invalid calls to
handlers must not modify `store`.

*Notes*:

1. **Leap seconds**: Slots will last `SLOT_DURATION_MS + 1000` or
   `SLOT_DURATION_MS - 1000` milliseconds around leap seconds. This is
   automatically handled by
   [UNIX time](https://en.wikipedia.org/wiki/Unix_time).
2. **Honest clocks**: Honest nodes are assumed to have clocks synchronized
   within `SLOT_DURATION_MS` milliseconds of each other.
3. **Eth1 data**: The large `ETH1_FOLLOW_DISTANCE` specified in the
   [honest validator document](./validator.md) should ensure that
   `state.latest_eth1_data` of the canonical beacon chain remains consistent
   with the canonical Ethereum proof-of-work chain. If not, emergency manual
   intervention will be required.
4. **Manual forks**: Manual forks may arbitrarily change the fork choice rule
   but are expected to be enacted at epoch transitions, with the fork details
   reflected in `state.fork`.
5. **Implementation**: The implementation found in this specification is
   constructed for ease of understanding rather than for optimization in
   computation, space, or any other resource. A number of optimized alternatives
   can be found [here](https://github.com/protolambda/lmd-ghost).

### Constants

| Name           | Value           |
| -------------- | --------------- |
| `BASIS_POINTS` | `Uint64(10000)` |

### Configs

| Name                                  | Mainnet       | Minimal |
| ------------------------------------- | ------------- | ------- |
| `PROPOSER_SCORE_BOOST`                | `Uint64(40)`  | *same*  |
| `REORG_HEAD_WEIGHT_THRESHOLD`         | `Uint64(20)`  | *same*  |
| `REORG_PARENT_WEIGHT_THRESHOLD`       | `Uint64(160)` | *same*  |
| `REORG_MAX_EPOCHS_SINCE_FINALIZATION` | `Epoch(2)`    | *same*  |

- The proposer score boost and re-org weight threshold are percentage values
  that are measured with respect to the weight of a single committee. See
  `calculate_committee_fraction`.

#### Time parameters

| Name                        | Mainnet        | Minimal | Duration                   |
| --------------------------- | -------------- | ------- | -------------------------- |
| `PROPOSER_REORG_CUTOFF_BPS` | `Uint64(1667)` | *same*  | ~17% of `SLOT_DURATION_MS` |

### Helpers

#### `ForkChoiceNode`

*Note*: In Phase0, `ForkChoiceNode` and `BeaconBlock` have a one-to-one mapping.
This abstraction is introduced to support upgradability.

```python
@dataclass(eq=True, frozen=True)
class ForkChoiceNode:
    root: Root
```

#### `LatestMessage`

```python
@dataclass(eq=True, frozen=True)
class LatestMessage:
    epoch: Epoch
    root: Root
```

#### `Store`

The `Store` is responsible for tracking information required for the fork choice
algorithm. The important fields being tracked are described below:

- `justified_checkpoint`: the justified checkpoint used as the starting point
  for the LMD GHOST fork choice algorithm.
- `finalized_checkpoint`: the highest known finalized checkpoint. The fork
  choice only considers blocks that are not conflicting with this checkpoint.
- `unrealized_justified_checkpoint` & `unrealized_finalized_checkpoint`: these
  track the highest justified & finalized checkpoints respectively, without
  regard to whether on-chain ***realization*** has occurred, i.e. FFG processing
  of new attestations within the state transition function. This is an important
  distinction from `justified_checkpoint` & `finalized_checkpoint`, because they
  will only track the checkpoints that are realized on-chain. Note that on-chain
  processing of FFG information only happens at epoch boundaries.
- `unrealized_justifications`: stores a map of block root to the unrealized
  justified checkpoint observed in that block.

```python
@dataclass
class Store:
    time_ms: Uint64
    genesis_time_ms: Uint64
    justified_checkpoint: Checkpoint
    finalized_checkpoint: Checkpoint
    unrealized_justified_checkpoint: Checkpoint
    unrealized_finalized_checkpoint: Checkpoint
    proposer_boost_root: Root
    equivocating_indices: set[ValidatorIndex]
    blocks: dict[Root, BeaconBlock]
    block_states: dict[Root, BeaconState]
    block_timeliness: dict[Root, bool]
    checkpoint_states: dict[Checkpoint, BeaconState]
    latest_messages: dict[ValidatorIndex, LatestMessage]
    unrealized_justifications: dict[Root, Checkpoint]
```

#### `get_forkchoice_store`

The provided anchor-state will be regarded as a trusted state, to not roll back
beyond. This should be the genesis state for a full client.

*Note*: With regards to fork choice, block headers are interchangeable with
blocks. The specification is likely to move to headers for reduced overhead in
test vectors and better encapsulation. Full implementations store blocks as part
of their database and will often use full blocks when dealing with production
fork choice.

```lean
def get_forkchoice_store
    (anchor_state : BeaconState)
    (anchor_block : BeaconBlock)
    : Result Store := do
  require (anchor_block.state_root == (<- hash_tree_root anchor_state))
  let anchor_root <- hash_tree_root anchor_block
  let anchor_epoch := get_current_epoch anchor_state
  let justified_checkpoint : Checkpoint := { epoch := anchor_epoch, root := anchor_root }
  let finalized_checkpoint : Checkpoint := { epoch := anchor_epoch, root := anchor_root }
  let genesis_time_ms := seconds_to_milliseconds anchor_state.genesis_time
  return {
    time_ms := compute_time_at_slot_ms genesis_time_ms anchor_state.slot
    genesis_time_ms
    justified_checkpoint
    finalized_checkpoint
    unrealized_justified_checkpoint := justified_checkpoint
    unrealized_finalized_checkpoint := finalized_checkpoint
    proposer_boost_root := zeroBytes 32
    equivocating_indices := {}
    blocks := Std.HashMap.ofList [(anchor_root, anchor_block)]
    block_states := Std.HashMap.ofList [(anchor_root, anchor_state)]
    block_timeliness := {}
    checkpoint_states := Std.HashMap.ofList [(justified_checkpoint, anchor_state)]
    latest_messages := {}
    unrealized_justifications := Std.HashMap.ofList [(anchor_root, justified_checkpoint)]
  }
```

#### `get_time_into_slot_ms`

```lean
def get_time_into_slot_ms
    (store : Store)
    : Uint64 :=
  store.time_ms - compute_time_at_slot_ms store.genesis_time_ms (get_current_slot store)
```

#### `get_slots_since_genesis`

```lean
def get_slots_since_genesis
    (store : Store)
    : Slot :=
  compute_slot_at_time_ms store.genesis_time_ms store.time_ms
```

#### `get_current_slot`

```lean
def get_current_slot
    (store : Store)
    : Slot :=
  get_slots_since_genesis store
```

#### `get_current_store_epoch`

```lean
def get_current_store_epoch
    (store : Store)
    : Epoch :=
  compute_epoch_at_slot (get_current_slot store)
```

#### `compute_slots_since_epoch_start`

```lean
def compute_slots_since_epoch_start
    (slot : Slot)
    : Slot :=
  slot - compute_start_slot_at_epoch (compute_epoch_at_slot slot)
```

#### `get_ancestor`

```lean
partial def get_ancestor
    (store : Store)
    (node : ForkChoiceNode)
    (slot : Slot)
    : Result ForkChoiceNode := do
  let block <- store.blocks.get? node.root
  if block.slot > slot then
    let parent : ForkChoiceNode := { root := block.parent_root }
    get_ancestor store parent slot
  else
    return node
```

#### `is_ancestor`

```lean
def is_ancestor
    (store : Store)
    (node : ForkChoiceNode)
    (ancestor : ForkChoiceNode)
    : Result Bool := do
  let ancestor_block <- store.blocks.get? ancestor.root
  return (<- get_ancestor store node ancestor_block.slot) == ancestor
```

#### `calculate_committee_fraction`

```lean
def calculate_committee_fraction
    (state : BeaconState)
    (committee_percent : Uint64)
    : Result Gwei := do
  let mut unslashed_and_active_indices : Std.HashSet ValidatorIndex := {}
  for index in get_active_validator_indices state (get_current_epoch state) do
    if !(<- state.validators[index]?).slashed then
      unslashed_and_active_indices := unslashed_and_active_indices.insert index
  let total_balance <- get_total_balance state unslashed_and_active_indices
  let committee_weight := total_balance / SLOTS_PER_EPOCH
  return committee_weight * committee_percent / 100
```

#### `get_checkpoint_block`

```lean
def get_checkpoint_block
    (store : Store)
    (root : Root)
    (epoch : Epoch)
    : Result Root := do
  let epoch_first_slot := compute_start_slot_at_epoch epoch
  let node : ForkChoiceNode := { root }
  return (<- get_ancestor store node epoch_first_slot).root
```

#### `get_supported_node`

```lean
def get_supported_node
    (store : Store)
    (message : LatestMessage)
    : ForkChoiceNode :=
  { root := message.root }
```

#### `get_attestation_score`

```lean
def get_attestation_score
    (store : Store)
    (node : ForkChoiceNode)
    (state : BeaconState)
    : Result Gwei := do
  let unslashed_and_active_indices <-
    (get_active_validator_indices state (get_current_epoch state)).filterM fun index => do
      return !(<- state.validators[index]?).slashed
  let mut score := 0
  for index in unslashed_and_active_indices do
    if let some message := store.latest_messages.get? index then
      if !store.equivocating_indices.contains index then
        if (<- is_ancestor store (get_supported_node store message) node) then
          score := score + (<- state.validators[index]?).effective_balance
  return score
```

#### `compute_proposer_score`

```lean
def compute_proposer_score
    (state : BeaconState)
    : Result Gwei :=
  calculate_committee_fraction state PROPOSER_SCORE_BOOST
```

#### `get_proposer_score`

```lean
def get_proposer_score
    (store : Store)
    : Result Gwei := do
  let justified_checkpoint_state <-
    store.checkpoint_states.get? store.justified_checkpoint
  compute_proposer_score justified_checkpoint_state
```

#### `get_weight`

```lean
def get_weight
    (store : Store)
    (node : ForkChoiceNode)
    : Result Gwei := do
  let state <- store.checkpoint_states.get? store.justified_checkpoint
  let attestation_score <- get_attestation_score store node state
  if store.proposer_boost_root == zeroBytes 32 then
    return attestation_score
  let mut proposer_score := 0
  let proposer_boost_node : ForkChoiceNode := { root := store.proposer_boost_root }
  if (<- is_ancestor store proposer_boost_node node) then
    proposer_score <- get_proposer_score store
  return attestation_score + proposer_score
```

#### `get_voting_source`

```lean
def get_voting_source
    (store : Store)
    (block_root : Root)
    : Result Checkpoint := do
  let block <- store.blocks.get? block_root
  let current_epoch := get_current_store_epoch store
  let block_epoch := compute_epoch_at_slot block.slot
  if current_epoch > block_epoch then
    return (<- store.unrealized_justifications.get? block_root)
  else
    let head_state <- store.block_states.get? block_root
    return head_state.current_justified_checkpoint
```

#### `get_node_children`

```lean
def get_node_children
    (store : Store)
    (node : ForkChoiceNode)
    : Array ForkChoiceNode :=
  let children := store.blocks.toArray.filter fun (_, block) =>
    block.parent_root == node.root
  children.map fun (root, _) => ({ root } : ForkChoiceNode)
```

#### `filter_node_tree`

```lean
partial def filter_node_tree
    (store : Store)
    (node : ForkChoiceNode)
    : Result (Array ForkChoiceNode) := do
  let children := get_node_children store node
  if children.size > 0 then
    let mut viable_nodes := #[]
    for child in children do
      viable_nodes := viable_nodes ++ (<- filter_node_tree store child)
    if viable_nodes.size > 0 then
      return viable_nodes.push node
    return #[]
  let current_epoch := get_current_store_epoch store
  let voting_source <- get_voting_source store node.root
  let correct_justified := store.justified_checkpoint.epoch == GENESIS_EPOCH
    || voting_source.epoch == store.justified_checkpoint.epoch
    || voting_source.epoch + 2 >= current_epoch
  let finalized_checkpoint_block <-
    get_checkpoint_block store node.root store.finalized_checkpoint.epoch
  let correct_finalized := store.finalized_checkpoint.epoch == GENESIS_EPOCH
    || store.finalized_checkpoint.root == finalized_checkpoint_block
  if correct_justified && correct_finalized then
    return #[node]
  return #[]
```

#### `get_filtered_node_tree`

```lean
def get_filtered_node_tree
    (store : Store)
    : Result (Array ForkChoiceNode) :=
  let base : ForkChoiceNode := { root := store.justified_checkpoint.root }
  filter_node_tree store base
```

#### `get_head`

```lean
def get_head
    (store : Store)
    : Result ForkChoiceNode := do
  let nodes <- get_filtered_node_tree store
  let mut head : ForkChoiceNode := { root := store.justified_checkpoint.root }
  while true do
    let children := (get_node_children store head).filter fun child =>
      nodes.contains child
    if children.size == 0 then
      return head
    let mut best <- children[0]?
    let mut best_weight <- get_weight store best
    for child in children do
      let weight <- get_weight store child
      if weight > best_weight
          || (weight == best_weight && child.root.toList > best.root.toList) then
        best := child
        best_weight := weight
    head := best
  unreachable!
```

#### `update_checkpoints`

```lean
def update_checkpoints
    (store : Store)
    (justified_checkpoint : Checkpoint)
    (finalized_checkpoint : Checkpoint)
    : Store := Id.run do
  let mut store := store
  if justified_checkpoint.epoch > store.justified_checkpoint.epoch then
    store := { store with justified_checkpoint }
  if finalized_checkpoint.epoch > store.finalized_checkpoint.epoch then
    store := { store with finalized_checkpoint }
  return store
```

#### `update_unrealized_checkpoints`

```lean
def update_unrealized_checkpoints
    (store : Store)
    (unrealized_justified_checkpoint : Checkpoint)
    (unrealized_finalized_checkpoint : Checkpoint)
    : Store := Id.run do
  let mut store := store
  if unrealized_justified_checkpoint.epoch
      > store.unrealized_justified_checkpoint.epoch then
    store := { store with unrealized_justified_checkpoint }
  if unrealized_finalized_checkpoint.epoch
      > store.unrealized_finalized_checkpoint.epoch then
    store := { store with unrealized_finalized_checkpoint }
  return store
```

#### `get_latest_message_epoch`

```lean
def get_latest_message_epoch
    (latest_message : LatestMessage)
    : Epoch :=
  latest_message.epoch
```

#### `seconds_to_milliseconds`

```lean
def seconds_to_milliseconds
    (seconds : Uint64)
    : Uint64 :=
  if seconds > UINT64_MAX / 1000 then UINT64_MAX else seconds * 1000
```

#### `milliseconds_to_seconds`

```lean
def milliseconds_to_seconds
    (milliseconds : Uint64)
    : Uint64 :=
  milliseconds / 1000
```

#### `get_slot_component_duration_ms`

```lean
def get_slot_component_duration_ms
    (basis_points : Uint64)
    : Uint64 :=
  basis_points * SLOT_DURATION_MS / BASIS_POINTS
```

#### `get_attestation_due_ms`

```lean
def get_attestation_due_ms
    : Uint64 :=
  get_slot_component_duration_ms ATTESTATION_DUE_BPS
```

#### `get_proposer_reorg_cutoff_ms`

```lean
def get_proposer_reorg_cutoff_ms
    : Uint64 :=
  get_slot_component_duration_ms PROPOSER_REORG_CUTOFF_BPS
```

#### `get_aggregate_due_ms`

```lean
def get_aggregate_due_ms
    : Uint64 :=
  get_slot_component_duration_ms AGGREGATE_DUE_BPS
```

#### Proposer head and reorg helpers

_Implementing these helpers is optional_.

##### `is_head_late`

```lean
def is_head_late
    (store : Store)
    (head_root : Root)
    : Result Bool := do
  return !(<- store.block_timeliness.get? head_root)
```

##### `is_shuffling_stable`

```lean
def is_shuffling_stable
    (slot : Slot)
    : Bool :=
  slot % SLOTS_PER_EPOCH != 0
```

##### `is_ffg_competitive`

```lean
def is_ffg_competitive
    (store : Store)
    (head_root : Root)
    (parent_root : Root)
    : Result Bool := do
  return (<- store.unrealized_justifications.get? head_root)
    == (<- store.unrealized_justifications.get? parent_root)
```

##### `is_finalization_ok`

```lean
def is_finalization_ok
    (store : Store)
    (slot : Slot)
    : Bool :=
  let epochs_since_finalization :=
    compute_epoch_at_slot slot - store.finalized_checkpoint.epoch
  epochs_since_finalization <= REORG_MAX_EPOCHS_SINCE_FINALIZATION
```

##### `is_proposing_on_time`

```lean
def is_proposing_on_time
    (store : Store)
    : Bool :=
  get_time_into_slot_ms store <= get_proposer_reorg_cutoff_ms
```

##### `is_head_weak`

*Note*: The function `is_head_weak` counts weight also from equivocating
validators from the committees of the head slot. This ensures that the counted
weight and the output of `is_head_weak` are monotonic: more attestations can
only increase the weight and change the output from `True` to `False`, not
vice-versa.

```lean
def is_head_weak
    (store : Store)
    (head_root : Root)
    : Result Bool := do
  let justified_state <- store.checkpoint_states.get? store.justified_checkpoint
  let reorg_threshold <-
    calculate_committee_fraction justified_state REORG_HEAD_WEIGHT_THRESHOLD
  let head_state <- store.block_states.get? head_root
  let head_block <- store.blocks.get? head_root
  let epoch := compute_epoch_at_slot head_block.slot
  let head_node : ForkChoiceNode := { root := head_root }
  let mut head_weight <- get_attestation_score store head_node justified_state
  for index in [0:get_committee_count_per_slot head_state epoch] do
    let committee <- get_beacon_committee head_state head_block.slot index
    for validator_index in committee do
      if store.equivocating_indices.contains validator_index then
        let validator <- justified_state.validators[validator_index]?
        head_weight := head_weight + validator.effective_balance
  return head_weight < reorg_threshold
```

##### `is_parent_strong`

```lean
def is_parent_strong
    (store : Store)
    (root : Root)
    : Result Bool := do
  let justified_state <- store.checkpoint_states.get? store.justified_checkpoint
  let parent_threshold <-
    calculate_committee_fraction justified_state REORG_PARENT_WEIGHT_THRESHOLD
  let parent_root := (<- store.blocks.get? root).parent_root
  let parent_node : ForkChoiceNode := { root := parent_root }
  let parent_weight <- get_attestation_score store parent_node justified_state
  return parent_weight > parent_threshold
```

##### `is_proposer_equivocation`

```lean
def is_proposer_equivocation
    (store : Store)
    (root : Root)
    : Result Bool := do
  let block <- store.blocks.get? root
  let proposer_index := block.proposer_index
  let slot := block.slot
  let matching_roots := (store.blocks.toArray.filter fun (_, block) =>
    block.proposer_index == proposer_index && block.slot == slot).map Prod.fst
  return matching_roots.size > 1
```

##### `get_proposer_head`

```lean
def get_proposer_head
    (store : Store)
    (head_node : ForkChoiceNode)
    (slot : Slot)
    : Result ForkChoiceNode := do
  let head_block <- store.blocks.get? head_node.root
  let parent_root := head_block.parent_root
  let parent_block <- store.blocks.get? parent_root
  let parent_node : ForkChoiceNode := { root := parent_root }
  let head_late <- is_head_late store head_node.root
  let shuffling_stable := is_shuffling_stable slot
  let ffg_competitive <- is_ffg_competitive store head_node.root parent_root
  let finalization_ok := is_finalization_ok store slot
  let proposing_on_time := is_proposing_on_time store
  let parent_slot_ok := parent_block.slot + 1 == head_block.slot
  let current_time_ok := head_block.slot + 1 == slot
  let single_slot_reorg := parent_slot_ok && current_time_ok
  require (store.proposer_boost_root != head_node.root)
  let head_weak <- is_head_weak store head_node.root
  let parent_strong <- is_parent_strong store head_node.root
  let proposer_equivocation <- is_proposer_equivocation store head_node.root
  if #[
    head_late,
    shuffling_stable,
    ffg_competitive,
    finalization_ok,
    proposing_on_time,
    single_slot_reorg,
    head_weak,
    parent_strong
  ].all id then
    return parent_node
  else if #[head_weak, current_time_ok, proposer_equivocation].all id then
    return parent_node
  else
    return head_node
```

*Note*: The ordering of conditions is a suggestion only. Implementations are
free to optimize by re-ordering the conditions from least to most expensive and
by returning early if any of the early conditions are `False`.

#### Pull-up tip helpers

##### `compute_pulled_up_tip`

```lean
def compute_pulled_up_tip
    (store : Store)
    (block_root : Root)
    : Result Store := do
  let state <- store.block_states.get? block_root
  let state <- process_justification_and_finalization state
  let mut store := { store with
    unrealized_justifications :=
      store.unrealized_justifications.insert block_root state.current_justified_checkpoint
  }
  store := update_unrealized_checkpoints
    store state.current_justified_checkpoint state.finalized_checkpoint
  let block_epoch := compute_epoch_at_slot (<- store.blocks.get? block_root).slot
  let current_epoch := get_current_store_epoch store
  if block_epoch < current_epoch then
    store := update_checkpoints
      store state.current_justified_checkpoint state.finalized_checkpoint
  return store
```

#### `on_tick` helpers

##### `on_tick_per_slot`

```lean
def on_tick_per_slot
    (store : Store)
    (time_ms : Uint64)
    : Store := Id.run do
  let previous_slot := get_current_slot store
  let mut store := { store with time_ms }
  let current_slot := get_current_slot store
  if current_slot > previous_slot then
    store := { store with proposer_boost_root := zeroBytes 32 }
  if current_slot > previous_slot
      && compute_slots_since_epoch_start current_slot == 0 then
    store := update_checkpoints
      store store.unrealized_justified_checkpoint store.unrealized_finalized_checkpoint
  return store
```

#### `on_attestation` helpers

##### `validate_target_epoch_against_current_time`

```lean
def validate_target_epoch_against_current_time
    (store : Store)
    (attestation : Attestation)
    : Result Unit := do
  let target := attestation.data.target
  let current_epoch := get_current_store_epoch store
  let previous_epoch := saturating_sub current_epoch 1
  require (#[current_epoch, previous_epoch].contains target.epoch)
```

##### `validate_on_attestation`

```lean
def validate_on_attestation
    (store : Store)
    (attestation : Attestation)
    (is_from_block : Bool)
    : Result Unit := do
  let target := attestation.data.target
  if !is_from_block then
    validate_target_epoch_against_current_time store attestation
  require (target.epoch == compute_epoch_at_slot attestation.data.slot)
  require (store.blocks.contains target.root)
  require (store.blocks.contains attestation.data.beacon_block_root)
  let block <- store.blocks.get? attestation.data.beacon_block_root
  require (block.slot <= attestation.data.slot)
  let checkpoint_block <-
    get_checkpoint_block store attestation.data.beacon_block_root target.epoch
  require (target.root == checkpoint_block)
  require (get_current_slot store >= attestation.data.slot + 1)
```

##### `store_target_checkpoint_state`

```lean
def store_target_checkpoint_state
    (store : Store)
    (target : Checkpoint)
    : Result Store := do
  if !store.checkpoint_states.contains target then
    let mut base_state <- store.block_states.get? target.root
    if base_state.slot < compute_start_slot_at_epoch target.epoch then
      base_state <- process_slots base_state (compute_start_slot_at_epoch target.epoch)
    let checkpoint_states := store.checkpoint_states.insert target base_state
    return { store with checkpoint_states }
  return store
```

##### `update_latest_messages`

```lean
def update_latest_messages
    (store : Store)
    (attesting_indices : Array ValidatorIndex)
    (attestation : Attestation)
    : Store := Id.run do
  let target := attestation.data.target
  let beacon_block_root := attestation.data.beacon_block_root
  let non_equivocating_attesting_indices := attesting_indices.filter fun index =>
    !store.equivocating_indices.contains index
  let mut store := store
  for i in non_equivocating_attesting_indices do
    let is_newer : Bool := match store.latest_messages.get? i with
      | some latest_message => target.epoch > latest_message.epoch
      | none => true
    if is_newer then
      let latest_message : LatestMessage := {
        epoch := target.epoch
        root := beacon_block_root
      }
      let latest_messages := store.latest_messages.insert i latest_message
      store := { store with latest_messages }
  return store
```

#### `on_block` helpers

##### `record_block_timeliness`

```lean
def record_block_timeliness
    (store : Store)
    (root : Root)
    : Result Store := do
  let block <- store.blocks.get? root
  let time_into_slot_ms := get_time_into_slot_ms store
  let attestation_threshold_ms := get_attestation_due_ms
  let is_before_attesting_interval := time_into_slot_ms < attestation_threshold_ms
  let is_timely := get_current_slot store == block.slot && is_before_attesting_interval
  return { store with block_timeliness := store.block_timeliness.insert root is_timely }
```

##### `compute_shuffling_lookahead_start_slot`

```lean
def compute_shuffling_lookahead_start_slot
    (epoch : Epoch)
    : Slot :=
  let lookahead_epoch := saturating_sub epoch MIN_SEED_LOOKAHEAD
  compute_start_slot_at_epoch lookahead_epoch
```

##### `compute_shuffling_dependent_slot`

```lean
def compute_shuffling_dependent_slot
    (epoch : Epoch)
    : Slot :=
  let lookahead_start_slot := compute_shuffling_lookahead_start_slot epoch
  saturating_sub lookahead_start_slot 1
```

##### `get_shuffling_dependent_root`

```lean
def get_shuffling_dependent_root
    (store : Store)
    (root : Root)
    (epoch : Epoch)
    : Result Root := do
  let node : ForkChoiceNode := { root }
  let dependent_slot := compute_shuffling_dependent_slot epoch
  return (<- get_ancestor store node dependent_slot).root
```

##### `update_proposer_boost_root`

```lean
def update_proposer_boost_root
    (store : Store)
    (head : Root)
    (root : Root)
    : Result Store := do
  let is_first_block := store.proposer_boost_root == zeroBytes 32
  let is_timely <- store.block_timeliness.get? root
  let epoch := get_current_store_epoch store
  let head_dependent_root <- get_shuffling_dependent_root store head epoch
  let block_dependent_root <- get_shuffling_dependent_root store root epoch
  let is_same_dependent_root := head_dependent_root == block_dependent_root
  if is_timely && is_first_block && is_same_dependent_root then
    return { store with proposer_boost_root := root }
  return store
```

### Handlers

#### `on_tick`

```lean
def on_tick
    (store : Store)
    (time_ms : Uint64)
    : Store := Id.run do
  let tick_slot := compute_slot_at_time_ms store.genesis_time_ms time_ms
  let mut store := store
  while get_current_slot store < tick_slot do
    let next_slot := get_current_slot store + 1
    let next_slot_time_ms := compute_time_at_slot_ms store.genesis_time_ms next_slot
    store := on_tick_per_slot store next_slot_time_ms
  return on_tick_per_slot store time_ms
```

#### `on_block`

```lean
def on_block
    (store : Store)
    (signed_block : SignedBeaconBlock)
    : Result Store := do
  let block := signed_block.message
  let block_root <- hash_tree_root block
  if store.blocks.contains block_root then
    return store
  require (store.block_states.contains block.parent_root)
  let pre_state <- store.block_states.get? block.parent_root
  require (get_current_slot store >= block.slot)
  let finalized_slot := compute_start_slot_at_epoch store.finalized_checkpoint.epoch
  require (block.slot > finalized_slot)
  let finalized_checkpoint_block <-
    get_checkpoint_block store block.parent_root store.finalized_checkpoint.epoch
  require (store.finalized_checkpoint.root == finalized_checkpoint_block)
  let state <- state_transition pre_state signed_block (validate_result := true)
  let head <- get_head store
  let mut store := { store with
    blocks := store.blocks.insert block_root block
    block_states := store.block_states.insert block_root state
  }
  store <- record_block_timeliness store block_root
  store <- update_proposer_boost_root store head.root block_root
  store := update_checkpoints
    store state.current_justified_checkpoint state.finalized_checkpoint
  compute_pulled_up_tip store block_root
```

#### `on_attestation`

```lean
def on_attestation
    (store : Store)
    (attestation : Attestation)
    (is_from_block : Bool := false)
    : Result Store := do
  validate_on_attestation store attestation is_from_block
  let store <- store_target_checkpoint_state store attestation.data.target
  let target_state <- store.checkpoint_states.get? attestation.data.target
  let indexed_attestation <- get_indexed_attestation target_state attestation
  require (<- is_valid_indexed_attestation target_state indexed_attestation)
  return update_latest_messages store indexed_attestation.attesting_indices attestation
```

#### `on_attester_slashing`

*Note*: `on_attester_slashing` should be called while syncing and a client MUST
maintain the equivocation set of `AttesterSlashing`s from at least the latest
finalized checkpoint.

```lean
def on_attester_slashing
    (store : Store)
    (attester_slashing : AttesterSlashing)
    : Result Store := do
  let attestation_1 := attester_slashing.attestation_1
  let attestation_2 := attester_slashing.attestation_2
  require (is_slashable_attestation_data attestation_1.data attestation_2.data)
  let state <- store.block_states.get? store.justified_checkpoint.root
  require (<- is_valid_indexed_attestation state attestation_1)
  require (<- is_valid_indexed_attestation state attestation_2)
  let indices := (Std.HashSet.ofList attestation_1.attesting_indices.toList).filter
    fun index => attestation_2.attesting_indices.contains index
  let mut store := store
  for index in indices do
    let equivocating_indices := store.equivocating_indices.insert index
    store := { store with equivocating_indices }
  return store
```

def initialize_proposer_lookahead(spec, state):
    current_epoch = spec.get_current_epoch(state)
    lookahead = []
    for i in range(int(spec.MIN_SEED_LOOKAHEAD) + 1):
        lookahead.extend(spec.get_beacon_proposer_indices(state, current_epoch + spec.Epoch(i)))
    return lookahead

def initialize_ptc_window(spec, state):
    empty_previous_epoch = [
        spec.PTC(data=[spec.ValidatorIndex(0) for _ in range(int(spec.PTC_SIZE))])
        for _ in range(int(spec.SLOTS_PER_EPOCH))
    ]
    ptcs = []
    current_epoch = spec.get_current_epoch(state)
    for e in range(int(spec.MIN_SEED_LOOKAHEAD) + 1):
        epoch = current_epoch + spec.Epoch(e)
        start_slot = spec.compute_start_slot_at_epoch(epoch)
        ptcs += [
            spec.compute_ptc(state, start_slot + spec.Slot(i))
            for i in range(int(spec.SLOTS_PER_EPOCH))
        ]
    return spec.PTCWindow(data=empty_previous_epoch + ptcs)

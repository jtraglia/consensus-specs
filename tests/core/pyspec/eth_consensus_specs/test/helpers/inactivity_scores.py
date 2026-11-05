from random import Random

from eth_consensus_specs.test.helpers.registry import set_inactivity_scores


def randomize_inactivity_scores(spec, state, minimum=0, maximum=50000, rng=None):
    if rng is None:
        rng = Random(4242)
    set_inactivity_scores(
        spec,
        state,
        spec.InactivityScores(
            data=[rng.randint(minimum, maximum) for _ in range(len(state.validators))]
        ),
    )


def zero_inactivity_scores(spec, state, rng=None):
    set_inactivity_scores(spec, state, spec.InactivityScores(data=[0] * len(state.validators)))

from eth_consensus_specs.test.helpers.forks import is_post_pq
from eth_consensus_specs.test.helpers.keys import get_vrf_data, xmss_builder_pubkeys, xmss_pubkeys


def get_validators(spec, state):
    """
    The validator registry, which moves to ``state.pq_validators`` from PQ
    onwards.
    """
    return state.pq_validators if is_post_pq(spec) else state.validators


def get_builders(spec, state):
    """
    The builder registry, which moves to ``state.pq_builders`` from PQ onwards.
    """
    return state.pq_builders if is_post_pq(spec) else state.builders


class PQBalances:
    """
    A list-like view of the balances that ``state.pq_validators`` holds, indexed
    by validator index.
    """

    def __init__(self, spec, state):
        self.spec = spec
        self.state = state

    def __getitem__(self, index):
        if isinstance(index, slice):
            return list(self)[index]
        return self.spec.get_validator(self.state, index).balance

    def __setitem__(self, index, balance):
        self.spec.get_validator(self.state, index).balance = balance

    def __len__(self):
        return len(self.state.pq_validators)

    def __iter__(self):
        return iter([validator.balance for validator in self.state.pq_validators])

    def copy(self):
        return list(self)


def get_balances(spec, state):
    """
    The validator balances, which move into the records of
    ``state.pq_validators`` from PQ onwards.
    """
    return PQBalances(spec, state) if is_post_pq(spec) else state.balances


def set_balances(spec, state, balances):
    """
    Replace the validator balances with ``balances``.
    """
    if is_post_pq(spec):
        for validator, balance in zip(state.pq_validators, balances, strict=True):
            validator.balance = balance
    else:
        state.balances = spec.Balances(data=balances)


def to_pq_validator(spec, validator, index, balance=None):
    """
    The PQ record of ``validator`` at ``index``, with the placeholder XMSS public
    key and VRF data of that index. The balance defaults to the effective
    balance.
    """
    return spec.PQValidator(
        pubkey=xmss_pubkeys[index],
        vrf_data=get_vrf_data(index),
        withdrawal_credentials=validator.withdrawal_credentials,
        index=index,
        balance=validator.effective_balance if balance is None else balance,
        effective_balance=validator.effective_balance,
        activation_eligibility_epoch=validator.activation_eligibility_epoch,
        activation_epoch=validator.activation_epoch,
        exit_epoch=validator.exit_epoch,
        withdrawable_epoch=validator.withdrawable_epoch,
        slashed=validator.slashed,
    )


def to_pq_builder(spec, builder, index):
    """
    The PQ record of ``builder`` at ``index``, with the placeholder XMSS public
    key of that index.
    """
    return spec.PQBuilder(
        index=index,
        pubkey=xmss_builder_pubkeys[index],
        version=builder.version,
        execution_address=builder.execution_address,
        balance=builder.balance,
        deposit_epoch=builder.deposit_epoch,
        withdrawable_epoch=builder.withdrawable_epoch,
    )


def append_validator(spec, state, validator, balance):
    """
    Append ``validator`` with ``balance`` to the registry, as a PQ record from PQ
    onwards.
    """
    if is_post_pq(spec):
        index = state.next_validator_index
        state.pq_validators.append(to_pq_validator(spec, validator, index, balance))
        state.next_validator_index = index + 1
    else:
        state.validators.append(validator)
        state.balances.append(balance)


def append_builder(spec, state, builder):
    """
    Append ``builder`` to the registry, as a PQ record from PQ onwards.
    """
    if is_post_pq(spec):
        index = max([builder.index + 1 for builder in state.pq_builders], default=0)
        state.pq_builders.append(to_pq_builder(spec, builder, index))
    else:
        state.builders.append(builder)


def set_validators(spec, state, validators):
    """
    Replace the registry with ``validators``, as PQ records from PQ onwards.
    """
    if is_post_pq(spec):
        state.pq_validators = spec.PQValidators(
            data=[to_pq_validator(spec, validator, i) for i, validator in enumerate(validators)]
        )
        state.next_validator_index = len(validators)
    else:
        state.validators = spec.Validators(data=validators)


def set_builders(spec, state, builders):
    """
    Replace the registry with ``builders``, as PQ records from PQ onwards.
    """
    if is_post_pq(spec):
        state.pq_builders = spec.PQBuilders(
            data=[to_pq_builder(spec, builder, i) for i, builder in enumerate(builders)]
        )
    else:
        state.builders = spec.Builders(data=builders)

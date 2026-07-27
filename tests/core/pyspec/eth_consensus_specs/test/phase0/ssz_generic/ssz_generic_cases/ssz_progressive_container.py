from collections.abc import Sequence
from random import Random

from eth_consensus_specs.debug.random_value import RandomizationMode
from eth_consensus_specs.test.exceptions import SkippedTest
from eth_consensus_specs.utils.ssz.ssz_impl import deserialize, serialize
from eth_consensus_specs.utils.ssz.ssz_typing import (
    Byte,
    ProgressiveBitlist,
    ProgressiveContainer,
    ProgressiveList,
    SSZType,
    Uint16,
    Uint64,
)

from .ssz_container import (
    container_case_fn,
    invalid_container_cases,
    SmallTestStruct,
    valid_container_cases,
    VarTestStruct,
)
from .ssz_test_case import invalid_test_case, list_of

Uint16List123 = list_of(Uint16, 123)


class ProgressiveSingleFieldContainerTestStruct(ProgressiveContainer):
    ACTIVE_FIELDS = (1,)

    A: Byte


ProgressiveSingleFieldContainerTestStructList10 = list_of(
    ProgressiveSingleFieldContainerTestStruct, 10
)


class ProgressiveSingleListContainerTestStruct(ProgressiveContainer):
    ACTIVE_FIELDS = (
        0,
        0,
        0,
        0,
        1,
    )

    C: ProgressiveBitlist


class ProgressiveVarTestStruct(ProgressiveContainer):
    ACTIVE_FIELDS = (
        1,
        0,
        1,
        0,
        1,
    )

    A: Byte
    B: Uint16List123
    C: ProgressiveBitlist


class ProgressiveComplexTestStruct(ProgressiveContainer):
    ACTIVE_FIELDS = (
        1,
        0,
        1,
        0,
        1,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        1,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
        1,
    )

    A: Byte
    B: Uint16List123
    C: ProgressiveBitlist
    D: ProgressiveList[Uint64]
    E: ProgressiveList[SmallTestStruct]
    F: ProgressiveList[ProgressiveList[VarTestStruct]]
    G: ProgressiveSingleFieldContainerTestStructList10
    H: ProgressiveList[ProgressiveVarTestStruct]


class ModifiedTestStruct1(ProgressiveContainer):
    ACTIVE_FIELDS = (
        1,
        1,
    )

    A: Byte
    X: Byte


class ModifiedTestStruct2(ProgressiveContainer):
    ACTIVE_FIELDS = (
        1,
        0,
        1,
    )

    A: Byte
    B: Uint16List123


class ModifiedTestStruct3(ProgressiveContainer):
    ACTIVE_FIELDS = (
        1,
        1,
        1,
    )

    A: Byte
    X: Byte
    B: Uint16List123


class ModifiedTestStruct4(ProgressiveContainer):
    ACTIVE_FIELDS = (
        0,
        0,
        1,
        0,
        1,
    )

    B: Uint16List123
    C: ProgressiveBitlist


class ModifiedTestStruct5(ProgressiveContainer):
    ACTIVE_FIELDS = (
        1,
        0,
        0,
        0,
        1,
    )

    A: Byte
    C: ProgressiveBitlist


class ModifiedTestStruct6(ProgressiveContainer):
    ACTIVE_FIELDS = (
        1,
        1,
        1,
        0,
        1,
        0,
        0,
        0,
        1,
    )

    A: Byte
    X: Byte
    B: Uint16List123
    C: ProgressiveBitlist
    D: ProgressiveList[Uint64]


class ModifiedTestStruct7(ProgressiveContainer):
    ACTIVE_FIELDS = (
        1,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        1,
    )

    A: Byte
    B: Uint16List123
    D: ProgressiveList[Uint64]


class ModifiedTestStruct8(ProgressiveContainer):
    ACTIVE_FIELDS = (
        1,
        1,
        1,
        0,
        1,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        1,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
        1,
    )

    A: Byte
    X: Byte
    B: Uint16List123
    C: ProgressiveBitlist
    D: ProgressiveList[Uint64]
    E: ProgressiveList[SmallTestStruct]
    F: ProgressiveList[ProgressiveList[VarTestStruct]]
    G: ProgressiveSingleFieldContainerTestStructList10
    H: ProgressiveList[ProgressiveVarTestStruct]


class ModifiedTestStruct9(ProgressiveContainer):
    ACTIVE_FIELDS = (
        1,
        0,
        1,
        0,
        1,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
        1,
    )

    A: Byte
    B: Uint16List123
    C: ProgressiveBitlist
    D: ProgressiveList[Uint64]
    F: ProgressiveList[ProgressiveList[VarTestStruct]]
    G: ProgressiveSingleFieldContainerTestStructList10
    H: ProgressiveList[ProgressiveVarTestStruct]


PRESET_PROGRESSIVE_CONTAINERS: dict[str, tuple[type[SSZType], Sequence[int]]] = {
    "ProgressiveSingleFieldContainerTestStruct": (ProgressiveSingleFieldContainerTestStruct, []),
    "ProgressiveSingleListContainerTestStruct": (ProgressiveSingleListContainerTestStruct, [0]),
    "ProgressiveVarTestStruct": (ProgressiveVarTestStruct, [1, 5]),
    "ProgressiveComplexTestStruct": (ProgressiveComplexTestStruct, [1, 5, 9, 13, 17, 21, 25]),
}


MODIFIED_PROGRESSIVE_CONTAINERS: Sequence[type[SSZType]] = [
    ModifiedTestStruct1,
    ModifiedTestStruct2,
    ModifiedTestStruct3,
    ModifiedTestStruct4,
    ModifiedTestStruct5,
    ModifiedTestStruct6,
    ModifiedTestStruct7,
    ModifiedTestStruct8,
    ModifiedTestStruct9,
]


def valid_cases():
    rng = Random(1234)
    for name, (typ, offsets) in PRESET_PROGRESSIVE_CONTAINERS.items():
        yield from valid_container_cases(rng, name, typ, offsets)


def invalid_cases():
    rng = Random(1234)
    for name, (typ, offsets) in PRESET_PROGRESSIVE_CONTAINERS.items():
        yield from invalid_container_cases(rng, name, typ, offsets)

        for mode in [
            RandomizationMode.mode_random,
            RandomizationMode.mode_nil_count,
            RandomizationMode.mode_one_count,
            RandomizationMode.mode_max_count,
        ]:
            for i, modded_typ in enumerate(MODIFIED_PROGRESSIVE_CONTAINERS):

                def the_test(rng, mode=mode, typ=typ, modded_typ=modded_typ):
                    serialized = serialize(container_case_fn(rng, mode, modded_typ))
                    try:
                        _ = deserialize(typ, serialized)
                    except Exception:
                        return serialized
                    raise SkippedTest(
                        "The serialized data still parses fine, it's not invalid data"
                    )

                yield (
                    f"{name}_{mode.to_name()}_modded_{i}",
                    invalid_test_case(typ, the_test, rng),
                )

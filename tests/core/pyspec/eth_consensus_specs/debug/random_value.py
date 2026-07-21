from enum import Enum
from random import Random

from ssz.bitfields import BaseBitlist, BaseBitvector
from ssz.boolean import Boolean
from ssz.byte_arrays import BaseByteList, BaseBytes
from ssz.collections import List, Vector
from ssz.container import Container
from ssz.ssz_base import SSZType
from ssz.uint import BaseUint

# in bytes
UINT_BYTE_SIZES = (1, 2, 4, 8, 16, 32)

random_mode_names = ("random", "zero", "max", "nil", "one", "lengthy")


class RandomizationMode(Enum):
    # random content / length
    mode_random = 0
    # Zero-value
    mode_zero = 1
    # Maximum value, limited to count 1 however
    mode_max = 2
    # Return 0 values, i.e. empty
    mode_nil_count = 3
    # Return 1 value, random content
    mode_one_count = 4
    # Return max amount of values, random content
    mode_max_count = 5

    def to_name(self):
        return random_mode_names[self.value]

    def is_changing(self):
        return self.value in [0, 4, 5]


def get_random_ssz_object(
    rng: Random,
    typ: type[SSZType],
    max_bytes_length: int,
    max_list_length: int,
    mode: RandomizationMode,
    chaos: bool,
) -> SSZType:
    """
    Create an object for a given type, filled with random data.
    :param rng: The random number generator to use.
    :param typ: The type to instantiate
    :param max_bytes_length: the max. length for a random bytes array
    :param max_list_length: the max. length for a random list
    :param mode: how to randomize
    :param chaos: if true, the randomization-mode will be randomly changed
    :return: the random object instance, of the given type.
    """
    if chaos:
        mode = rng.choice(list(RandomizationMode))
    if issubclass(typ, BaseByteList):
        limit = int(typ.LIMIT)
        if mode == RandomizationMode.mode_nil_count:
            return typ(data=b"")
        elif mode == RandomizationMode.mode_max_count:
            return typ(data=get_random_bytes_list(rng, min(max_bytes_length, limit)))
        elif mode == RandomizationMode.mode_one_count:
            return typ(data=get_random_bytes_list(rng, min(1, limit)))
        elif mode == RandomizationMode.mode_zero:
            return typ(data=b"\x00" * min(1, limit))
        elif mode == RandomizationMode.mode_max:
            return typ(data=b"\xff" * min(1, limit))
        else:
            return typ(
                data=get_random_bytes_list(rng, rng.randint(0, min(max_bytes_length, limit)))
            )
    if issubclass(typ, BaseBytes):
        # Random byte vectors can be bigger than max bytes size, e.g. custody chunk data.
        # No max-bytes-length limitation here.
        if mode == RandomizationMode.mode_zero:
            return typ(b"\x00" * int(typ.LENGTH))
        elif mode == RandomizationMode.mode_max:
            return typ(b"\xff" * int(typ.LENGTH))
        else:
            return typ(get_random_bytes_list(rng, typ.LENGTH))
    elif issubclass(typ, Boolean | BaseUint):
        # Basic types
        if mode == RandomizationMode.mode_zero:
            return get_min_basic_value(typ)
        elif mode == RandomizationMode.mode_max:
            return get_max_basic_value(typ)
        else:
            return get_random_basic_value(rng, typ)
    elif issubclass(typ, Vector | BaseBitvector):
        elem_type = typ.ELEMENT_TYPE if issubclass(typ, Vector) else Boolean
        length = int(typ.LENGTH)
        return typ(
            data=(
                get_random_ssz_object(
                    rng, elem_type, max_bytes_length, max_list_length, mode, chaos
                )
                for _ in range(length)
            )
        )
    elif issubclass(typ, List | BaseBitlist):
        limit = min(int(typ.LIMIT), max_list_length)
        length = rng.randint(0, limit)
        if mode == RandomizationMode.mode_one_count:
            length = 1
        elif mode == RandomizationMode.mode_max_count:
            length = limit
        elif mode == RandomizationMode.mode_nil_count:
            length = 0

        elem_type = Boolean if issubclass(typ, BaseBitlist) else typ.ELEMENT_TYPE
        max_list_length = 1 << (max_list_length.bit_length() >> 1)
        return typ(
            data=(
                get_random_ssz_object(
                    rng, elem_type, max_bytes_length, max_list_length, mode, chaos
                )
                for _ in range(length)
            )
        )
    elif issubclass(typ, Container):
        # Container
        return typ(
            **{
                field_name: get_random_ssz_object(
                    rng, field.annotation, max_bytes_length, max_list_length, mode, chaos
                )
                for field_name, field in typ.model_fields.items()
            }
        )
    else:
        raise Exception(f"Type not recognized: typ={typ}")


def get_random_bytes_list(rng: Random, length: int) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(length))


def get_random_basic_value(rng: Random, typ) -> SSZType:
    if issubclass(typ, Boolean):
        return typ(rng.choice((True, False)))
    elif issubclass(typ, BaseUint):
        assert typ.get_byte_length() in UINT_BYTE_SIZES
        return typ(rng.randint(0, 256 ** typ.get_byte_length() - 1))
    else:
        raise ValueError(f"Not a basic type: typ={typ}")


def get_min_basic_value(typ) -> SSZType:
    if issubclass(typ, Boolean):
        return typ(False)  # noqa: FBT003
    elif issubclass(typ, BaseUint):
        assert typ.get_byte_length() in UINT_BYTE_SIZES
        return typ(0)
    else:
        raise ValueError(f"Not a basic type: typ={typ}")


def get_max_basic_value(typ) -> SSZType:
    if issubclass(typ, Boolean):
        return typ(True)  # noqa: FBT003
    elif issubclass(typ, BaseUint):
        assert typ.get_byte_length() in UINT_BYTE_SIZES
        return typ(256 ** typ.get_byte_length() - 1)
    else:
        raise ValueError(f"Not a basic type: typ={typ}")

from collections.abc import Callable
from functools import cache
from random import Random

from eth_consensus_specs.debug.encode import encode
from eth_consensus_specs.utils.ssz.ssz_impl import deserialize, hash_tree_root, serialize
from eth_consensus_specs.utils.ssz.ssz_typing import (
    Bitlist,
    Bitvector,
    ByteList,
    ByteVector,
    List,
    SSZType,
    Vector,
)

# A collection states its bound in the class body, so a type parameterized on
# one has to be declared. These build the declaration, for the cases that need
# a bound the surrounding module does not know until it runs.


@cache
def list_of(element_type: type[SSZType], limit: int) -> type[List]:
    return type(f"{element_type.__name__}List{limit}", (List[element_type],), {"LIMIT": limit})


@cache
def vector_of(element_type: type[SSZType], length: int) -> type[Vector]:
    return type(
        f"{element_type.__name__}Vector{length}", (Vector[element_type],), {"LENGTH": length}
    )


@cache
def bitlist_of(limit: int) -> type[Bitlist]:
    return type(f"Bitlist{limit}", (Bitlist,), {"LIMIT": limit})


@cache
def bitvector_of(length: int) -> type[Bitvector]:
    return type(f"Bitvector{length}", (Bitvector,), {"LENGTH": length})


@cache
def bytelist_of(limit: int) -> type[ByteList]:
    return type(f"ByteList{limit}", (ByteList,), {"LIMIT": limit})


@cache
def bytevector_of(length: int) -> type[ByteVector]:
    return type(f"ByteVector{length}", (ByteVector,), {"LENGTH": length})


def safe_lambda(fn: Callable):
    code = fn.__code__
    if code.co_freevars:
        raise ValueError(
            f"Multi-threading requires all variables to be captured: {list(code.co_freevars)} in {code.co_filename}:{code.co_firstlineno}"
        )
    return fn


def capture_seed(rng: Random | None = None):
    return rng.randint(0, 2**32 - 1) if rng is not None else None


def valid_test_case(value_fn: Callable[[], SSZType], rng: Random | None = None):
    seed = capture_seed(rng)

    def case_fn():
        if seed is not None:
            value = safe_lambda(value_fn)(rng=Random(seed))
        else:
            value = safe_lambda(value_fn)()
        serialized = serialize(value)
        assert deserialize(value.__class__, serialized) == value
        yield "value", "data", encode(value)
        yield "serialized", "ssz", serialized
        yield "root", "meta", "0x" + hash_tree_root(value).hex()

    return case_fn


def invalid_test_case(typ: type[SSZType], bytez_fn: Callable[[], bytes], rng: Random | None = None):
    seed = capture_seed(rng)

    def case_fn():
        if seed is not None:
            serialized = safe_lambda(bytez_fn)(rng=Random(seed))
        else:
            serialized = safe_lambda(bytez_fn)()
        try:
            _ = deserialize(typ, serialized)
        except Exception:
            yield "serialized", "ssz", serialized
            return
        code = bytez_fn.__code__
        raise ValueError(
            f"Invalid {typ.__name__} data should not deserialize: {serialized.hex()} in {code.co_filename}:{code.co_firstlineno}"
        )

    return case_fn

from typing import Any

from eth_consensus_specs.debug.random_value import get_field_types
from eth_consensus_specs.utils.ssz.ssz_impl import deserialize, hash_tree_root
from eth_consensus_specs.utils.ssz.ssz_typing import (
    BitList,
    BitVector,
    Boolean,
    Byte,
    ByteList,
    ByteVector,
    CompatibleUnion,
    Container,
    List,
    ProgressiveBitList,
    ProgressiveContainer,
    ProgressiveList,
    Uint,
    Vector,
)


def decode(data: Any, typ):
    if issubclass(typ, Uint | Boolean):
        return typ(data)
    elif issubclass(typ, BitList | ProgressiveBitList | BitVector) or (
        issubclass(typ, ProgressiveList) and issubclass(typ.ELEMENT_TYPE, Byte)
    ):
        return deserialize(typ, bytes.fromhex(data[2:]))
    elif issubclass(typ, List | ProgressiveList | Vector):
        return typ(data=[decode(element, typ.ELEMENT_TYPE) for element in data])
    elif issubclass(typ, ByteVector):
        return typ(bytes.fromhex(data[2:]))
    elif issubclass(typ, ByteList):
        return typ(data=bytes.fromhex(data[2:]))
    elif issubclass(typ, Container | ProgressiveContainer):
        temp = {}
        for field_name, field_type in get_field_types(typ).items():
            temp[field_name] = decode(data[field_name], field_type)
            if field_name + "_hash_tree_root" in data:
                assert (
                    data[field_name + "_hash_tree_root"][2:]
                    == hash_tree_root(temp[field_name]).hex()
                )
        ret = typ(**temp)
        if "hash_tree_root" in data:
            assert data["hash_tree_root"][2:] == hash_tree_root(ret).hex()
        return ret
    elif issubclass(typ, CompatibleUnion):
        selector = int(data["selector"])
        return typ(selector=selector, data=decode(data["data"], typ.OPTIONS[selector]))
    else:
        raise Exception(f"Type not recognized: data={data}, typ={typ}")

from typing import Any

from ssz.bitfields import BaseBitlist, BaseBitvector
from ssz.boolean import Boolean
from ssz.byte_arrays import BaseByteList, BaseBytes
from ssz.collections import List, Vector
from ssz.container import Container
from ssz.uint import BaseUint

from eth_consensus_specs.utils.ssz.ssz_impl import deserialize, hash_tree_root


def decode(data: Any, typ):
    if issubclass(typ, BaseUint | Boolean):
        return typ(data)
    elif issubclass(typ, BaseBitlist | BaseBitvector):
        return deserialize(typ, bytes.fromhex(data[2:]))
    elif issubclass(typ, List | Vector):
        return typ(data=(decode(element, typ.ELEMENT_TYPE) for element in data))
    elif issubclass(typ, BaseBytes):
        return typ(bytes.fromhex(data[2:]))
    elif issubclass(typ, BaseByteList):
        return typ(data=bytes.fromhex(data[2:]))
    elif issubclass(typ, Container):
        temp = {}
        for field_name, field in typ.model_fields.items():
            temp[field_name] = decode(data[field_name], field.annotation)
            if field_name + "_hash_tree_root" in data:
                assert (
                    data[field_name + "_hash_tree_root"][2:]
                    == hash_tree_root(temp[field_name]).hex()
                )
        ret = typ(**temp)
        if "hash_tree_root" in data:
            assert data["hash_tree_root"][2:] == hash_tree_root(ret).hex()
        return ret
    else:
        raise Exception(f"Type not recognized: data={data}, typ={typ}")

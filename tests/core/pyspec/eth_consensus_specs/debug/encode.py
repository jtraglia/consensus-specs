from ssz.bitfields import BaseBitlist, BaseBitvector
from ssz.boolean import Boolean
from ssz.byte_arrays import BaseByteList
from ssz.collections import List, Vector
from ssz.container import Container
from ssz.uint import BaseUint

from eth_consensus_specs.utils.ssz.ssz_impl import hash_tree_root, serialize


def encode(value, include_hash_tree_roots=False):
    if isinstance(value, BaseUint):
        # Larger uints are boxed and the class declares their byte length
        if value.get_byte_length() > 8:
            return str(int(value))
        return int(value)
    elif isinstance(value, Boolean):
        return bool(value)
    elif isinstance(value, BaseBitlist | BaseBitvector):
        return "0x" + serialize(value).hex()
    elif isinstance(value, list | List | Vector):
        return [encode(element, include_hash_tree_roots) for element in value]
    elif isinstance(value, BaseByteList):
        return "0x" + serialize(value).hex()
    elif isinstance(value, bytes):  # bytes and fixed byte arrays
        return "0x" + value.hex()
    elif isinstance(value, Container):
        ret = {}
        for field_name in type(value).model_fields:
            field_value = getattr(value, field_name)
            ret[field_name] = encode(field_value, include_hash_tree_roots)
            if include_hash_tree_roots:
                ret[field_name + "_hash_tree_root"] = "0x" + hash_tree_root(field_value).hex()
        if include_hash_tree_roots:
            ret["hash_tree_root"] = "0x" + hash_tree_root(value).hex()
        return ret
    else:
        raise Exception(f"Type not recognized: value={value}, typ={type(value)}")

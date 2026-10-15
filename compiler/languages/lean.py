import functools
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import NamedTuple

from compiler.languages.base import Declaration, Environment, Foreign, Signature, SszType, Type
from compiler.model import Definition, Kind, References, SpecError

TOOLCHAIN = "leanprover/lean4:v4.34.1"
POOL = ThreadPoolExecutor()
SSZ_REPOSITORY = "https://github.com/ethereum/ssz-specs.git"
SSZ_REVISION = "d4a0d75f36b2f3c1602d58b1fb039c9f2a0e3ab9"
DEFINITION = re.compile(r"(?:partial )?def (\w+)\s")
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
RESULT = "Result "
DEFAULTS = {"none": "None", "true": "True", "false": "False"}
KEYWORDS = frozenset(
    {
        "abbrev",
        "at",
        "by",
        "class",
        "def",
        "deriving",
        "do",
        "else",
        "end",
        "export",
        "for",
        "from",
        "fun",
        "have",
        "if",
        "import",
        "in",
        "instance",
        "let",
        "match",
        "mut",
        "namespace",
        "open",
        "return",
        "section",
        "show",
        "structure",
        "then",
        "try",
        "unless",
        "variable",
        "where",
        "with",
    }
)


class Scalar(NamedTuple):
    lean: str
    reader: str
    writer: str


SCALARS = {
    "bool": Scalar("Bool", "asBool", "ofBool"),
    "uint": Scalar("Nat", "asUint", "ofUint"),
    "byteVector": Scalar("ByteArray", "asBytes", "ofBytes"),
    "byteList": Scalar("ByteArray", "asBytes", "ofBytes"),
    "bitVector": Scalar("Array Bool", "asBits", "ofBits"),
    "bitList": Scalar("Array Bool", "asBits", "ofBits"),
    "progressiveBitList": Scalar("Array Bool", "asBits", "ofBits"),
}
PLAIN = {"bool": "Bool", "int": "Nat", "bytes": "ByteArray", "str": "String"}
SEQUENCES = ("vector", "list", "progressiveList")
CONTAINERS = ("container", "progressiveContainer")

LAKEFILE = f"""\
name = "spec"

[[require]]
name = "ssz"
git = "{SSZ_REPOSITORY}"
rev = "{SSZ_REVISION}"
subDir = "lean"
"""

PRELUDE = """\
import Ssz
import Std.Data.HashMap
import Std.Data.HashSet

set_option linter.unusedVariables false

namespace Spec

abbrev Result (value : Type) := Except String value

instance : MonadLift Option Result where
  monadLift
    | some value => .ok value
    | none => .error "index out of range"

class Merkleizable (value : Type) where
  desc : Ssz.Desc
  toValue : value -> Ssz.Value

def require (condition : Bool) : Result Unit :=
  if condition then .ok () else .error "assertion failed"

def raise {value : Type} (kind : String) (message : String) : Result value :=
  .error s!"{kind}: {message}"

def sha256 (data : ByteArray) : ByteArray :=
  Ssz.Sha256.hash data

def bytes_to_uint64 (data : ByteArray) : Nat :=
  data.data.foldr (fun byte total => total * 256 + byte.toNat) 0

def uint_to_bytes (size : Nat) (value : Nat) : ByteArray :=
  ByteArray.mk ((Array.range size).map fun index => (value >>> (8 * index)).toUInt8)

def hash_tree_root {value : Type} [merkleizable : Merkleizable value] (object : value) :
    Result ByteArray :=
  match Ssz.hashTreeRoot (Merkleizable.desc value) (Merkleizable.toValue object) with
  | .ok root => .ok (ByteArray.mk root)
  | .error reason => .error reason.reason

def zeroBytes (size : Nat) : ByteArray :=
  ByteArray.mk (Array.replicate size 0)

def ofUint (value : Nat) : Ssz.Value :=
  .uint value

def ofBool (value : Bool) : Ssz.Value :=
  .bool value

def ofBytes (value : ByteArray) : Ssz.Value :=
  .bytes value.data

def ofBits (value : Array Bool) : Ssz.Value :=
  .bits value

def ofArray {element : Type} (write : element -> Ssz.Value) (values : Array element) :
    Ssz.Value :=
  .seq (values.toList.map write)

def asUint : Ssz.Value -> Result Nat
  | .uint value => .ok value
  | _ => .error "expected an integer"

def asBool : Ssz.Value -> Result Bool
  | .bool value => .ok value
  | _ => .error "expected a boolean"

def asBytes : Ssz.Value -> Result ByteArray
  | .bytes value => .ok (ByteArray.mk value)
  | _ => .error "expected bytes"

def asBits : Ssz.Value -> Result (Array Bool)
  | .bits value => .ok value
  | _ => .error "expected bits"

def asFields : Ssz.Value -> Result (Array Ssz.Value)
  | .seq values => .ok values.toArray
  | _ => .error "expected a container"

def asArray {element : Type} (read : Ssz.Value -> Result element) :
    Ssz.Value -> Result (Array element)
  | .seq values => List.toArray <$> values.mapM read
  | _ => .error "expected a sequence"

def decodeWith {value : Type} (desc : Ssz.Desc) (read : Ssz.Value -> Result value)
    (data : ByteArray) : Result value :=
  match Ssz.deserialize desc data.data with
  | .ok decoded => read decoded
  | .error reason => .error reason.reason

def encodeWith (desc : Ssz.Desc) (value : Ssz.Value) : Result ByteArray :=
  match Ssz.serialize desc value with
  | .ok data => .ok (ByteArray.mk data)
  | .error reason => .error reason.reason

def readFrames (data : ByteArray) : Result (List ByteArray) := Id.run do
  let mut frames := #[]
  let mut position := 0
  while position < data.size do
    if position + 4 > data.size then
      return .error "truncated frame"
    let start := position + 4
    let stop := start + bytes_to_uint64 (data.extract position start)
    if stop > data.size then
      return .error "truncated frame"
    frames := frames.push (data.extract start stop)
    position := stop
  return .ok frames.toList

def writeFrames (frames : List ByteArray) : ByteArray :=
  frames.foldl (fun data frame => data ++ uint_to_bytes 4 frame.size ++ frame) ByteArray.empty

def reply (status : UInt8) (payload : ByteArray) : ByteArray :=
  ByteArray.mk #[status] ++ payload

instance : Merkleizable Nat where
  desc := .uint 8
  toValue := ofUint

def encodeAs {value : Type} (desc : Ssz.Desc) (write : value -> Ssz.Value) (object : value) :
    Result ByteArray :=
  encodeWith desc (write object)

def decodeBytes (data : ByteArray) : Result ByteArray :=
  .ok data

def encodeBytes (data : ByteArray) : Result ByteArray :=
  .ok data

def decodeArray {value : Type} (decode : ByteArray -> Result value) (data : ByteArray) :
    Result (Array value) := do
  let frames <- readFrames data
  return (<- frames.mapM decode).toArray

def encodeArray {value : Type} (encode : value -> Result ByteArray) (values : Array value) :
    Result ByteArray := do
  return writeFrames (<- values.toList.mapM encode)

def decodeSet {value : Type} [BEq value] [Hashable value] (decode : ByteArray -> Result value)
    (data : ByteArray) : Result (Std.HashSet value) := do
  return Std.HashSet.ofList (<- decodeArray decode data).toList

def encodeSet {value : Type} [BEq value] [Hashable value] (encode : value -> Result ByteArray)
    (values : Std.HashSet value) : Result ByteArray :=
  encodeArray encode values.toArray

def decodeOption {value : Type} (decode : ByteArray -> Result value) (data : ByteArray) :
    Result (Option value) := do
  match <- readFrames data with
  | [] => return none
  | [frame] => return some (<- decode frame)
  | _ => .error "expected at most one value"

def encodeOption {value : Type} (encode : value -> Result ByteArray) :
    Option value -> Result ByteArray
  | none => .ok (writeFrames [])
  | some value => do return writeFrames [<- encode value]

def decodePair {first second : Type} (decodeFirst : ByteArray -> Result first)
    (decodeSecond : ByteArray -> Result second) (data : ByteArray) :
    Result (Prod first second) := do
  match <- readFrames data with
  | [one, two] => return ((<- decodeFirst one), (<- decodeSecond two))
  | _ => .error "expected two values"

def encodePair {first second : Type} (encodeFirst : first -> Result ByteArray)
    (encodeSecond : second -> Result ByteArray) (value : Prod first second) :
    Result ByteArray := do
  return writeFrames [<- encodeFirst value.1, <- encodeSecond value.2]

def decodeMap {key value : Type} [BEq key] [Hashable key]
    (decodeKey : ByteArray -> Result key) (decodeValue : ByteArray -> Result value)
    (data : ByteArray) : Result (Std.HashMap key value) := do
  return Std.HashMap.ofList (<- decodeArray (decodePair decodeKey decodeValue) data).toList

def encodeMap {key value : Type} [BEq key] [Hashable key]
    (encodeKey : key -> Result ByteArray) (encodeValue : value -> Result ByteArray)
    (values : Std.HashMap key value) : Result ByteArray :=
  encodeArray (encodePair encodeKey encodeValue) values.toArray

@[extern "spec_host_call"]
opaque hostCall (name : @& String) (data : @& ByteArray) : ByteArray

def host (name : String) (frames : List ByteArray) : Result ByteArray := do
  let answer := hostCall name (writeFrames frames)
  let body := answer.extract 1 answer.size
  match (answer[0]? : Option UInt8) with
  | some 0 => return body
  | some _ => .error ((String.fromUTF8? body).getD s!"`{name}` failed")
  | none => .error s!"nothing answered `{name}`"

def hostBool (name : String) (frames : List ByteArray) : Result Bool := do
  return (<- host name frames) == ByteArray.mk #[1]

namespace bls

def Sign (privkey : Nat) (message : ByteArray) : Result ByteArray :=
  host "bls.Sign" [uint_to_bytes 32 privkey, message]

def Verify (pubkey : ByteArray) (message : ByteArray) (signature : ByteArray) : Result Bool :=
  hostBool "bls.Verify" [pubkey, message, signature]

def Aggregate (signatures : Array ByteArray) : Result ByteArray :=
  host "bls.Aggregate" [writeFrames signatures.toList]

def FastAggregateVerify (pubkeys : Array ByteArray) (message : ByteArray)
    (signature : ByteArray) : Result Bool :=
  hostBool "bls.FastAggregateVerify" [writeFrames pubkeys.toList, message, signature]

def AggregateVerify (pubkeys : Array ByteArray) (messages : Array ByteArray)
    (signature : ByteArray) : Result Bool :=
  hostBool "bls.AggregateVerify" [writeFrames pubkeys.toList, writeFrames messages.toList, signature]

def KeyValidate (pubkey : ByteArray) : Result Bool :=
  hostBool "bls.KeyValidate" [pubkey]

end bls
"""

SHIM = """\
#include <lean/lean.h>

#define SPEC_EXPORT __attribute__((visibility("default"), used))

typedef const uint8_t *(*spec_host_fn)(const char *, const uint8_t *, size_t, size_t *);

extern void lean_initialize_runtime_module(void);
extern lean_object *initialize_Spec(uint8_t builtin);
extern lean_object *spec_dispatch(lean_object *key, lean_object *args);
extern lean_object *spec_config_names(lean_object *unit);

static int initialized = 0;
static spec_host_fn host = NULL;

static void spec_init(void) {
    if (initialized) return;
    lean_initialize_runtime_module();
    lean_object *result = initialize_Spec(1);
    if (lean_io_result_is_ok(result)) {
        lean_dec_ref(result);
    } else {
        lean_io_result_show_error(result);
        lean_dec(result);
    }
    lean_io_mark_end_initialization();
    initialized = 1;
}

SPEC_EXPORT void *spec_call(const char *key, const uint8_t *args, size_t length) {
    spec_init();
    lean_object *bytes = lean_alloc_sarray(1, length, length);
    uint8_t *target = lean_sarray_cptr(bytes);
    for (size_t index = 0; index < length; index++) {
        target[index] = args[index];
    }
    return (void *)spec_dispatch(lean_mk_string(key), bytes);
}

SPEC_EXPORT void *spec_configs(void) {
    spec_init();
    return (void *)spec_config_names(lean_box(0));
}

SPEC_EXPORT size_t spec_size(void *reply) { return lean_sarray_size((lean_object *)reply); }

SPEC_EXPORT const uint8_t *spec_data(void *reply) {
    return lean_sarray_cptr((lean_object *)reply);
}

SPEC_EXPORT void spec_release(void *reply) { lean_dec((lean_object *)reply); }

SPEC_EXPORT void spec_set_host(spec_host_fn function) { host = function; }

lean_object *spec_host_call(b_lean_obj_arg name, b_lean_obj_arg data) {
    size_t size = 0;
    const uint8_t *answer = NULL;
    if (host != NULL) {
        answer = host(lean_string_cstr(name), lean_sarray_cptr(data), lean_sarray_size(data), &size);
    }
    lean_object *bytes = lean_alloc_sarray(1, size, size);
    uint8_t *target = lean_sarray_cptr(bytes);
    for (size_t index = 0; index < size; index++) {
        target[index] = answer[index];
    }
    return bytes;
}
"""


def _name(name: str) -> str:
    return f"«{name}»" if name in KEYWORDS else name


def _top(text: str) -> Iterator[int]:
    depth = 0
    for index, character in enumerate(text):
        if character in "([{":
            depth += 1
        elif character in ")]}":
            depth -= 1
        elif depth == 0:
            yield index


def _groups(text: str, opening: str = "(", closing: str = ")") -> list[str]:
    groups = []
    depth = start = 0
    for index, character in enumerate(text):
        if character in "([{":
            depth += 1
            start = index + 1 if depth == 1 else start
        elif character in ")]}":
            depth -= 1
            if depth == 0 and text[start - 1] == opening and character == closing:
                groups.append(text[start:index])
    return groups


def _enclosed(text: str) -> bool:
    depth = 0
    for index, character in enumerate(text):
        depth += (character == "(") - (character == ")")
        if depth == 0:
            return index == len(text) - 1 and text.startswith("(")
    return False


def _words(text: str) -> list[str]:
    text = text.strip()
    while _enclosed(text):
        text = text[1:-1].strip()
    words = []
    start = 0
    for index in [*_top(text), len(text)]:
        if index == len(text) or text[index].isspace():
            if word := text[start:index].strip():
                words.append(word)
            start = index + 1
    return words


def _type(text: str, definition: Definition, variables: frozenset[str]) -> Type:
    match _words(text):
        case ["Bool"]:
            return Type("bool")
        case ["Nat"]:
            return Type("int")
        case ["ByteArray"]:
            return Type("bytes")
        case ["Array", element]:
            return Type("sequence", (_type(element, definition, variables),))
        case ["Std.HashSet", element]:
            return Type("set", (_type(element, definition, variables),))
        case ["Option", element]:
            return Type("option", (_type(element, definition, variables),))
        case ["Std.HashMap", key, value]:
            return Type(
                "map",
                (_type(key, definition, variables), _type(value, definition, variables)),
            )
        case ["Prod", _, _]:
            return Type("tuple", _components(text, definition, variables))
        case [name] if name in variables:
            return Type("object")
        case [name] if IDENTIFIER.fullmatch(name):
            return Type(name)
    raise SpecError(
        f"{definition.path}: `{definition.name}` uses `{text.strip()}`, which cannot cross "
        "into another language"
    )


def _components(text: str, definition: Definition, variables: frozenset[str]) -> tuple[Type, ...]:
    match _words(text):
        case ["Prod", first, rest]:
            return (
                _type(first, definition, variables),
                *_components(rest, definition, variables),
            )
    return (_type(text, definition, variables),)


def _signature(definition: Definition) -> tuple[Signature, bool]:
    source = definition.source
    body = next((index for index in _top(source) if source.startswith(":=", index)), None)
    if body is None:
        raise SpecError(f"{definition.path}: `{definition.name}` has no body")
    header = source[:body]
    colon = max((index for index in _top(header) if header[index] == ":"), default=None)
    if colon is None:
        raise SpecError(f"{definition.path}: `{definition.name}` declares no result type")
    variables = frozenset(
        name
        for group in _groups(header[:colon], "{", "}")
        if group.partition(":")[2].strip() == "Type"
        for name in group.partition(":")[0].split()
    )
    parameters = []
    defaults = {}
    for group in _groups(header[:colon]):
        names, _, annotation = group.partition(":")
        annotation, _, default = annotation.partition(":=")
        kind = _type(annotation, definition, variables)
        parameters += [(name, kind) for name in names.split()]
        if default:
            literal = DEFAULTS.get(default.strip(), default.strip())
            if not literal.isdigit() and literal not in DEFAULTS.values():
                raise SpecError(
                    f"{definition.path}: `{definition.name}` gives `{names.strip()}` "
                    f"the default `{default.strip()}`, which another language cannot spell"
                )
            defaults |= dict.fromkeys(names.split(), literal)
    result = header[colon + 1 :].strip()
    fallible = result.startswith(RESULT)
    result = result.removeprefix(RESULT)
    results = () if _words(result) == ["Unit"] else _components(result, definition, variables)
    if any(kind.name == "object" for kind in results):
        raise SpecError(f"{definition.path}: `{definition.name}` returns a value of any type")
    return Signature(tuple(parameters), results, tuple(defaults.items())), fallible


def _ordered(definitions: list[Definition]) -> list[Definition]:
    named = {definition.name: definition for definition in definitions}
    ordered: list[Definition] = []

    def place(definition: Definition, calling: frozenset[str]) -> None:
        if definition in ordered:
            return
        if definition.name in calling:
            raise SpecError(f"{definition.path}: `{definition.name}` calls itself through others")
        for name in IDENTIFIER.findall(definition.source):
            if name != definition.name and name in named:
                place(named[name], calling | {definition.name})
        ordered.append(definition)

    for definition in definitions:
        place(definition, frozenset())
    return ordered


def _reader(types: dict[str, SszType], name: str) -> str:
    kind = types[name]
    if kind.kind in CONTAINERS:
        return f"{name}.ofValue"
    if kind.kind in SEQUENCES:
        return f"(asArray {_reader(types, str(kind.element))})"
    return SCALARS[kind.kind].reader


def _writer(types: dict[str, SszType], name: str) -> str:
    kind = types[name]
    if kind.kind in CONTAINERS:
        return f"{name}.toValue"
    if kind.kind in SEQUENCES:
        return f"(ofArray {_writer(types, str(kind.element))})"
    return SCALARS[kind.kind].writer


def _default(types: dict[str, SszType], name: str) -> str:
    kind = types[name]
    match kind.kind:
        case "bool":
            return "false"
        case "uint":
            return "0"
        case "byteVector":
            return f"zeroBytes {kind.size}"
        case "byteList":
            return "ByteArray.empty"
        case "bitVector":
            return f"Array.replicate {kind.size} false"
        case "vector":
            return f"Array.replicate {kind.size} ({_default(types, str(kind.element))})"
        case "container" | "progressiveContainer":
            return "default"
    return "#[]"


def _listing(items: list[str], indent: str) -> str:
    if not items:
        return "[]"
    return "[\n" + ",\n".join(f"{indent}  {item}" for item in items) + f"\n{indent}]"


def _desc(kind: SszType) -> str:
    bound = "none" if kind.size is None else f"(some {kind.size})"
    match kind.kind:
        case "bool":
            return ".bool"
        case "progressiveBitList":
            return f".progressiveBitList {bound}"
        case "vector" | "list":
            return f".{kind.kind} {kind.element}.desc {kind.size}"
        case "progressiveList":
            return f".progressiveList {kind.element}.desc {bound}"
        case "container" | "progressiveContainer":
            names = _listing([json.dumps(field) for field, _ in kind.fields], "    ")
            descs = _listing([f"{field}.desc" for _, field in kind.fields], "    ")
            layout = _listing(["true" if bit else "false" for bit in kind.layout], "    ")
            if kind.kind == "container":
                return f".container\n    {names}\n    {descs}"
            return f".progressiveContainer\n    {layout}\n    {names}\n    {descs}"
    return f".{kind.kind} {kind.size}"


def _of_value(types: dict[str, SszType], name: str, fields: tuple[tuple[str, str], ...]) -> str:
    reads = "".join(
        f"  let {_name(field)} <- {_reader(types, kind)} (<- fields[{index}]?)\n"
        for index, (field, kind) in enumerate(fields)
    )
    punned = "".join(f"    {_name(field)}\n" for field, _ in fields)
    return (
        f"def {name}.ofValue (value : Ssz.Value) : Result {name} := do\n"
        f"  let fields <- asFields value\n{reads}  return {{\n{punned}  }}"
    )


def _structure(types: dict[str, SszType], name: str) -> list[str]:
    fields = types[name].fields
    declared = "".join(f"  {_name(field)} : {kind}\n" for field, kind in fields)
    defaults = "".join(f"    {_name(field)} := {_default(types, kind)}\n" for field, kind in fields)
    writes = ",\n".join(
        f"    {_writer(types, kind)} value.{_name(field)}" for field, kind in fields
    )
    return [
        f"structure {name} where\n{declared}  deriving BEq, Hashable",
        f"instance : Inhabited {name} where\n  default := {{\n{defaults}  }}",
        f"def {name}.desc : Ssz.Desc :=\n  {_desc(types[name])}",
        f"def {name}.toValue (value : {name}) : Ssz.Value :=\n  .seq [\n{writes}\n  ]",
        _of_value(types, name, fields),
        f"instance : Merkleizable {name} where\n  desc := {name}.desc\n  toValue := {name}.toValue",
    ]


def _record(environment: Environment, name: str) -> list[str]:
    record = environment.records[name]
    declared = "".join(f"  {_name(field)} : {_lean_type(kind)}\n" for field, kind in record.fields)
    derived = "Inhabited, BEq, Hashable" if record.hashable else "Inhabited"
    reads = "".join(
        f"    {_name(field)} := (<- {_codec(environment, kind)[0]} (<- fields[{index}]?))\n"
        for index, (field, kind) in enumerate(record.fields)
    )
    writes = ",\n".join(
        f"    (<- {_codec(environment, kind)[1]} value.{_name(field)})"
        for field, kind in record.fields
    )
    return [
        f"structure {name} where\n{declared}  deriving {derived}",
        (
            f"def {name}.decode (data : ByteArray) : Result {name} := do\n"
            f"  let fields := (<- readFrames data).toArray\n  return {{\n{reads}  }}"
        ),
        (
            f"def {name}.encode (value : {name}) : Result ByteArray := do\n"
            f"  return writeFrames [\n{writes}\n  ]"
        ),
    ]


def _declarations(types: dict[str, SszType], name: str) -> list[str]:
    kind = types[name]
    if kind.kind in CONTAINERS:
        return _structure(types, name)
    lean = f"Array {kind.element}" if kind.kind in SEQUENCES else SCALARS[kind.kind].lean
    return [
        f"abbrev {name} := {lean}",
        f"def {name}.desc : Ssz.Desc :=\n  {_desc(kind)}",
        (
            f"def {name}.hash_tree_root (value : {name}) : Result ByteArray :=\n"
            f"  Spec.hash_tree_root (merkleizable := {{ desc := {name}.desc, "
            f"toValue := {_writer(types, name)} }}) value"
        ),
    ]


def _constant(types: dict[str, SszType], name: str, kind: str, value: object) -> str:
    shape = types[kind].kind if kind in types else kind
    if shape == "bool":
        literal = "true" if value else "false"
    elif shape in ("uint", "int"):
        literal = str(value)
    elif shape in ("byteVector", "byteList", "bytes"):
        assert isinstance(value, bytes)
        literal = f"ByteArray.mk #[{', '.join(str(byte) for byte in value)}]"
    elif shape == "str":
        literal = json.dumps(value)
    else:
        raise SpecError(f"`{name}` holds a value lean cannot spell")
    return f"def {name} : {PLAIN.get(kind, kind)} :=\n  {literal}"


def _configuration(types: dict[str, SszType], configs: dict[str, str]) -> list[str]:
    fields = tuple(configs.items())
    declared = "".join(f"  {name} : {kind}\n" for name, kind in fields)
    return [
        f"class Config where\n{declared}".rstrip(),
        f"def Config.desc : Ssz.Desc :=\n  {_desc(SszType('container', fields=fields))}",
        _of_value(types, "Config", fields),
        f"export Config ({' '.join(configs)})",
    ]


def _lean_type(kind: Type) -> str:
    arguments = [_lean_type(argument) for argument in kind.arguments]
    match kind.name:
        case "bool":
            return "Bool"
        case "int":
            return "Nat"
        case "bytes":
            return "ByteArray"
        case "sequence":
            return f"(Array {arguments[0]})"
        case "set":
            return f"(Std.HashSet {arguments[0]})"
        case "map":
            return f"(Std.HashMap {arguments[0]} {arguments[1]})"
        case "option":
            return f"(Option {arguments[0]})"
        case "tuple":
            *rest, last = arguments
            for first in reversed(rest):
                last = f"(Prod {first} {last})"
            return last
    return kind.name


def _codec(environment: Environment, kind: Type) -> tuple[str, str]:
    types = environment.types
    match kind.name:
        case "bool":
            return "(decodeWith .bool asBool)", "(encodeAs .bool ofBool)"
        case "int":
            return "(decodeWith (.uint 32) asUint)", "(encodeAs (.uint 32) ofUint)"
        case "bytes":
            return "decodeBytes", "encodeBytes"
        case "sequence" | "set" | "option":
            decoder, encoder = _codec(environment, kind.arguments[0])
            wrapper = {"sequence": "Array", "set": "Set", "option": "Option"}[kind.name]
            return f"(decode{wrapper} {decoder})", f"(encode{wrapper} {encoder})"
        case "map":
            (key_decoder, key_encoder), (value_decoder, value_encoder) = [
                _codec(environment, argument) for argument in kind.arguments
            ]
            return (
                f"(decodeMap {key_decoder} {value_decoder})",
                f"(encodeMap {key_encoder} {value_encoder})",
            )
        case "tuple":
            *rest, last = [_codec(environment, argument) for argument in kind.arguments]
            decoder, encoder = last
            for first_decoder, first_encoder in reversed(rest):
                decoder = f"(decodePair {first_decoder} {decoder})"
                encoder = f"(encodePair {first_encoder} {encoder})"
            return decoder, encoder
        case "object":
            raise SpecError("only a parameter can hold a value of any type")
    if kind.name in environment.records:
        return f"{kind.name}.decode", f"{kind.name}.encode"
    if kind.name not in types:
        raise SpecError(f"`{kind.name}` has no SSZ shape")
    desc = f"{kind.name}.desc"
    reader, writer = _reader(types, kind.name), _writer(types, kind.name)
    return f"(decodeWith {desc} {reader})", f"(encodeAs {desc} {writer})"


def _arm(environment: Environment, definition: Definition) -> str:
    signature, fallible = _signature(definition)
    names = [name for name, _ in signature.parameters]
    lines = [f'  | "{definition.name}", [{", ".join(names)}] => do']
    objects = []
    for name, kind in signature.parameters:
        if kind.name == "object":
            objects.append(name)
        else:
            lines.append(f"    let {name} <- {_codec(environment, kind)[0]} {name}")
    call = " ".join([definition.name, *names])
    for name in objects:
        call = f"withObject {name} fun {name} => {call if fallible else f'pure ({call})'}"
        fallible = True
    if not signature.results:
        lines += [f"    {call}" if fallible else f"    let _ := {call}", "    return []"]
        return "\n".join(lines)
    lines.append(f"    let result {'<-' if fallible else ':='} {call}")
    count = len(signature.results)
    parts = []
    for index, kind in enumerate(signature.results):
        part = "result" + ".2" * index + (".1" if count > 1 and index < count - 1 else "")
        parts.append(f"(<- {_codec(environment, kind)[1]} {part})")
    lines.append(f"    return [{', '.join(parts)}]")
    return "\n".join(lines)


def _with_object(types: dict[str, SszType]) -> str:
    arms = "".join(
        f'  | some "{name}" =>\n'
        f"    @call {name} {{ desc := {name}.desc, toValue := {_writer(types, name)} }}\n"
        f"      (<- decodeWith {name}.desc {_reader(types, name)} object)\n"
        for name in types
    )
    return (
        "def withObject {result : Type} (data : ByteArray)\n"
        "    (call : {value : Type} -> [Merkleizable value] -> value -> Result result) :\n"
        "    Result result := do\n"
        "  let [name, object] <- readFrames data\n"
        '    | .error "expected a type name and an object"\n'
        "  match String.fromUTF8? name with\n"
        f"{arms}"
        '  | _ => .error "the object has a type this specification does not know"'
    )


def _dispatch(environment: Environment, definitions: list[Definition]) -> str:
    types = environment.types
    configs = list(environment.configs)
    functions = _listing([json.dumps(definition.name) for definition in definitions], "  ")
    settings = "_config : Config <- decodeWith Config.desc Config.ofValue settings"
    arms = "\n".join(_arm(environment, definition) for definition in definitions)
    generic = any(
        kind.name == "object"
        for definition in definitions
        for _, kind in _signature(definition)[0].parameters
    )
    return "\n\n".join(
        [
            *([_with_object(types)] if generic else []),
            f"def functions : List String :=\n  {functions}",
            (
                "def call (key : String) (frames : List ByteArray) : Result (List ByteArray) := do\n"
                f"  let {'settings' if configs else '_settings'} :: arguments := frames\n"
                '    | .error "missing the configuration"\n'
                + (f"  let {settings}\n" if configs else "")
                + "  match key, arguments with\n"
                + f"{arms}\n"
                + '  | _, _ => .error s!"`{key}` takes other arguments"'
            ),
            (
                "@[export spec_dispatch]\n"
                "def dispatch (key : String) (data : ByteArray) : ByteArray :=\n"
                "  if functions.contains key then\n"
                "    match readFrames data >>= call key with\n"
                "    | .ok results => reply 0 (writeFrames results)\n"
                "    | .error message => reply 1 message.toUTF8\n"
                "  else\n"
                "    reply 2 key.toUTF8"
            ),
            (
                "@[export spec_config_names]\n"
                "def configNames (_ : Unit) : ByteArray :=\n"
                f"  {json.dumps(','.join(configs))}.toUTF8"
            ),
        ]
    )


def _module(definitions: list[Definition], environment: Environment) -> str:
    types = environment.types
    ordered = _ordered(definitions)
    sources = "\n\n".join(definition.source for definition in ordered)
    configs = list(environment.configs)
    sections = [
        PRELUDE.strip(),
        *(text for name in types for text in _declarations(types, name)),
        *(text for name in environment.records for text in _record(environment, name)),
        *(_constant(types, name, *value) for name, value in environment.values.items()),
        *(_configuration(types, environment.configs) if configs else []),
        f"section\nvariable [Config]\n\n{sources}\n\nend" if configs else sources,
        _dispatch(environment, ordered),
        "end Spec",
    ]
    return "\n\n".join(sections) + "\n"


def _run(
    command: list[str],
    directory: Path | None = None,
    variables: dict[str, str] | None = None,
    source: Path | None = None,
) -> str:
    try:
        completed = subprocess.run(
            command,
            cwd=directory,
            env={**os.environ, "ELAN_TOOLCHAIN": TOOLCHAIN, **(variables or {})},
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        raise SpecError(
            f"`{command[0]}` is not installed, see https://lean-lang.org/install/"
        ) from None
    if completed.returncode != 0:
        output = completed.stdout + completed.stderr
        if source is not None:
            output = output.replace("Spec.lean", str(source))
        raise SpecError(f"`{' '.join(command)}` failed:\n{output}")
    return completed.stdout.strip()


@functools.cache
def _libdir() -> str:
    return _run(["lean", "--print-libdir"])


@functools.cache
def _workspace(directory: Path) -> tuple[Path, str]:
    directory.mkdir(parents=True, exist_ok=True)
    for name, content in (("lakefile.toml", LAKEFILE), ("lean-toolchain", f"{TOOLCHAIN}\n")):
        if not (directory / name).exists() or (directory / name).read_text() != content:
            (directory / name).write_text(content)
    _run(["lake", "build", "ssz/Ssz:static"], directory)
    lean_path = _run(["lake", "env", "printenv", "LEAN_PATH"], directory)
    package = directory / ".lake" / "packages" / "ssz" / "lean"
    return package / ".lake" / "build" / "lib" / "libssz_Ssz.a", lean_path


def _compile(module: str, library: Path, workspace: tuple[Path, str], source: Path) -> None:
    archive, lean_path = workspace
    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch)
        (work / "Spec.lean").write_text(module)
        (work / "shim.c").write_text(SHIM)
        _run(["lean", "-c", "Spec.c", "Spec.lean"], work, {"LEAN_PATH": lean_path}, source)
        link = [str(archive), "-lleanshared", f"-Wl,-rpath,{_libdir()}"]
        _run(["leanc", "-shared", "-o", "Spec.so", "Spec.c", "shim.c", *link], work)
        library.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(work / "Spec.so", library)


class Lean(Foreign):
    name = "lean"
    builtins = frozenset(
        {"bytes_to_uint64", "hash_tree_root", "raise", "require", "sha256", "uint_to_bytes"}
    )

    def __init__(self) -> None:
        self.compiling: dict[str, Future[None]] = {}
        self.pending: list[tuple[Future[None] | None, Path, Path]] = []

    def declarations(self, source: str) -> list[Declaration]:
        match = DEFINITION.match(source)
        if match is None:
            raise SpecError(f"expected a `def` in the lean block: {source.splitlines()[0]}")
        return [Declaration(Kind.FUNCTION, match.group(1), source)]

    def references(self, source: str) -> References:
        return frozenset(), frozenset(IDENTIFIER.findall(source))

    def signature(self, definition: Definition) -> Signature:
        return _signature(definition)[0]

    def build(
        self,
        directory: Path,
        preset: str,
        definitions: list[Definition],
        environment: Environment,
        cache: Path,
    ) -> None:
        module = _module(definitions, environment)
        source = directory / f"{preset}.lean"
        source.write_text(module)
        key = hashlib.sha256(f"{TOOLCHAIN}\n{SSZ_REVISION}\n{SHIM}\n{module}".encode()).hexdigest()
        library = cache / f"{key}.so"
        if key not in self.compiling and not library.exists():
            version = TOOLCHAIN.rpartition(":")[2]
            workspace = _workspace(cache / f"ssz-{SSZ_REVISION[:12]}-{version}")
            _libdir()
            self.compiling[key] = POOL.submit(_compile, module, library, workspace, source)
        target = directory / f"{preset}.{self.name}.so"
        self.pending.append((self.compiling.get(key), library, target))

    def wait(self) -> None:
        for compiling, library, target in self.pending:
            if compiling is not None:
                compiling.result()
            shutil.copy(library, target)
        self.pending.clear()

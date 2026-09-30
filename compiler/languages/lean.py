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
DEFINITION = re.compile(r"def (\w+)\s")
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
RESULT = "Result "
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

def hash (data : ByteArray) : ByteArray :=
  Ssz.Sha256.hash data

def hash_tree_root {value : Type} [Merkleizable value] (object : value) : Result ByteArray :=
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

def readLength (data : ByteArray) (start : Nat) : Nat :=
  (List.range 4).foldr (fun index total => total * 256 + (data.get! (start + index)).toNat) 0

def lengthBytes (size : Nat) : ByteArray :=
  ByteArray.mk ((Array.range 4).map fun index => (size >>> (8 * index)).toUInt8)

def readFrames (data : ByteArray) : Result (List ByteArray) := Id.run do
  let mut frames := #[]
  let mut position := 0
  while position < data.size do
    if position + 4 > data.size then
      return .error "truncated frame"
    let start := position + 4
    let stop := start + readLength data position
    if stop > data.size then
      return .error "truncated frame"
    frames := frames.push (data.extract start stop)
    position := stop
  return .ok frames.toList

def writeFrames (frames : List ByteArray) : ByteArray :=
  frames.foldl (fun data frame => data ++ lengthBytes frame.size ++ frame) ByteArray.empty

def reply (status : UInt8) (payload : ByteArray) : ByteArray :=
  ByteArray.mk #[status] ++ payload
"""

SHIM = """\
#include <lean/lean.h>

#define SPEC_EXPORT __attribute__((visibility("default"), used))

extern void lean_initialize_runtime_module(void);
extern lean_object *initialize_Spec(uint8_t builtin);
extern lean_object *spec_dispatch(lean_object *key, lean_object *args);
extern lean_object *spec_config_names(lean_object *unit);

static int initialized = 0;

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


def _groups(text: str) -> list[str]:
    groups = []
    depth = start = 0
    for index, character in enumerate(text):
        if character == "(":
            depth += 1
            start = index + 1 if depth == 1 else start
        elif character == ")":
            depth -= 1
            if depth == 0:
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


def _type(text: str, definition: Definition) -> Type:
    match _words(text):
        case ["Bool"]:
            return Type("bool")
        case ["Nat"]:
            return Type("int")
        case ["Array", element]:
            return Type("sequence", _type(element, definition))
        case [name] if IDENTIFIER.fullmatch(name):
            return Type(name)
    raise SpecError(
        f"{definition.path}: `{definition.name}` uses `{text.strip()}`, which cannot cross "
        "into another language"
    )


def _results(text: str, definition: Definition) -> tuple[Type, ...]:
    match _words(text):
        case ["Unit"]:
            return ()
        case ["Prod", first, rest]:
            return (_type(first, definition), *_results(rest, definition))
    return (_type(text, definition),)


def _signature(definition: Definition) -> tuple[Signature, bool]:
    source = definition.source
    body = next((index for index in _top(source) if source.startswith(":=", index)), None)
    if body is None:
        raise SpecError(f"{definition.path}: `{definition.name}` has no body")
    header = source[:body]
    colon = max((index for index in _top(header) if header[index] == ":"), default=None)
    if colon is None:
        raise SpecError(f"{definition.path}: `{definition.name}` declares no result type")
    parameters = []
    for group in _groups(header[:colon]):
        names, _, annotation = group.partition(":")
        kind = _type(annotation, definition)
        parameters += [(name, kind) for name in names.split()]
    result = header[colon + 1 :].strip()
    fallible = result.startswith(RESULT)
    results = _results(result.removeprefix(RESULT), definition)
    return Signature(tuple(parameters), results), fallible


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
        f"structure {name} where\n{declared}  deriving BEq",
        f"instance : Inhabited {name} where\n  default := {{\n{defaults}  }}",
        f"def {name}.desc : Ssz.Desc :=\n  {_desc(types[name])}",
        f"def {name}.toValue (value : {name}) : Ssz.Value :=\n  .seq [\n{writes}\n  ]",
        _of_value(types, name, fields),
        f"instance : Merkleizable {name} where\n  desc := {name}.desc\n  toValue := {name}.toValue",
    ]


def _declarations(types: dict[str, SszType], name: str) -> list[str]:
    kind = types[name]
    if kind.kind in CONTAINERS:
        return _structure(types, name)
    lean = f"Array {kind.element}" if kind.kind in SEQUENCES else SCALARS[kind.kind].lean
    return [f"abbrev {name} := {lean}", f"def {name}.desc : Ssz.Desc :=\n  {_desc(kind)}"]


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


def _boundary(types: dict[str, SszType], kind: Type) -> tuple[str, str, str]:
    if kind.element is not None:
        desc, reader, writer = _boundary(types, kind.element)
        return f"(.progressiveList {desc} none)", f"(asArray {reader})", f"(ofArray {writer})"
    if kind.name == "bool":
        return ".bool", "asBool", "ofBool"
    if kind.name == "int":
        return "(.uint 8)", "asUint", "ofUint"
    if kind.name not in types:
        raise SpecError(f"`{kind.name}` has no SSZ shape")
    return f"{kind.name}.desc", _reader(types, kind.name), _writer(types, kind.name)


def _arm(types: dict[str, SszType], definition: Definition) -> str:
    signature, fallible = _signature(definition)
    names = [name for name, _ in signature.parameters]
    lines = [f'  | "{definition.name}", [{", ".join(names)}] => do']
    for name, kind in signature.parameters:
        desc, reader, _ = _boundary(types, kind)
        lines.append(f"    let {name} <- decodeWith {desc} {reader} {name}")
    call = " ".join([definition.name, *names])
    if not signature.results:
        lines += [f"    {call}" if fallible else f"    let _ := {call}", "    return []"]
        return "\n".join(lines)
    lines.append(f"    let result {'<-' if fallible else ':='} {call}")
    count = len(signature.results)
    parts = []
    for index, kind in enumerate(signature.results):
        part = "result" + ".2" * index + (".1" if count > 1 and index < count - 1 else "")
        desc, _, writer = _boundary(types, kind)
        parts.append(f"(<- encodeWith {desc} ({writer} {part}))")
    lines.append(f"    return [{', '.join(parts)}]")
    return "\n".join(lines)


def _dispatch(types: dict[str, SszType], definitions: list[Definition], configs: list[str]) -> str:
    functions = _listing([json.dumps(definition.name) for definition in definitions], "  ")
    settings = "_config : Config <- decodeWith Config.desc Config.ofValue settings"
    arms = "\n".join(_arm(types, definition) for definition in definitions)
    return "\n\n".join(
        [
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
        *(_constant(types, name, *value) for name, value in environment.values.items()),
        *(_configuration(types, environment.configs) if configs else []),
        f"section\nvariable [Config]\n\n{sources}\n\nend" if configs else sources,
        _dispatch(types, ordered, configs),
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
    builtins = frozenset({"hash", "hash_tree_root", "require"})

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

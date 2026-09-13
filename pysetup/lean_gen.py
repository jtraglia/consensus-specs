"""
Generate the Lean side of the specification, and the Python that calls into it.

A function the markdown defines in a ```lean block is compiled rather than
executed: the generated Python keeps the signature and docstring the spec gives
it, serializes its arguments, and calls the Lean library across the FFI.

Everything the Lean author writes against is generated from the same markdown:
the SSZ descriptor of every type, a wrapper type naming it, an accessor and a
setter for every field, and every constant of the preset. Only the function
bodies are written by hand.
"""

import ast
import re
from pathlib import Path
from types import ModuleType
from typing import NamedTuple

# Python annotations that are not SSZ types but that a bound function may use.
PLAIN_TYPES = {"bool", "int"}

SCALAR_DESCS = {
    "Boolean": "Ssz.Desc.bool",
    "bool": "Ssz.Desc.bool",
    "Byte": "Ssz.Desc.uint8",
    "Uint8": "Ssz.Desc.uint8",
    "Uint16": "Ssz.Desc.uint16",
    "Uint32": "Ssz.Desc.uint32",
    "Uint64": "Ssz.Desc.uint64",
    "Uint128": "Ssz.Desc.uint128",
    "Uint256": "Ssz.Desc.uint256",
    "int": "Ssz.Desc.uint64",
}
COLLECTIONS = {
    "List": ("list", "LIMIT"),
    "Vector": ("vector", "LENGTH"),
    "ByteList": ("byteList", "LIMIT"),
    "ByteVector": ("byteVector", "LENGTH"),
    "BitList": ("bitList", "LIMIT"),
    "BitVector": ("bitVector", "LENGTH"),
    "ProgressiveList": ("progressiveList", None),
    "ProgressiveBitList": ("progressiveBitList", None),
}
BYTES_TYPE = re.compile(r"^Bytes(\d+)$")

UINT_READERS = {
    8: "Pyspec.asUInt8",
    16: "Pyspec.asUInt16",
    32: "Pyspec.asUInt32",
    64: "Pyspec.asUInt64",
}
UINT_LEAN = {8: "UInt8", 16: "UInt16", 32: "UInt32", 64: "UInt64"}


class LeanType(NamedTuple):
    """How one spec type is spelled in Lean, read from a value, and written back."""

    desc: str
    lean: str
    # Templates over a single ``{}``: the value being read, or the term being written.
    read: str
    write: str

    def reader(self, value: str) -> str:
        return self.read.format(value)

    def writer(self, term: str) -> str:
        return self.write.format(term)


class Binding(NamedTuple):
    """A spec function whose implementation comes from Lean."""

    name: str
    key: str
    params: list[tuple[str, LeanType]]
    result: LeanType
    # Set when the Python signature returns None and the function edits its first
    # argument. Lean returns the new value and the caller copies it back.
    mutates: str | None
    # Set when the Lean definition returns SpecM, so its result must be bound.
    monadic: bool


class UnsupportedType(Exception):
    """A type that cannot cross the boundary, named so the author can see why."""


def module_name(fork: str, preset: str) -> str:
    return f"{fork.capitalize()}{preset.capitalize()}"


def _uint(width_bits: int) -> LeanType:
    if width_bits in UINT_LEAN:
        return LeanType(
            desc=SCALAR_DESCS[f"Uint{width_bits}"],
            lean=UINT_LEAN[width_bits],
            read=f"({UINT_READERS[width_bits]} {{}})",
            write="(Ssz.Value.uint ({}).toNat)",
        )
    # Lean has no UInt128 or UInt256, so the wide integers are plain naturals.
    return LeanType(
        desc=SCALAR_DESCS[f"Uint{width_bits}"],
        lean="Nat",
        read="(Pyspec.asNat {})",
        write="(Ssz.Value.uint {})",
    )


BOOL_TYPE = LeanType(
    desc="Ssz.Desc.bool", lean="Bool", read="(Pyspec.asBool {})", write="(Ssz.Value.bool {})"
)
BYTES_READ = LeanType(
    desc="", lean="ByteArray", read="(Pyspec.asBytes {})", write="(Pyspec.ofBytes {})"
)
BITS_READ = LeanType(
    desc="", lean="Array Bool", read="(Pyspec.asBits {})", write="(Pyspec.ofBits {})"
)


class LeanTypes:
    """The spec's type table, translated once and then looked up by name."""

    def __init__(self, spec_object, ordered: dict[str, str], module: ModuleType):
        self.module = module
        self.table: dict[str, LeanType] = {}
        self.declarations: list[str] = []
        # Types that have no Lean rendering, mapped to what stopped them. A
        # function that names one cannot be bound, and is told why.
        self.skipped: dict[str, str] = {}
        self._build(spec_object, ordered)

    # -- resolving bounds ----------------------------------------------------

    def value_of(self, expression: str) -> int:
        """Resolve a bound, which may be any expression over spec constants."""
        names = dict(vars(self.module)) | dict(self.module.config._asdict())
        return int(eval(expression, names))

    # -- translating type expressions ---------------------------------------

    def translate(self, node: ast.expr) -> LeanType:
        """The Lean rendering of a Python SSZ type expression."""
        text = ast.unparse(node)
        if text in self.table:
            return self.table[text]
        if text in SCALAR_DESCS:
            if text in ("Boolean", "bool"):
                return BOOL_TYPE
            if text == "Byte":
                return _uint(8)
            return _uint(int(text.removeprefix("Uint")) if text != "int" else 64)
        if match := BYTES_TYPE.match(text):
            return BYTES_READ._replace(desc=f"(Ssz.Desc.byteVector {match.group(1)})")
        if isinstance(node, ast.Subscript):
            head = ast.unparse(node.value)
            parts = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
            if head in COLLECTIONS:
                return self._collection(head, parts)
        raise UnsupportedType(text)

    def _collection(self, head: str, parts: list[ast.expr]) -> LeanType:
        constructor, _ = COLLECTIONS[head]
        if head in ("ByteList", "ByteVector"):
            return BYTES_READ._replace(
                desc=f"(Ssz.Desc.{constructor} {self.value_of(ast.unparse(parts[0]))})"
            )
        if head in ("BitList", "BitVector"):
            return BITS_READ._replace(
                desc=f"(Ssz.Desc.{constructor} {self.value_of(ast.unparse(parts[0]))})"
            )
        if head == "ProgressiveBitList":
            return BITS_READ._replace(desc="Ssz.Desc.progressiveBitList")
        element = self.translate(parts[0])
        if head == "ProgressiveList":
            desc = f"(Ssz.Desc.progressiveList {element.desc})"
        else:
            desc = f"(Ssz.Desc.{constructor} {element.desc} {self.value_of(ast.unparse(parts[1]))})"
        return self._sequence(desc, element)

    @staticmethod
    def _sequence(desc: str, element: LeanType) -> LeanType:
        return LeanType(
            desc=desc,
            lean=f"(Array {element.lean})",
            read="((Pyspec.asSeq {}).map (fun element => " + element.reader("element") + "))",
            write="(Pyspec.ofSeq (({}).map (fun element => " + element.writer("element") + ")))",
        )

    # -- building the table --------------------------------------------------

    def _build(self, spec_object, ordered: dict[str, str]) -> None:
        for name, value in spec_object.custom_types.items():
            self._declare_alias(name, ast.parse(value).body[0].value)
        # Only SSZ types cross the boundary. The dataclasses -- ``Store`` and
        # the like -- hold Python containers that have no encoding.
        for name, source in ordered.items():
            if name not in spec_object.ssz_objects:
                self.skipped[name] = "not an SSZ type"
                continue
            try:
                self._declare(name, source)
            except UnsupportedType as error:
                self.skipped[name] = f"built on {error}"

    def require(self, node: ast.expr) -> LeanType:
        """Translate a type, reporting a skipped one by the reason it was skipped."""
        text = ast.unparse(node)
        if text in self.skipped:
            raise UnsupportedType(f"{text} ({self.skipped[text]})")
        return self.translate(node)

    def _declare_alias(self, name: str, node: ast.expr) -> None:
        underlying = self.translate(node)
        self.declarations.append(f"abbrev {name} := {underlying.lean}")
        self.declarations.append(f"def Descs.{name} : Ssz.Desc := {underlying.desc}")
        self.table[name] = underlying._replace(desc=f"Descs.{name}", lean=name)

    def _declare(self, name: str, source: str) -> None:
        cls = ast.parse(source).body[0]
        assert isinstance(cls, ast.ClassDef)
        base = cls.bases[0] if cls.bases else None
        head = (
            ast.unparse(base.value if isinstance(base, ast.Subscript) else base) if base else None
        )

        if head in COLLECTIONS:
            self._declare_collection(name, cls, head, base)
        elif head in ("Container", "ProgressiveContainer", None):
            self._declare_container(name, cls, head)
        else:
            # A scalar alias, or a type unchanged from an earlier fork.
            self._declare_alias(name, ast.Name(id=head))

    def _declare_collection(self, name: str, cls: ast.ClassDef, head: str, base: ast.expr) -> None:
        constructor, bound_name = COLLECTIONS[head]
        bound = _class_body_value(cls, bound_name) if bound_name else None
        if head in ("ByteList", "ByteVector"):
            resolved = BYTES_READ._replace(desc=f"(Ssz.Desc.{constructor} {self.value_of(bound)})")
        elif head in ("BitList", "BitVector"):
            resolved = BITS_READ._replace(desc=f"(Ssz.Desc.{constructor} {self.value_of(bound)})")
        elif head == "ProgressiveBitList":
            resolved = BITS_READ._replace(desc="Ssz.Desc.progressiveBitList")
        else:
            element = self.translate(base.slice)
            if head == "ProgressiveList":
                desc = f"(Ssz.Desc.progressiveList {element.desc})"
            else:
                desc = f"(Ssz.Desc.{constructor} {element.desc} {self.value_of(bound)})"
            resolved = self._sequence(desc, element)
        self.declarations.append(f"abbrev {name} := {resolved.lean}")
        self.declarations.append(f"def Descs.{name} : Ssz.Desc := {resolved.desc}")
        self.table[name] = resolved._replace(desc=f"Descs.{name}", lean=name)

    def _declare_container(self, name: str, cls: ast.ClassDef, head: str | None) -> None:
        fields = [
            (statement.target.id, self.translate(statement.annotation))
            for statement in cls.body
            if isinstance(statement, ast.AnnAssign)
        ]
        names = "[" + ", ".join(f'"{field}"' for field, _ in fields) + "]"
        descs = "[" + ", ".join(kind.desc for _, kind in fields) + "]"
        if head == "ProgressiveContainer":
            active = getattr(self.module, name).ACTIVE_FIELDS
            mask = "[" + ", ".join("true" if bit else "false" for bit in active) + "]"
            desc = f".progressiveContainer {mask} {names}\n    {descs}"
        else:
            desc = f".container {names}\n    {descs}"

        lines = [
            f"def Descs.{name} : Ssz.Desc :=\n  {desc}",
            f"/-- `{name}`, as the specification declares it. -/",
            f"structure {name} where\n  raw : Ssz.Value\nderiving Inhabited",
        ]
        for index, (field, kind) in enumerate(fields):
            source = f"(Pyspec.field self.raw {index})"
            lines.append(
                f"def {name}.{field} (self : {name}) : {kind.lean} := {kind.reader(source)}"
            )
            written = kind.writer("value")
            lines.append(
                f"def {name}.set_{field} (self : {name}) (value : {kind.lean}) : {name} :=\n"
                f"  ⟨Pyspec.setField self.raw {index} {written}⟩"
            )
        self.declarations.extend(lines)
        self.table[name] = LeanType(desc=f"Descs.{name}", lean=name, read="⟨{}⟩", write="({}).raw")


def _class_body_value(cls: ast.ClassDef, name: str) -> str | None:
    for statement in cls.body:
        if isinstance(statement, ast.Assign) and getattr(statement.targets[0], "id", None) == name:
            return ast.unparse(statement.value)
    return None


def _lean_return_type(source: str, name: str) -> str:
    """The declared result of a Lean definition, read off its signature."""
    start = source.index(f"def {name}")
    depth = 0
    for offset in range(start, len(source) - 1):
        character = source[offset]
        if character in "([{⟨":
            depth += 1
        elif character in ")]}⟩":
            depth -= 1
        elif depth == 0 and source[offset : offset + 2] == ":=":
            signature = source[start:offset]
            colon = signature.rindex(":")
            return signature[colon + 1 :].strip()
    raise ValueError(f"could not read the result type of lean definition {name!r}")


def collect_bindings(fork: str, preset: str, spec_object, types: LeanTypes) -> list[Binding]:
    """Match each Lean definition to the Python signature it replaces."""
    bindings = []
    for name, lean_source in spec_object.lean_functions.items():
        python_source = spec_object.functions.get(name)
        if python_source is None:
            raise ValueError(f"lean block defines {name!r}, which the specification does not")
        function = ast.parse(python_source).body[0]
        assert isinstance(function, ast.FunctionDef)

        try:
            params = [
                (argument.arg, types.require(argument.annotation))
                for argument in function.args.args
            ]
        except UnsupportedType as error:
            raise ValueError(
                f"{name}: parameter type {error} cannot cross the boundary yet"
            ) from error

        returns = ast.unparse(function.returns)
        mutates = None
        if returns == "None":
            if not params:
                raise ValueError(f"{name}: returns None but takes no argument to edit")
            mutates = params[0][0]
            result = params[0][1]
        else:
            try:
                result = types.require(function.returns)
            except UnsupportedType as error:
                raise ValueError(
                    f"{name}: result type {error} cannot cross the boundary yet"
                ) from error

        bindings.append(
            Binding(
                name=name,
                key=f"{fork}/{preset}/{name}",
                params=params,
                result=result,
                mutates=mutates,
                monadic=_lean_return_type(lean_source, name).startswith("SpecM"),
            )
        )
    return bindings


def emit_constants(spec_object, module: ModuleType) -> list[str]:
    """Every constant of the preset, as a Lean definition."""
    names = [
        *spec_object.constant_vars,
        *spec_object.preset_vars,
        *spec_object.preset_dep_constant_vars,
        *spec_object.config_vars,
    ]
    configuration = dict(module.config._asdict())
    lines = []
    for name in dict.fromkeys(names):
        value = configuration.get(name, getattr(module, name, None))
        if isinstance(value, bool):
            lines.append(f"def {name} : Bool := {'true' if value else 'false'}")
        elif isinstance(value, int):
            if 0 <= value < 2**64:
                lines.append(f"def {name} : UInt64 := {value}")
            elif value >= 0:
                lines.append(f"def {name} : Nat := {value}")
        elif isinstance(value, bytes):
            body = ", ".join(str(byte) for byte in value)
            lines.append(f"def {name} : ByteArray := ⟨#[{body}]⟩")
    return lines


def emit_dispatch(bindings: list[Binding]) -> list[str]:
    """A runner per bound function, and the match that selects one."""
    lines = []
    for binding in bindings:
        steps = [f'  Pyspec.check (frames.size == {len(binding.params)}) "wrong argument count"']
        arguments = []
        for index, (_, kind) in enumerate(binding.params):
            steps.append(f"  let value{index} \u2190 Pyspec.decodeArg {kind.desc} frames[{index}]!")
            arguments.append(kind.reader(f"value{index}"))
        call = " ".join([binding.name, *arguments])
        steps.append(f"  let result {'\u2190' if binding.monadic else ':='} {call}")
        steps.append(
            f"  Pyspec.encodeResult {binding.result.desc} {binding.result.writer('result')}"
        )
        lines.append(
            f"private def run_{binding.name} (frames : Array ByteArray) : ByteArray :=\n"
            "  Pyspec.reply do\n" + "\n".join(f"  {step}" for step in steps)
        )

    arms = "\n".join(
        f'  | "{binding.key}" => some (run_{binding.name} (Pyspec.unframe args))'
        for binding in bindings
    )
    lines.append(
        "/-- Serve one call for this fork and preset. -/\n"
        "def dispatch (key : String) (args : ByteArray) : Option ByteArray :=\n"
        "  match key with\n" + arms + "\n  | _ => none"
    )
    return lines


def generate(
    fork: str,
    preset: str,
    spec_object,
    ordered: dict[str, str],
    module: ModuleType,
    out_dir: Path,
) -> list[Binding]:
    """Write this fork and preset's Lean module. Returns what it binds."""
    types = LeanTypes(spec_object, ordered, module)
    bindings = collect_bindings(fork, preset, spec_object, types)
    if not bindings:
        return []

    name = module_name(fork, preset)
    namespace = f"Pyspec.Spec.{name}"
    body = [
        "import Pyspec.Runtime",
        "",
        f"/-! `{fork}` under the `{preset}` preset, generated from the markdown. -/",
        "",
        f"namespace {namespace}",
        "",
        "/-! Constants of the preset. -/",
        "",
        *emit_constants(spec_object, module),
        "",
        "/-! Types, their SSZ descriptors, and an accessor for every field. -/",
        "",
        "\n\n".join(types.declarations),
        "",
        "/-! Definitions the specification writes in Lean. -/",
        "",
        "\n\n".join(spec_object.lean_functions.values()),
        "",
        "/-! The boundary: decoding arguments, and encoding what comes back. -/",
        "",
        "\n\n".join(emit_dispatch(bindings)),
        "",
        f"end {namespace}",
    ]
    path = out_dir / f"{name}.lean"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(body) + "\n")
    return bindings


def write_root(generated: dict[str, list[Binding]], lean_dir: Path) -> None:
    """Write the module that gathers every fork and exports the entry point."""
    modules = sorted(generated)
    imports = [f"import Pyspec.Generated.{name}" for name in modules]
    attempts = "\n".join(
        f"    match Pyspec.Spec.{name}.dispatch key args with\n"
        f"    | some reply => reply\n"
        f"    | none =>"
        for name in modules
    )
    unknown = '    Pyspec.failure s!"no lean definition bound for {key}"'
    body = [
        *(imports or ["import Pyspec.Runtime"]),
        "",
        "/-! Every fork and preset that defines a function in Lean. -/",
        "",
        "namespace Pyspec.Generated",
        "",
        "/--",
        "Serve one call from Python.",
        "",
        "The key is `<fork>/<preset>/<function>`, the arguments arrive framed, and",
        "the reply is a status byte followed by the result or the reason it failed.",
        "-/",
        "@[export pyspec_dispatch]",
        "def dispatch (key : String) (args : ByteArray) : ByteArray :=",
        *([attempts] if modules else []),
        unknown,
        "",
        "end Pyspec.Generated",
    ]
    path = lean_dir / "Pyspec" / "Generated.lean"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(body) + "\n")


# Python annotations that are not SSZ classes, and the SSZ class to send them as.
PYTHON_COERCIONS = {"bool": "Boolean", "int": "Uint64"}
# A result declared as a plain Python type comes back as the SSZ class that
# carried it, and has to be handed on as the type the specification declares.
RESULT_COERCIONS = {"bool": "bool", "int": "int"}

LEAN_RUNTIME_BLOCK = '''
import ctypes
import os
import sys
from pathlib import Path

# The compiled Lean specification, and the calls that reach it.
_LEAN_DEFAULT_PATH = Path(__file__).resolve().parents[5] / "lean" / ".lake" / "build" / "libpyspec"


class _LeanLibrary:
    """The Lean library, opened on first use."""

    def __init__(self) -> None:
        self._library = None

    def _open(self) -> ctypes.CDLL:
        path = os.environ.get("PYSPEC_LEAN_LIB")
        if path is None:
            suffix = ".dylib" if sys.platform == "darwin" else ".so"
            path = str(_LEAN_DEFAULT_PATH.with_suffix(suffix))
        if not Path(path).exists():
            raise RuntimeError(
                f"the lean specification is not built: {path} is missing. Run 'make lean'."
            )
        library = ctypes.CDLL(path)
        library.pyspec_call.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
        library.pyspec_call.restype = ctypes.c_void_p
        library.pyspec_size.argtypes = [ctypes.c_void_p]
        library.pyspec_size.restype = ctypes.c_size_t
        library.pyspec_data.argtypes = [ctypes.c_void_p]
        library.pyspec_data.restype = ctypes.c_void_p
        library.pyspec_release.argtypes = [ctypes.c_void_p]
        library.pyspec_release.restype = None
        self._library = library
        return library

    def invoke(self, key: str, payload: bytes) -> bytes:
        """Call into Lean, copying the reply out before releasing it."""
        library = self._library or self._open()
        reply = library.pyspec_call(key.encode(), payload, len(payload))
        try:
            size = library.pyspec_size(reply)
            return ctypes.string_at(library.pyspec_data(reply), size)
        finally:
            library.pyspec_release(reply)


_lean_library = _LeanLibrary()


def _lean_call(key, arguments, result_type):
    """
    Run a spec function that the specification defines in Lean.

    Arguments go over as a run of frames, each a four-byte little-endian length
    and that many bytes of SSZ. The reply is a status byte, then the encoded
    result, or the reason a spec assertion refused it.
    """
    frames = []
    for declared, value in arguments:
        encoded = bytes(ssz_serialize(value if isinstance(value, declared) else declared(value)))
        frames.append(len(encoded).to_bytes(4, "little") + encoded)
    reply = _lean_library.invoke(key, b"".join(frames))
    if not reply:
        raise RuntimeError(f"the lean specification returned nothing for {key}")
    if reply[0] != 0:
        raise AssertionError(reply[1:].decode("utf-8", "replace"))
    return ssz_deserialize(result_type, reply[1:])


def _lean_copy(target, source) -> None:
    """Copy a returned value back over the argument the caller passed in."""
    for name in type(target).model_fields:
        setattr(target, name, getattr(source, name))
'''


def _python_header(source: str) -> list[str]:
    """The signature and docstring of a function, as source lines."""
    function = ast.parse(source).body[0]
    assert isinstance(function, ast.FunctionDef)
    lines = source.split("\n")
    first = function.body[0]
    is_docstring = (
        isinstance(first, ast.Expr)
        and isinstance(first.value, ast.Constant)
        and isinstance(first.value.value, str)
    )
    return lines[: first.end_lineno] if is_docstring else lines[: first.lineno - 1]


def _ssz_class(annotation: str) -> str:
    return PYTHON_COERCIONS.get(annotation, annotation)


def _call(key: str, arguments: str, result: str, indent: str) -> list[str]:
    """The call across the boundary, laid out at the given indent."""
    return [
        f"{indent}_lean_call(",
        f'{indent}    "{key}",',
        f"{indent}    ({arguments},),",
        f"{indent}    {result},",
        f"{indent})",
    ]


def emit_python(fork: str, preset: str, spec_object) -> tuple[dict[str, str], str]:
    """
    Rewrite each Lean-defined function to call across the boundary.

    Returns the replacement sources, and the runtime block the module needs.
    """
    if not spec_object.lean_functions:
        return {}, ""

    replacements = {}
    for name in spec_object.lean_functions:
        source = spec_object.functions[name]
        function = ast.parse(source).body[0]
        assert isinstance(function, ast.FunctionDef)

        arguments = ", ".join(
            f"({_ssz_class(ast.unparse(argument.annotation))}, {argument.arg})"
            for argument in function.args.args
        )
        returns = ast.unparse(function.returns)
        key = f"{fork}/{preset}/{name}"

        if returns == "None":
            # The function edits its first argument, so Lean hands back the new
            # value and it is copied over the one the caller passed in.
            first = function.args.args[0]
            result = _ssz_class(ast.unparse(first.annotation))
            body = [
                "    _lean_copy(",
                f"        {first.arg},",
                *_call(key, arguments, result, "        "),
                "    )",
            ]
            body[-2] += ","
        elif returns in RESULT_COERCIONS:
            # The result travels as an SSZ value, but the specification declares
            # it as a plain Python type.
            body = [
                f"    return {RESULT_COERCIONS[returns]}(",
                *_call(key, arguments, _ssz_class(returns), "        "),
                "    )",
            ]
        else:
            lines = _call(key, arguments, _ssz_class(returns), "    ")
            body = [f"    return {lines[0].lstrip()}", *lines[1:]]

        replacements[name] = "\n".join([*_python_header(source), *body])

    return replacements, LEAN_RUNTIME_BLOCK

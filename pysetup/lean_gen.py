"""
Generate the Lean side of the specification, and the Python that calls into it.

A function the markdown defines in a ```lean block is compiled rather than
executed: the generated Python keeps the signature and docstring the spec gives
it, serializes its arguments, and calls the Lean library across the FFI.

Everything the Lean author writes against is generated from the same markdown:
a structure for every type, its SSZ descriptor, and every constant of the
preset. Only the definitions themselves are written by hand.
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

# The SSZ base types, so that a Lean signature can be spelled the way the Python
# one is. Every unsigned integer is a natural: a definition works with them
# unbounded, and their width is checked where they are written back.
BASE_ALIASES = [
    "abbrev Boolean := Bool",
    "abbrev Byte := Nat",
    *(f"abbrev Uint{bits} := Nat" for bits in (8, 16, 32, 64, 128, 256)),
    *(f"abbrev Bytes{size} := ByteArray" for size in (1, 4, 8, 20, 31, 32, 48, 96)),
]


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
    # Set when the Lean definition returns Result, so its result must be bound.
    monadic: bool


class UnsupportedType(Exception):
    """A type that cannot cross the boundary, named so the author can see why."""


def module_name(fork: str, preset: str) -> str:
    """The Lean module a fork and preset are generated into."""
    return f"{fork.capitalize()}{preset.capitalize()}"


def namespace_of(fork: str, preset: str) -> str:
    """The namespace its definitions live in."""
    return f"Spec.{fork.capitalize()}.{preset.capitalize()}"


def _uint(width_bits: int) -> LeanType:
    return LeanType(
        desc=SCALAR_DESCS[f"Uint{width_bits}"],
        lean="Nat",
        read="(Spec.asNat {})",
        write="(Ssz.Value.uint {})",
    )


BOOL_TYPE = LeanType(
    desc="Ssz.Desc.bool", lean="Bool", read="(Spec.asBool {})", write="(Ssz.Value.bool {})"
)
BYTES_READ = LeanType(
    desc="", lean="ByteArray", read="(Spec.asBytes {})", write="(Spec.ofBytes {})"
)
BITS_READ = LeanType(desc="", lean="Array Bool", read="(Spec.asBits {})", write="(Spec.ofBits {})")


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
            if head == "Optional":
                return self._optional(self.translate(parts[0]))
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
    def _optional(element: LeanType) -> LeanType:
        """
        A value that may be absent, which SSZ has no shape for.

        It crosses as a list that holds at most one element, so that `none` is
        the empty list and `some` is the list holding the value.
        """
        return LeanType(
            desc=f"(Ssz.Desc.list {element.desc} 1)",
            lean=f"(Option {element.lean})",
            read="(((Spec.asElements {}).map (fun element => "
            + element.reader("element")
            + "))[0]?)",
            write="(Spec.ofElements (match {} with | some element => #["
            + element.writer("element")
            + "] | none => #[]))",
        )

    @staticmethod
    def _sequence(desc: str, element: LeanType) -> LeanType:
        return LeanType(
            desc=desc,
            lean=f"(Sequence {element.lean})",
            read="(Sequence.mk ((Spec.asElements {}).map (fun element => "
            + element.reader("element")
            + ")))",
            write="(Spec.ofElements ((({}).elements).map (fun element => "
            + element.writer("element")
            + ")))",
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

        declaration = [f"structure {name} where"]
        declaration += [f"  {field} : {kind.lean}" for field, kind in fields]
        declaration.append("  deriving Repr, BEq")

        written = ", ".join(kind.writer(f"self.{field}") for field, kind in fields)
        read = "\n".join(
            f"    {field} := {kind.reader(f'(Spec.field value {index})')}"
            for index, (field, kind) in enumerate(fields)
        )
        self.declarations += [
            f"def Descs.{name} : Ssz.Desc :=\n  {desc}",
            f"/-- `{name}`, as the specification declares it. -/\n" + "\n".join(declaration),
            f"def {name}.toValue (self : {name}) : Ssz.Value :=\n  .seq [{written}]",
            f"def {name}.ofValue (value : Ssz.Value) : {name} :=\n  {{\n{read}\n  }}",
            (
                f"/-- The default `{name}`, which is what `empty()` gives in Python. -/\n"
                f"def {name}.empty : {name} := {name}.ofValue (Spec.defaultOf Descs.{name})"
            ),
            f"instance : Inhabited {name} := {{ default := {name}.empty }}",
        ]
        self.table[name] = LeanType(
            desc=f"Descs.{name}",
            lean=name,
            read=f"({name}.ofValue {{}})",
            write="({}).toValue",
        )


def _class_body_value(cls: ast.ClassDef, name: str) -> str | None:
    for statement in cls.body:
        if isinstance(statement, ast.Assign) and getattr(statement.targets[0], "id", None) == name:
            return ast.unparse(statement.value)
    return None


# How a Lean type is spelled when the generated Python declares it.
LEAN_TO_PYTHON = {"Bool": "bool", "Nat": "int"}

OPENERS, CLOSERS = "([{\u27e8", ")]}\u27e9"


class LeanSignature(NamedTuple):
    """What a Lean definition declares about itself."""

    params: list[tuple[str, str]]
    returns: str
    doc: str | None


def _top_level(text: str, start: int = 0):
    """Walk a string, yielding each index that sits outside every bracket."""
    depth = 0
    for index in range(start, len(text)):
        character = text[index]
        if character in OPENERS:
            depth += 1
        elif character in CLOSERS:
            depth -= 1
        elif depth == 0:
            yield index


def parse_lean_signature(source: str, name: str) -> LeanSignature:
    """Read a Lean definition's parameters, result and doc comment."""
    start = source.index(f"def {name}")

    doc = None
    preamble = source[:start].rstrip()
    if preamble.endswith("-/") and "/--" in preamble:
        doc = preamble[preamble.rindex("/--") + 3 : preamble.rindex("-/")].strip()

    body = next(
        (index for index in _top_level(source, start) if source[index : index + 2] == ":="), None
    )
    if body is None:
        raise ValueError(f"lean definition {name!r} has no body")
    signature = source[start:body]

    colon = None
    for index in _top_level(signature):
        if signature[index] == ":" and signature[index : index + 2] != ":=":
            colon = index
    if colon is None:
        raise ValueError(f"lean definition {name!r} declares no result type")

    params = []
    for group in re.findall(r"\(([^()]*)\)", signature[:colon]):
        if ":" not in group:
            continue
        declared, _, annotation = group.partition(":")
        params += [(argument, annotation.strip()) for argument in declared.split()]

    return LeanSignature(params, signature[colon + 1 :].strip(), doc)


class Facade(NamedTuple):
    """The Python face of a Lean definition: what callers and tests still see."""

    name: str
    key: str
    params: list[tuple[str, str]]
    returns: str
    doc: str | None
    # The Python block, where the specification still carries one.
    source: str | None


def _spec_name(lean_type: str) -> str:
    """The name the specification knows a Lean type by."""
    inner = lean_type.removeprefix("Option ")
    if inner != lean_type:
        return f"Optional[{_spec_name(inner.strip())}]"
    return LEAN_TO_PYTHON.get(lean_type, lean_type)


def facade_of(fork: str, preset: str, name: str, spec_object) -> Facade:
    """
    Work out what the generated Python declares for a Lean definition.

    A specification that still carries the Python block is taken at its word. One
    that has dropped it has its signature read off the Lean instead: a definition
    whose result is the type of its first argument is one that edits it, which is
    what `-> None` means on the Python side.
    """
    key = f"{fork}/{preset}/{name}"
    source = spec_object.functions.get(name)
    if source is not None:
        function = ast.parse(source).body[0]
        assert isinstance(function, ast.FunctionDef)
        params = [(a.arg, ast.unparse(a.annotation)) for a in function.args.args]
        return Facade(name, key, params, ast.unparse(function.returns), None, source)

    signature = parse_lean_signature(spec_object.lean_functions[name], name)
    params = [(argument, _spec_name(annotation)) for argument, annotation in signature.params]
    result = _spec_name(signature.returns.removeprefix("Result").strip())
    returns = "None" if params and result == params[0][1] else result
    return Facade(name, key, params, returns, signature.doc, None)


def collect_bindings(fork: str, preset: str, spec_object, types: LeanTypes) -> list[Binding]:
    """Match each Lean definition to the Python face the generated module keeps."""
    bindings = []
    for name, lean_source in spec_object.lean_functions.items():
        facade = facade_of(fork, preset, name, spec_object)

        def resolve(annotation: str, what: str, fn: str = name) -> LeanType:
            try:
                return types.require(ast.parse(annotation).body[0].value)
            except UnsupportedType as error:
                raise ValueError(f"{fn}: {what} {error} cannot cross the boundary yet") from error

        for argument, annotation in facade.params:
            if OPTIONAL_TYPE.match(annotation):
                raise ValueError(f"{name}: parameter {argument} may not be optional")
        params = [
            (argument, resolve(annotation, "parameter type"))
            for argument, annotation in facade.params
        ]
        if facade.returns == "None":
            if not params:
                raise ValueError(f"{name}: returns None but takes no argument to edit")
            mutates, result = params[0][0], params[0][1]
        else:
            mutates, result = None, resolve(facade.returns, "result type")

        bindings.append(
            Binding(
                name=name,
                key=facade.key,
                params=params,
                result=result,
                mutates=mutates,
                monadic=parse_lean_signature(lean_source, name).returns.startswith("Result"),
            )
        )
    return bindings


def record_type(name: str) -> str:
    """The Lean structure a list-of-records constant holds entries of."""
    return "".join(part.capitalize() for part in name.split("_")) + "Entry"


def _emit_records(name: str, fields: list[str], entries) -> list[str]:
    """A constant that holds a list of records, as a structure and an array."""
    kind = record_type(name)
    declaration = [f"structure {kind} where"]
    declaration += [f"  {field} : Nat" for field in fields]
    declaration.append("  deriving Repr, BEq")
    rows = [
        "{ " + ", ".join(f"{field} := {int(entry[field])}" for field in fields) + " }"
        for entry in entries
    ]
    return [
        "\n".join(declaration),
        f"def {name} : Array {kind} :=\n  #[" + ", ".join(rows) + "]",
    ]


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
        if fields := spec_object.record_fields.get(name):
            lines += _emit_records(name, fields, value or ())
        elif isinstance(value, bool):
            lines.append(f"def {name} : Bool := {'true' if value else 'false'}")
        elif isinstance(value, int) and value >= 0:
            lines.append(f"def {name} : Nat := {value}")
        elif isinstance(value, bytes):
            body = ", ".join(str(byte) for byte in value)
            lines.append(f"def {name} : ByteArray := ByteArray.mk #[{body}]")
    return lines


def emit_dispatch(bindings: list[Binding]) -> list[str]:
    """A runner per bound function, and the match that selects one."""
    lines = []
    for binding in bindings:
        steps = [f'  Spec.assert (frames.size == {len(binding.params)}) "wrong argument count"']
        arguments = []
        for index, (_, kind) in enumerate(binding.params):
            steps.append(f"  let value{index} <- Spec.decodeArg {kind.desc} frames[{index}]!")
            arguments.append(kind.reader(f"value{index}"))
        call = " ".join([binding.name, *arguments])
        steps.append(f"  let result {'<-' if binding.monadic else ':='} {call}")
        steps.append(f"  Spec.encodeResult {binding.result.desc} {binding.result.writer('result')}")
        lines.append(
            f"private def run_{binding.name} (frames : Array ByteArray) : ByteArray :=\n"
            "  Spec.reply do\n" + "\n".join(f"  {step}" for step in steps)
        )

    arms = "\n".join(
        f'  | "{binding.key}" => some (run_{binding.name} (Spec.unframe args))'
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
    namespace = namespace_of(fork, preset)
    body = [
        "import Spec.Runtime",
        "",
        f"/-! `{fork}` under the `{preset}` preset, generated from the markdown. -/",
        "",
        f"namespace {namespace}",
        "",
        "/-! Constants of the preset. -/",
        "",
        *emit_constants(spec_object, module),
        "",
        "/-! Types as the specification declares them, and their SSZ descriptors. -/",
        "",
        "\n".join(BASE_ALIASES),
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


def write_root(generated: dict[tuple[str, str], list[Binding]], lean_dir: Path) -> None:
    """Write the module that gathers every fork and exports the entry point."""
    targets = sorted(generated)
    imports = [f"import Spec.Generated.{module_name(*target)}" for target in targets]
    attempts = "\n".join(
        f"    match {namespace_of(*target)}.dispatch key args with\n"
        f"    | some reply => reply\n"
        f"    | none =>"
        for target in targets
    )
    unknown = '    Spec.failure s!"no lean definition bound for {key}"'
    body = [
        *(imports or ["import Spec.Runtime"]),
        "",
        "/-! Every fork and preset that defines a function in Lean. -/",
        "",
        "namespace Spec.Generated",
        "",
        "/--",
        "Serve one call from the caller.",
        "",
        "The key is `<fork>/<preset>/<function>`, the arguments arrive framed, and",
        "the reply is a status byte followed by the result or the reason it failed.",
        "-/",
        "@[export spec_dispatch]",
        "def dispatch (key : String) (args : ByteArray) : ByteArray :=",
        *([attempts] if targets else []),
        unknown,
        "",
        "end Spec.Generated",
    ]
    path = lean_dir / "Spec" / "Generated.lean"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(body) + "\n")


# Python annotations that are not SSZ classes, and the SSZ class to send them as.
PYTHON_COERCIONS = {"bool": "Boolean", "int": "Uint64"}
OPTIONAL_TYPE = re.compile(r"^Optional\[(.+)\]$")
# A result declared as a plain Python type comes back as the SSZ class that
# carried it, and has to be handed on as the type the specification declares.
RESULT_COERCIONS = {"bool": "bool", "int": "int"}

LEAN_RUNTIME_BLOCK = '''
import ctypes
import os
import sys
from functools import cache
from pathlib import Path

# The compiled Lean specification, and the calls that reach it.
_LEAN_LIBRARY_PATH = Path(__file__).resolve().parents[5] / "lean" / ".lake" / "build" / "libspec"


class _LeanLibrary:
    """The Lean library, opened on first use."""

    def __init__(self) -> None:
        self._library = None

    def _open(self) -> ctypes.CDLL:
        path = os.environ.get("LEAN_SPEC_LIB")
        if path is None:
            suffix = ".dylib" if sys.platform == "darwin" else ".so"
            path = str(_LEAN_LIBRARY_PATH.with_suffix(suffix))
        if not Path(path).exists():
            raise RuntimeError(
                f"the lean specification is not built: {path} is missing. Run 'make lean'."
            )
        library = ctypes.CDLL(path)
        library.spec_call.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
        library.spec_call.restype = ctypes.c_void_p
        library.spec_size.argtypes = [ctypes.c_void_p]
        library.spec_size.restype = ctypes.c_size_t
        library.spec_data.argtypes = [ctypes.c_void_p]
        library.spec_data.restype = ctypes.c_void_p
        library.spec_release.argtypes = [ctypes.c_void_p]
        library.spec_release.restype = None
        self._library = library
        return library

    def invoke(self, key: str, payload: bytes) -> bytes:
        """Call into Lean, copying the reply out before releasing it."""
        library = self._library or self._open()
        reply = library.spec_call(key.encode(), payload, len(payload))
        try:
            size = library.spec_size(reply)
            return ctypes.string_at(library.spec_data(reply), size)
        finally:
            library.spec_release(reply)


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


@cache
def _lean_optional(element):
    """The SSZ type an `Optional` crosses as: a list holding at most one element."""
    return type(f"Optional{element.__name__}", (List[element],), {"LIMIT": 1})


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
    if match := OPTIONAL_TYPE.match(annotation):
        return f"_lean_optional({_ssz_class(match.group(1))})"
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


def _header(facade: Facade) -> list[str]:
    """The signature and docstring the generated module declares."""
    if facade.source is not None:
        return _python_header(facade.source)

    arguments = ", ".join(f"{argument}: {annotation}" for argument, annotation in facade.params)
    lines = [f"def {facade.name}({arguments}) -> {facade.returns}:"]
    if len(lines[0]) > 100:
        lines = [f"def {facade.name}("]
        lines += [f"    {a}: {t}," for a, t in facade.params]
        lines.append(f") -> {facade.returns}:")
    if facade.doc:
        lines.append('    """')
        lines += [f"    {line}".rstrip() for line in facade.doc.splitlines()]
        lines.append('    """')
    return lines


def emit_python(fork: str, preset: str, spec_object) -> tuple[dict[str, str], str]:
    """
    Give each Lean-defined function a Python face that calls across the boundary.

    A specification that still carries the Python block keeps its signature and
    docstring. One that has dropped it has them generated from the Lean.
    """
    if not spec_object.lean_functions:
        return {}, ""

    replacements = {}
    for name in spec_object.lean_functions:
        facade = facade_of(fork, preset, name, spec_object)
        arguments = ", ".join(
            f"({_ssz_class(annotation)}, {argument})" for argument, annotation in facade.params
        )

        if facade.returns == "None":
            # The function edits its first argument, so Lean hands back the new
            # value and it is copied over the one the caller passed in.
            first, annotation = facade.params[0]
            body = [
                "    _lean_copy(",
                f"        {first},",
                *_call(facade.key, arguments, _ssz_class(annotation), "        "),
                "    )",
            ]
            body[-2] += ","
        elif OPTIONAL_TYPE.match(facade.returns):
            # The result travels as a list holding at most one element, which is
            # what the specification declares as `Optional`.
            lines = _call(facade.key, arguments, _ssz_class(facade.returns), "    ")
            body = [f"    result = {lines[0].lstrip()}", *lines[1:]]
            body.append("    return result[0] if len(result) > 0 else None")
        elif facade.returns in RESULT_COERCIONS:
            # The result travels as an SSZ value, but the specification declares
            # it as a plain Python type.
            body = [
                f"    return {RESULT_COERCIONS[facade.returns]}(",
                *_call(facade.key, arguments, _ssz_class(facade.returns), "        "),
                "    )",
            ]
        else:
            lines = _call(facade.key, arguments, _ssz_class(facade.returns), "    ")
            body = [f"    return {lines[0].lstrip()}", *lines[1:]]

        replacements[name] = "\n".join([*_header(facade), *body])

    return replacements, LEAN_RUNTIME_BLOCK

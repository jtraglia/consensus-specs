import functools
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from compiler.languages.base import Declaration, Foreign
from compiler.model import Definition, Kind, References, SpecError

TOOLCHAIN = "leanprover/lean4:v4.34.1"
DEFINITION = re.compile(r"def (\w+)\s")
PARAMETER = re.compile(r"\((\w+) : ([^()]+)\)")
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
RESULT = "Result "
WIDTHS = {"Uint8": 1, "Uint16": 2, "Uint32": 4, "Uint64": 8, "Uint256": 32}

PRELUDE = """\
namespace Spec

abbrev Uint8 := Nat
abbrev Uint16 := Nat
abbrev Uint32 := Nat
abbrev Uint64 := Nat
abbrev Uint256 := Nat

abbrev Result (value : Type) := Except String value

def assert (condition : Bool) : Result Unit :=
  if condition then .ok () else .error "assertion failed"
"""

CODEC = """\
def decode (width : Nat) (bytes : ByteArray) (offset : Nat) : Nat :=
  (List.range width).foldr (fun index total => total * 256 + (bytes.get! (offset + index)).toNat) 0

def encode (width : Nat) (value : Nat) : ByteArray :=
  ByteArray.mk ((Array.range width).map (fun index => ((value >>> (8 * index)) % 256).toUInt8))

def reply (status : UInt8) (payload : ByteArray) : ByteArray :=
  ByteArray.mk #[status] ++ payload

def finish (width : Nat) (value : Nat) : ByteArray :=
  if value < 2 ^ (8 * width) then reply 0 (encode width value)
  else reply 1 "result out of range".toUTF8

def finishResult (width : Nat) (value : Except String Nat) : ByteArray :=
  match value with
  | .ok result => finish width result
  | .error message => reply 1 message.toUTF8
"""

DISPATCH = """\
@[export spec_dispatch]
def dispatch (key : String) (args : ByteArray) : ByteArray :=
  match key with
{arms}
  | _ => reply 2 key.toUTF8
"""

SHIM = """\
#include <lean/lean.h>

#define SPEC_EXPORT __attribute__((visibility("default"), used))

extern void lean_initialize_runtime_module(void);
extern lean_object *initialize_Spec(uint8_t builtin);
extern lean_object *spec_dispatch(lean_object *key, lean_object *args);

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

SPEC_EXPORT size_t spec_size(void *reply) { return lean_sarray_size((lean_object *)reply); }

SPEC_EXPORT const uint8_t *spec_data(void *reply) {
    return lean_sarray_cptr((lean_object *)reply);
}

SPEC_EXPORT void spec_release(void *reply) { lean_dec((lean_object *)reply); }
"""


def _signature(definition: Definition) -> tuple[list[tuple[str, str]], str, bool]:
    header = definition.source.split(":=", 1)[0]
    parameters = [(name, kind.strip()) for name, kind in PARAMETER.findall(header)]
    result = header.rsplit(")", 1)[-1].strip().removeprefix(":").strip()
    return parameters, result.removeprefix(RESULT), result.startswith(RESULT)


def _width(definition: Definition, kind: str) -> int:
    if kind not in WIDTHS:
        raise SpecError(f"{definition.path}: `{definition.name}` uses unsupported type `{kind}`")
    return WIDTHS[kind]


def _arm(definition: Definition) -> str:
    parameters, result, fallible = _signature(definition)
    lines = [f'  | "{definition.name}" =>']
    offset = 0
    for name, kind in parameters:
        lines.append(f"    let {name} := decode {_width(definition, kind)} args {offset}")
        offset += _width(definition, kind)
    call = " ".join([f"Spec.{definition.name}", *(name for name, _ in parameters)])
    finish = "finishResult" if fallible else "finish"
    lines.append(f"    {finish} {_width(definition, result)} ({call})")
    return "\n".join(lines)


def _run(command: list[str], directory: Path | None = None) -> str:
    try:
        completed = subprocess.run(
            command,
            cwd=directory,
            env={**os.environ, "ELAN_TOOLCHAIN": TOOLCHAIN},
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        raise SpecError(
            f"`{command[0]}` is not installed, see https://lean-lang.org/install/"
        ) from None
    if completed.returncode != 0:
        raise SpecError(f"`{' '.join(command)}` failed:\n{completed.stdout}{completed.stderr}")
    return completed.stdout.strip()


@functools.cache
def _libdir() -> str:
    return _run(["lean", "--print-libdir"])


def _compile(module: str, library: Path) -> None:
    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch)
        (work / "Spec.lean").write_text(module)
        (work / "shim.c").write_text(SHIM)
        _run(["lean", "-c", "Spec.c", "Spec.lean"], work)
        link = ["-lleanshared", f"-Wl,-rpath,{_libdir()}"]
        _run(["leanc", "-shared", "-o", "Spec.so", "Spec.c", "shim.c", *link], work)
        library.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(work / "Spec.so", library)


class Lean(Foreign):
    name = "lean"

    def declarations(self, source: str) -> list[Declaration]:
        match = DEFINITION.match(source)
        if match is None:
            raise SpecError(f"expected a `def` in the lean block: {source.splitlines()[0]}")
        return [Declaration(Kind.FUNCTION, match.group(1), source)]

    def references(self, source: str) -> References:
        return frozenset(), frozenset(IDENTIFIER.findall(source))

    def signature(self, definition: Definition) -> tuple[list[tuple[str, str]], str]:
        parameters, result, _ = _signature(definition)
        return parameters, result

    def build(
        self, directory: Path, preset: str, definitions: list[Definition], cache: Path
    ) -> None:
        dispatch = DISPATCH.format(arms="\n".join(_arm(definition) for definition in definitions))
        sources = [definition.source for definition in definitions]
        sections = [PRELUDE, *sources, "end Spec", CODEC, dispatch]
        module = "\n\n".join(section.strip() for section in sections) + "\n"
        (directory / f"{preset}.lean").write_text(module)
        library = cache / f"{hashlib.sha256((TOOLCHAIN + SHIM + module).encode()).hexdigest()}.so"
        if not library.exists():
            _compile(module, library)
        shutil.copy(library, directory / f"{preset}.{self.name}.so")

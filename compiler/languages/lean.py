import re
import shutil
import subprocess
import sys
from pathlib import Path

from compiler.discover import DeclarationError, SpecError
from compiler.languages.base import Foreign, References
from compiler.model import Definition, FUNCTION

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


def _header(source: str) -> str:
    return source.split(":=", 1)[0]


def _width(definition: Definition, kind: str) -> int:
    if kind not in WIDTHS:
        raise DeclarationError(
            f"{definition.path}: `{definition.name}` uses unsupported type `{kind}`"
        )
    return WIDTHS[kind]


def _run(command: list[str], directory: Path) -> str:
    try:
        completed = subprocess.run(
            command, cwd=directory, capture_output=True, text=True, check=False
        )
    except FileNotFoundError:
        raise SpecError(
            f"`{command[0]}` is not installed, see https://lean-lang.org/install/"
        ) from None
    if completed.returncode != 0:
        raise SpecError(f"`{' '.join(command)}` failed:\n{completed.stdout}{completed.stderr}")
    return completed.stdout.strip()


class Lean(Foreign):
    name = "lean"

    def read_declaration(self, source: str) -> tuple[str, str, str | None]:
        match = DEFINITION.match(source)
        if match is None:
            raise DeclarationError(f"expected a `def` in the lean block: {source.splitlines()[0]}")
        return FUNCTION, match.group(1), None

    def split_imports(self, source: str) -> list[tuple[str, str]]:
        raise DeclarationError("lean blocks cannot import")

    def references(self, source: str) -> References:
        return frozenset(), frozenset(IDENTIFIER.findall(source))

    def signature(self, definition: Definition) -> tuple[list[tuple[str, str]], str]:
        header = _header(definition.source)
        parameters = [(name, kind.strip()) for name, kind in PARAMETER.findall(header)]
        result = header.rsplit(")", 1)[-1].strip().removeprefix(":").strip()
        return parameters, result.removeprefix(RESULT)

    def dispatch(self, definition: Definition) -> str:
        parameters, result = self.signature(definition)
        lines = [f'  | "{definition.fork}.{definition.name}" =>']
        offset = 0
        for name, kind in parameters:
            lines.append(f"    let {name} := decode {_width(definition, kind)} args {offset}")
            offset += _width(definition, kind)
        call = " ".join([f"Spec.{definition.name}", *(name for name, _ in parameters)])
        header = _header(definition.source)
        fallible = header.rsplit(")", 1)[-1].strip().removeprefix(":").strip().startswith(RESULT)
        finish = "finishResult" if fallible else "finish"
        lines.append(f"    {finish} {_width(definition, result)} ({call})")
        return "\n".join(lines)

    def build(self, out: Path, definitions: list[Definition]) -> None:
        directory = out / "lean"
        shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir(parents=True)
        dispatcher = "\n".join(self.dispatch(definition) for definition in definitions)
        module = "\n\n".join(
            [
                PRELUDE,
                *(definition.source for definition in definitions),
                "end Spec",
                CODEC,
                (
                    "@[export spec_dispatch]\n"
                    "def dispatch (key : String) (args : ByteArray) : ByteArray :=\n"
                    f"  match key with\n{dispatcher}\n  | _ => reply 2 key.toUTF8"
                ),
            ]
        )
        (directory / "Spec.lean").write_text(module + "\n")
        (directory / "shim.c").write_text(SHIM)
        _run(["lean", "-c", "Spec.c", "Spec.lean"], directory)
        libdir = _run(["lean", "--print-libdir"], directory)
        extension = "dylib" if sys.platform == "darwin" else "so"
        _run(
            [
                "leanc",
                "-shared",
                "-o",
                f"libspec.{extension}",
                "Spec.c",
                "shim.c",
                "-lleanshared",
                f"-Wl,-rpath,{libdir}",
            ],
            directory,
        )

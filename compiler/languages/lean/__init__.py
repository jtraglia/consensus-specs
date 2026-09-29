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

DEFINITION = re.compile(r"def (\w+)\s")
PARAMETER = re.compile(r"\((\w+) : ([^()]+)\)")
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
RESULT = "Result "
WIDTHS = {"Uint8": 1, "Uint16": 2, "Uint32": 4, "Uint64": 8, "Uint256": 32}

FILES = Path(__file__).parent
PRELUDE = (FILES / "prelude.lean").read_text().strip()
CODEC = (FILES / "codec.lean").read_text().strip()
SHIM = (FILES / "shim.c").read_text()
TOOLCHAIN = (FILES / "lean-toolchain").read_text().strip()


def _signature(definition: Definition) -> tuple[list[tuple[str, str]], str, bool]:
    header = definition.source.split(":=", 1)[0]
    parameters = [(name, kind.strip()) for name, kind in PARAMETER.findall(header)]
    result = header.rsplit(")", 1)[-1].strip().removeprefix(":").strip()
    return parameters, result.removeprefix(RESULT), result.startswith(RESULT)


def _width(definition: Definition, kind: str) -> int:
    if kind not in WIDTHS:
        raise SpecError(f"{definition.path}: `{definition.name}` uses unsupported type `{kind}`")
    return WIDTHS[kind]


def _dispatch(definition: Definition) -> str:
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
        arms = "\n".join(_dispatch(definition) for definition in definitions)
        dispatch = (
            "@[export spec_dispatch]\n"
            "def dispatch (key : String) (args : ByteArray) : ByteArray :=\n"
            f"  match key with\n{arms}\n  | _ => reply 2 key.toUTF8\n"
        )
        sources = [definition.source for definition in definitions]
        module = "\n\n".join([PRELUDE, "namespace Spec", *sources, "end Spec", CODEC, dispatch])
        (directory / f"{preset}.lean").write_text(module)
        library = cache / f"{hashlib.sha256((TOOLCHAIN + SHIM + module).encode()).hexdigest()}.so"
        if not library.exists():
            _compile(module, library)
        shutil.copy(library, directory / f"{preset}.{self.name}.so")

#!/bin/sh
#
# Build the Lean specification into a shared library that Python can open.
#
# Lake produces a static archive. Nothing in the shared library references the
# Lean definitions, so every archive member is force-loaded to keep the linker
# from dropping them.
set -e
cd "$(dirname "$0")"

if ! command -v lake >/dev/null 2>&1; then
    echo "error: lake is not installed. See https://lean-lang.org/install/" >&2
    exit 1
fi

case "$(uname -s)" in
    Darwin) EXTENSION=dylib ;;
    *)      EXTENSION=so ;;
esac
LIBDIR=$(lean --print-libdir)

lake build Spec:static ssz/Ssz:static
leanc -c ffi/shim.c -o .lake/build/shim.o

# The generated library is force-loaded so its exports survive -dead_strip. The
# SSZ library is linked normally: only what the specification reaches is pulled in.
leanc -shared -o ".lake/build/libspec.$EXTENSION" .lake/build/shim.o \
    -Wl,-force_load,"$PWD/.lake/build/lib/libSpec_Spec.a" \
    "$PWD/.lake/packages/ssz/lean/.lake/build/lib/libssz_Ssz.a" \
    -lleanshared -Wl,-rpath,"$LIBDIR"

echo "built lean/.lake/build/libspec.$EXTENSION"

"""python -m compiler"""

from __future__ import annotations

import argparse
import sys

from compiler.build import build


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compile consensus-spec markdown files",
    )
    parser.add_argument("--fork", type=str, default=None, help="Build only this fork")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    try:
        out_root = build(only=args.fork, verbose=args.verbose)
    except (ValueError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.verbose:
        print(f"Wrote artifacts under {out_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Generate index.md files for specification directories to enable directory browsing.

Each specification directory gets an index page listing the documents it contains,
providing a GitHub-like directory browsing experience on the documentation site.
The pages are written directly into the docs directory, which is a copy of the
specification sources assembled by the `_copy_docs` make target.
"""

import os
import sys

REPLACEMENTS = {
    "api": "API",
    "bls": "BLS",
    "das": "DAS",
    "p2p": "P2P",
    "ssz": "SSZ",
}


def format_filename_as_title(filename: str) -> str:
    """Convert a filename to a human-readable title."""
    name = filename[:-3] if filename.endswith(".md") else filename

    name = name.replace("-", " ").replace("_", " ")

    formatted_words = []
    for word in name.split():
        lower_word = word.lower()
        if lower_word in REPLACEMENTS:
            formatted_words.append(REPLACEMENTS[lower_word])
        else:
            formatted_words.append(word.title())

    return " ".join(formatted_words)


def list_dir(dir_path: str) -> tuple[list[str], list[str]]:
    """Return the markdown files and subdirectories of a directory."""
    files = []
    subdirs = []

    if os.path.exists(dir_path):
        for item in sorted(os.listdir(dir_path)):
            item_path = os.path.join(dir_path, item)
            if os.path.isdir(item_path):
                subdirs.append(item)
            elif item.endswith(".md") and item != "index.md":
                files.append(item)

    return files, subdirs


def generate_spec_index(dir_path: str, level: int = 1, prefix: str = "") -> str:
    """Generate index content for a specification directory.

    The prefix is the path of dir_path relative to the directory that the index
    page is written to, so that links to nested documents resolve correctly.
    """
    files, subdirs = list_dir(dir_path)

    content = ""

    if level == 1:
        content = "# Index\n\n"
        if files:
            content += "## Core\n\n"

    for file in files:
        name = format_filename_as_title(file)
        content += f"- [{name}](./{prefix}{file})\n"

    for subdir in subdirs:
        formatted_name = format_filename_as_title(subdir)
        heading_level = "#" * (level + 1)
        content += f"\n{heading_level} {formatted_name}\n\n"
        subdir_path = os.path.join(dir_path, subdir)
        subdir_content = generate_spec_index(subdir_path, level + 1, f"{prefix}{subdir}/")
        if subdir_content.strip():
            content += subdir_content
        else:
            content += f"*No files in {subdir}/*\n"

    if not files and not subdirs and level == 1:
        content += "*No specification files found in this directory.*\n"

    return content


def main(docs_dir: str) -> None:
    """Write an index page into every fork directory of the specifications."""
    print("Generating specification index pages...")

    specs_dir = os.path.join(docs_dir, "specs")
    if not os.path.isdir(specs_dir):
        print(f"error: specifications directory does not exist: {specs_dir}")
        sys.exit(1)

    _, fork_dirs = list_dir(specs_dir)
    for fork in fork_dirs:
        fork_path = os.path.join(specs_dir, fork)
        index_path = os.path.join(fork_path, "index.md")
        print(f"  - Generating {index_path}")
        with open(index_path, "w") as f:
            f.write(generate_spec_index(fork_path))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "docs")

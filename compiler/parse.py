"""Turn one markdown spec file into a Spec."""

from __future__ import annotations

import ast
import re
import string
from typing import TYPE_CHECKING

from marko.block import BlankLine, FencedCode, Heading, HTMLBlock
from marko.ext.gfm import gfm
from marko.ext.gfm.elements import Table, TableCell, TableRow
from marko.inline import CodeSpan

from compiler.models import NAMED_FIELDS, Spec, Value

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from marko.element import Element

LIST_OF_RECORDS_RE = re.compile(
    r"<!--\s*list-of-records:([a-zA-Z0-9_-]+)(?::(mainnet|minimal))?\s*-->"
)
SAME_TOKEN = "same"
SECTIONS = frozenset(
    {
        "aliases",
        "types",
        "containers",
        "dataclasses",
        "exceptions",
        "presets",
        "configs",
        "constants",
    }
)
CLASS_SECTIONS = frozenset({"aliases", "types", "containers", "dataclasses", "exceptions"})
VARIANT_SECTIONS = frozenset({"presets", "configs"})


def parse_file(path: Path) -> Spec:
    return Parser(path).run()


class Parser:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.spec = Spec()
        self.headings: list[tuple[int, str]] = []
        self.current_name: str | None = None
        self.elements: Iterator[Element] = iter(gfm.parse(path.read_text()).children)

    def run(self) -> Spec:
        while (child := self._next()) is not None:
            if isinstance(child, Heading):
                self._heading(child)
            elif isinstance(child, FencedCode):
                self._code(child)
            elif isinstance(child, Table):
                self._table(child)
            elif isinstance(child, HTMLBlock):
                self._html(child)
        self.spec.assert_unique_names()
        return self.spec

    def _next(self) -> Element | None:
        try:
            while isinstance(result := next(self.elements), BlankLine):
                pass
            return result
        except StopIteration:
            return None

    def _heading(self, heading: Heading) -> None:
        title = _text(heading)
        self.headings = [(level, text) for level, text in self.headings if level < heading.level]
        self.headings.append((heading.level, title))
        last = heading.children[-1]
        self.current_name = last.children if isinstance(last, CodeSpan) else None

    def _section(self) -> str | None:
        for _, title in reversed(self.headings):
            word = title.strip("`").split()[0].lower() if title.strip() else ""
            if word in SECTIONS:
                return word
        return None

    def _code(self, block: FencedCode) -> None:
        if block.lang != "python":
            return
        source = block.children[0].children.strip()
        module = ast.parse(source)
        lines = source.split("\n")
        last_class: tuple[dict[str, str], str] | None = None
        for element in module.body:
            start = (
                element.decorator_list[0].lineno - 1
                if getattr(element, "decorator_list", None)
                else element.lineno - 1
            )
            chunk = "\n".join(line.rstrip() for line in lines[start : element.end_lineno])
            if isinstance(element, ast.FunctionDef):
                self._store("functions", element.name, chunk)
            elif isinstance(element, ast.ClassDef):
                last_class = self._class(chunk, element)
            elif isinstance(element, ast.Assign) and len(element.targets) == 1:
                target = element.targets[0]
                if not isinstance(target, ast.Name):
                    raise ValueError(f"unsupported assignment: {source}")
                if last_class is None:
                    raise ValueError(f"{self.path}: assignment {target.id!r} is not after a class")
                bucket, name = last_class
                bucket[name] += "\n\n" + chunk
            else:
                raise ValueError(f"unrecognized python: {source}")

    def _class(self, source: str, cls: ast.ClassDef) -> tuple[dict[str, str], str]:
        if self.current_name is not None and cls.name != self.current_name:
            raise ValueError(f"class {cls.name} does not match heading {self.current_name}")
        section = self._section()
        bucket_name = section if section in CLASS_SECTIONS else _class_kind(cls)
        self._store(bucket_name, cls.name, source)
        bucket: dict[str, str] = getattr(self.spec, bucket_name)
        return bucket, cls.name

    def _table(self, table: Table) -> None:
        section = self._section()
        if section == "constants":
            parse_row = _constant_row
        elif section in VARIANT_SECTIONS:
            parse_row = _variant_row
        else:
            return
        columns = 3 if section in VARIANT_SECTIONS else 2
        for row in table.children[1:]:
            if len(row.children) < columns:
                continue
            name, value = parse_row(row)
            if not _is_constant_name(name):
                raise ValueError(f"{self.path}: expected constant name, got {name!r}")
            self._store(section, name, value)

    def _html(self, html: HTMLBlock) -> None:
        body = html.body.strip()
        if body == "<!-- eth_consensus_specs: skip -->":
            self._next()
            return
        match = LIST_OF_RECORDS_RE.match(body)
        if not match:
            return
        table = self._next()
        if not isinstance(table, Table):
            raise ValueError(f"expected table after list-of-records, got {type(table)}")
        variant = match.group(2) or "mainnet"
        self._list_of_records(table, match.group(1).upper(), variant)

    def _list_of_records(self, table: Table, name: str, variant: str) -> None:
        header = [
            re.sub(r"\s+", "_", _text(cell).upper()) for cell in table.children[0].children[:-1]
        ]
        rows = [
            {header[i]: _text(cell) for i, cell in enumerate(row.children[:-1])}
            for row in table.children[1:]
        ]
        existing = self.spec.configs.get(name)
        mainnet = existing.mainnet if existing and isinstance(existing.mainnet, list) else []
        minimal = existing.minimal if existing and isinstance(existing.minimal, list) else []
        if variant == "minimal":
            minimal = rows
        else:
            mainnet = rows
        self.spec.configs[name] = Value(mainnet, minimal)

    def _store(self, field: str, name: str, value: object) -> None:
        bucket = getattr(self.spec, field)
        if name in bucket:
            raise ValueError(f"{self.path}: duplicate {name}")
        for other in NAMED_FIELDS:
            if other != field and name in getattr(self.spec, other):
                raise ValueError(f"{self.path}: {name} is already a {other}")
        bucket[name] = value


def _text(node: object) -> str:
    parts: list[str] = []

    def walk(item: object) -> None:
        if isinstance(item, str):
            parts.append(item)
            return
        children = getattr(item, "children", None)
        if isinstance(children, str):
            parts.append(children)
        elif children:
            for child in children:
                walk(child)

    walk(node)
    return "".join(parts).strip()


def _class_kind(cls: ast.ClassDef) -> str:
    if any(
        (isinstance(deco, ast.Name) and deco.id == "dataclass")
        or (
            isinstance(deco, ast.Call)
            and isinstance(deco.func, ast.Name)
            and deco.func.id == "dataclass"
        )
        for deco in cls.decorator_list
    ):
        return "dataclasses"
    if (
        cls.bases
        and isinstance(cls.bases[0], ast.Name)
        and cls.bases[0].id
        in {
            "Exception",
            "BaseException",
        }
    ):
        return "exceptions"
    raise ValueError(f"class {cls.name} is not under a known heading")


def _is_constant_name(name: str) -> bool:
    if not name or name[0] not in string.ascii_uppercase + "_":
        return False
    return all(c in string.ascii_uppercase + "_" + string.digits for c in name[1:])


def _constant_row(row: TableRow) -> tuple[str, str]:
    cells = list(row.children)
    return _cell_code(cells[0]), _cell_code(cells[1])


def _variant_row(row: TableRow) -> tuple[str, Value]:
    cells = list(row.children)
    name = _cell_code(cells[0])
    if _is_same(_text(cells[1])):
        raise ValueError(f"{name}: Mainnet column cannot use *{SAME_TOKEN}*")
    mainnet = _cell_code(cells[1])
    if _is_same(_text(cells[2])):
        return name, Value(mainnet, mainnet)
    return name, Value(mainnet, _cell_code(cells[2]))


def _is_same(text: str) -> bool:
    return text.strip().lower() == SAME_TOKEN


def _cell_code(cell: TableCell) -> str:
    if cell.children:
        first = cell.children[0]
        if isinstance(first, CodeSpan):
            return first.children
        if hasattr(first, "children"):
            inner = first.children
            if isinstance(inner, str):
                return inner
            if isinstance(inner, list) and inner:
                child = inner[0]
                if isinstance(child, CodeSpan):
                    return child.children
                if hasattr(child, "children") and isinstance(child.children, str):
                    return child.children
    return _text(cell)

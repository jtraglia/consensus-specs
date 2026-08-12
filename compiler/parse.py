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

from compiler.models import Spec, Value

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from marko.element import Element

ANNOTATION_RE = re.compile(r"\(\s*=\s*([\d,]+)")
LIST_OF_RECORDS_RE = re.compile(
    r"<!--\s*list-of-records:([a-zA-Z0-9_-]+)(?::(mainnet|minimal))?\s*-->"
)
SAME_TOKEN = "same"
SECTION_KINDS = {
    "alias": "alias",
    "aliases": "alias",
    "type": "type",
    "types": "type",
    "container": "container",
    "containers": "container",
    "preset": "preset",
    "configuration": "config",
    "constant": "constant",
    "constants": "constant",
}


def parse_file(path: Path) -> Spec:
    return Parser(path).run()


class Parser:
    def __init__(self, path: Path) -> None:
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

    def _section_kind(self) -> str | None:
        for _, title in reversed(self.headings):
            word = title.strip("`").split()[0].lower() if title.strip() else ""
            if word in SECTION_KINDS:
                return SECTION_KINDS[word]
        return None

    def _code(self, block: FencedCode) -> None:
        if block.lang != "python":
            return
        source = block.children[0].children.strip()
        module = ast.parse(source)
        lines = source.split("\n")
        for element in module.body:
            start = (
                element.decorator_list[0].lineno - 1
                if getattr(element, "decorator_list", None)
                else element.lineno - 1
            )
            chunk = "\n".join(line.rstrip() for line in lines[start : element.end_lineno])
            if isinstance(element, ast.FunctionDef):
                self.spec.functions[_function_key(element)] = chunk
            elif isinstance(element, ast.ClassDef):
                self._class(chunk, element)
            elif isinstance(element, ast.Assign) and len(element.targets) == 1:
                target = element.targets[0]
                if not isinstance(target, ast.Name):
                    raise ValueError(f"unsupported assignment: {source}")
                self.spec.instances[target.id] = chunk
            else:
                raise ValueError(f"unrecognized python: {source}")

    def _class(self, source: str, cls: ast.ClassDef) -> None:
        if self.current_name is not None and cls.name != self.current_name:
            raise ValueError(f"class {cls.name} does not match heading {self.current_name}")
        if self._section_kind() == "alias":
            self.spec.aliases[cls.name] = source
        else:
            self.spec.types[cls.name] = source

    def _table(self, table: Table) -> None:
        kind = self._section_kind()
        if kind not in ("preset", "config", "constant", None):
            return
        header = [_text(cell).strip().lower() for cell in table.children[0].children]
        two_col = len(header) >= 3 and header[1] == "mainnet" and header[2] == "minimal"
        for row in table.children[1:]:
            if len(row.children) < 2:
                continue
            name, mainnet, minimal, ann_main, ann_min = _row_fields(row, two_col)
            if not _is_constant_name(name):
                continue
            value = Value(
                mainnet=mainnet,
                minimal=minimal,
                annotation_mainnet=ann_main,
                annotation_minimal=ann_min,
            )
            if kind == "preset":
                self.spec.presets[name] = value
            elif kind == "config":
                self.spec.configs[name] = value
            else:
                self.spec.constants[name] = value

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
        mainnet = existing.records_mainnet if existing and existing.records_mainnet else []
        minimal = existing.records_minimal if existing and existing.records_minimal else []
        if variant == "minimal":
            minimal = rows
        else:
            mainnet = rows
        self.spec.configs[name] = Value(
            mainnet=_format_records(mainnet),
            minimal=_format_records(minimal),
            records_mainnet=mainnet,
            records_minimal=minimal,
        )


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


def _function_key(fn: ast.FunctionDef) -> str:
    if fn.args.args:
        first = fn.args.args[0]
        if first.arg == "self" and isinstance(first.annotation, ast.Name):
            return f"{first.annotation.id}.{fn.name}"
    return fn.name


def _is_constant_name(name: str) -> bool:
    if not name or name[0] not in string.ascii_uppercase + "_":
        return False
    return all(c in string.ascii_uppercase + "_" + string.digits for c in name[1:])


def _row_fields(row: TableRow, two_col: bool) -> tuple[str, str, str, int | None, int | None]:
    cells = list(row.children)
    name = _cell_code(cells[0])
    mainnet = _cell_code(cells[1])
    ann_main = _annotation(cells[1])
    if two_col:
        if _is_same(_text(cells[1])):
            raise ValueError(f"{name}: Mainnet column cannot use *{SAME_TOKEN}*")
        if _is_same(_text(cells[2])):
            return name, mainnet, mainnet, ann_main, ann_main
        return name, mainnet, _cell_code(cells[2]), ann_main, _annotation(cells[2])
    return name, mainnet, mainnet, ann_main, ann_main


def _is_same(text: str) -> bool:
    return text.strip().lower() == SAME_TOKEN


def _annotation(cell: TableCell) -> int | None:
    match = ANNOTATION_RE.search(_text(cell))
    if match:
        return int(match.group(1).replace(",", ""))
    return None


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


def _format_records(records: list[dict[str, str]]) -> str:
    lines = ["("]
    for record in records:
        lines.append("    frozendict({")
        for key, value in record.items():
            lines.append(f'        "{key}": {value},')
        lines.append("    }),")
    lines.append(")")
    return "\n".join(lines)

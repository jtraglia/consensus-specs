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

COLLECTION_BASES = frozenset(
    {
        "BitList",
        "BitVector",
        "ByteList",
        "ByteVector",
        "List",
        "ProgressiveBitList",
        "ProgressiveList",
        "Vector",
    }
)
SCALAR_BASES = frozenset(
    {
        "Boolean",
        "Byte",
        "Bytes1",
        "Bytes4",
        "Bytes8",
        "Bytes20",
        "Bytes31",
        "Bytes32",
        "Bytes48",
        "Bytes96",
        "Uint8",
        "Uint16",
        "Uint32",
        "Uint64",
        "Uint128",
        "Uint256",
    }
)
BOUND_SAFE_CALLS = frozenset({"active_fields", "ceillog2", "floorlog2", *SCALAR_BASES})
TYPE_PREFIXES = (
    "Uint",
    "BitList",
    "BitVector",
    "ByteList",
    "ByteVector",
    "Bytes",
    "List",
    "ProgressiveBitList",
    "ProgressiveList",
    "Union",
    "Vector",
)
ANNOTATION_RE = re.compile(r"\(\s*=\s*([\d,]+)")
LIST_OF_RECORDS_RE = re.compile(r"<!--\s*list-of-records:([a-zA-Z0-9_-]+)\s*-->")


def parse_file(
    path: Path,
    yaml_presets: dict[str, str],
    yaml_configs: dict[str, str | list],
    preset_name: str,
) -> Spec:
    return _Parser(path, yaml_presets, yaml_configs, preset_name).run()


class _Parser:
    def __init__(
        self,
        path: Path,
        yaml_presets: dict[str, str],
        yaml_configs: dict[str, str | list],
        preset_name: str,
    ) -> None:
        self.yaml_presets = yaml_presets
        self.yaml_configs = yaml_configs
        self.preset_name = preset_name
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
        title = _heading_text(heading)
        self.headings = [(level, text) for level, text in self.headings if level < heading.level]
        self.headings.append((heading.level, title))
        self.current_name = _heading_code_name(heading)

    def _section_kind(self) -> str:
        for _, title in reversed(self.headings):
            key = title.strip("`").split()[0].lower() if title.strip() else ""
            if key == "preset":
                return "preset"
            if key == "configuration":
                return "config"
        return "constant"

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
                self.spec.functions[element.name] = chunk
            elif isinstance(element, ast.ClassDef):
                self._class(chunk, element)
            elif isinstance(element, ast.Assign) and len(element.targets) == 1:
                target = element.targets[0]
                if not isinstance(target, ast.Name):
                    raise ValueError(f"unsupported assignment: {source}")
                self.spec.assignments[target.id] = chunk
            else:
                raise ValueError(f"unrecognized python: {source}")

    def _class(self, source: str, cls: ast.ClassDef) -> None:
        if self.current_name is not None and cls.name != self.current_name:
            raise ValueError(f"class {cls.name} does not match heading {self.current_name}")
        parent = _parent_class(cls)
        if parent in SCALAR_BASES and isinstance(cls.bases[0], ast.Name):
            self.spec.classes[cls.name] = source
            return
        if parent in COLLECTION_BASES or parent == "ProgressiveContainer":
            if _bound_needs_helper(cls):
                return
        self.spec.classes[cls.name] = source

    def _table(self, table: Table) -> None:
        kind = self._section_kind()
        for row in table.children:
            if len(row.children) < 2:
                continue
            name, expression, description, annotation = _row_fields(row)
            if description is not None and description.startswith("<!-- predefined-type -->"):
                continue
            if not _is_constant_name(name):
                if expression.startswith(TYPE_PREFIXES):
                    self.spec.classes[name] = f"class {name}({expression}):\n    pass"
                continue
            value = Value(expression=expression, annotation=annotation)
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
        self._list_of_records(table, match.group(1).upper())

    def _list_of_records(self, table: Table, name: str) -> None:
        header = [
            re.sub(r"\s+", "_", _cell_text(cell).upper())
            for cell in table.children[0].children[:-1]
        ]
        spec_rows = [
            {header[i]: _cell_text(cell) for i, cell in enumerate(row.children[:-1])}
            for row in table.children[1:]
        ]
        type_map: dict[str, str] = {}
        typed = re.compile(r"^(\w+)\(.*\)$")
        for row in spec_rows:
            for key, raw in row.items():
                match = typed.match(raw)
                if match:
                    type_map[key] = match.group(1)

        entries = self.yaml_configs.get(name, spec_rows)
        if not isinstance(entries, list):
            raise ValueError(f"expected a list for {name} in config")
        typed_rows = []
        for entry in entries:
            typed_rows.append(
                {
                    key: f"{type_map[key]}({raw})" if key in type_map else raw
                    for key, raw in entry.items()
                }
            )
        if self.preset_name == "mainnet" and spec_rows != typed_rows:
            raise ValueError(f"list of records mismatch for {name}")
        self.spec.configs[name] = Value(expression=_format_records(typed_rows))


def _heading_text(heading: Heading) -> str:
    parts: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, str):
            parts.append(node)
            return
        children = getattr(node, "children", None)
        if isinstance(children, str):
            parts.append(children)
        elif children:
            for child in children:
                walk(child)

    walk(heading)
    return "".join(parts).strip()


def _heading_code_name(heading: Heading) -> str | None:
    last = heading.children[-1]
    if isinstance(last, CodeSpan):
        return last.children
    return None


def _parent_class(cls: ast.ClassDef) -> str | None:
    if not cls.bases:
        return None
    base = cls.bases[0]
    if isinstance(base, ast.Name):
        return base.id
    if isinstance(base, ast.Subscript):
        return base.value.id
    if isinstance(base, ast.Call):
        return base.func.id
    return None


def _bound_needs_helper(cls: ast.ClassDef) -> bool:
    return any(
        isinstance(node, ast.Call)
        and not (isinstance(node.func, ast.Name) and node.func.id in BOUND_SAFE_CALLS)
        for statement in cls.body
        if isinstance(statement, ast.Assign)
        for node in ast.walk(statement)
    )


def _is_constant_name(name: str) -> bool:
    if not name or name[0] not in string.ascii_uppercase + "_":
        return False
    return all(c in string.ascii_uppercase + "_" + string.digits for c in name[1:])


def _row_fields(row: TableRow) -> tuple[str, str, str | None, int | None]:
    cells = list(row.children)
    name = _cell_code(cells[0])
    value_cell = cells[1]
    expression = _cell_code(value_cell)
    description = _cell_text(cells[2]) if len(cells) >= 3 else None
    annotation = None
    match = ANNOTATION_RE.search(_cell_text(value_cell))
    if match:
        annotation = int(match.group(1).replace(",", ""))
    return name, expression, description, annotation


def _cell_code(cell: TableCell) -> str:
    text = _cell_text(cell)
    # Prefer the first inline code span if present.
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
    return text


def _cell_text(cell: TableCell) -> str:
    parts: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, str):
            parts.append(node)
            return
        children = getattr(node, "children", None)
        if isinstance(children, str):
            parts.append(children)
        elif children:
            for child in children:
                walk(child)

    walk(cell)
    return "".join(parts).strip()


def _format_records(records: list[dict[str, str]]) -> str:
    lines = ["("]
    for record in records:
        lines.append("    frozendict({")
        for key, value in record.items():
            lines.append(f'        "{key}": {value},')
        lines.append("    }),")
    lines.append(")")
    return "\n".join(lines)

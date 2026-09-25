import re
from collections.abc import Iterator
from pathlib import Path

from marko.block import BlankLine, FencedCode, Heading, HTMLBlock, List
from marko.element import Element
from marko.ext.gfm import gfm
from marko.ext.gfm.elements import Table
from marko.inline import CodeSpan

from .discover import DIRECTIVE, parse_directive, REMOVED, SpecError
from .languages import LANGUAGES
from .model import (
    CONFIG,
    CONSTANT,
    Definition,
    Document,
    IMPORT,
    PRESET,
    PRESETS,
    Records,
    TYPE,
    Variable,
)

SECTIONS = {"constants": CONSTANT, "presets": PRESET, "configs": CONFIG}
SECTION = re.compile(r"\b(constants|presets|configs)\b", re.IGNORECASE)
BUILD = re.compile(
    r"<!--\s*eth_consensus_specs:\s*build\s*\n```(\w+)\n(.*?)\n```\s*\n-->", re.DOTALL
)
RECORD_NOTES = ("Date", "Description")
SAME = "same"


def text_of(element: Element | str) -> str:
    if isinstance(element, str):
        return element
    children = getattr(element, "children", "")
    if isinstance(children, str):
        return children
    return "".join(text_of(child) for child in children)


def code_of(element: Element) -> str | None:
    if isinstance(element, CodeSpan):
        return element.children
    children = getattr(element, "children", None)
    if isinstance(children, list):
        for child in children:
            if (code := code_of(child)) is not None:
                return code
    return None


class Parser:
    def __init__(self, path: Path, fork: str) -> None:
        self.path = path
        self.document = Document(path, fork)
        self.headings: list[tuple[int, str, str | None]] = []
        self.records: dict[str, Variable] = {}

    def error(self, message: str) -> SpecError:
        return SpecError(f"{self.path}: {message}")

    def run(self) -> Document:
        elements = iter(
            child
            for child in gfm.parse(self.path.read_text()).children
            if not isinstance(child, BlankLine)
        )
        if self.path.name == REMOVED:
            self.removed(elements)
        else:
            for element in elements:
                self.element(element, elements)
        return self.document

    def element(self, element: Element, elements: Iterator[Element]) -> None:
        match element:
            case Heading():
                self.heading(element)
            case FencedCode():
                self.code(element.lang, element.children[0].children.strip("\n"), build=False)
            case Table():
                self.table(element)
            case HTMLBlock():
                self.html(element.body, elements)

    def heading(self, heading: Heading) -> None:
        last = heading.children[-1] if heading.children else None
        name = last.children if isinstance(last, CodeSpan) else None
        self.headings = [h for h in self.headings if h[0] < heading.level]
        self.headings.append((heading.level, text_of(heading), name))

    def section(self) -> str | None:
        for _, text, _ in reversed(self.headings):
            if match := SECTION.search(text):
                return SECTIONS[match.group(1).lower()]
        return None

    def code(self, lang: str, source: str, build: bool) -> None:
        language = LANGUAGES.get(lang)
        if language is None:
            return
        source = "\n".join(line.rstrip() for line in source.split("\n"))
        try:
            kind, name, receiver = language.read_declaration(source)
        except language.DeclarationError as error:
            raise self.error(str(error)) from None
        if kind == TYPE and not build:
            heading = self.headings[-1][2] if self.headings else None
            if heading is not None and heading != name:
                raise self.error(f"type `{name}` is under the heading for `{heading}`")
        if kind == IMPORT:
            for imported, statement in language.split_imports(source):
                self.document.items.append(
                    Definition(imported, kind, lang, statement, self.document.fork, self.path)
                )
            return
        self.document.items.append(
            Definition(name, kind, lang, source, self.document.fork, self.path, receiver, build)
        )

    def html(self, body: str, elements: Iterator[Element]) -> None:
        body = body.strip()
        if match := BUILD.fullmatch(body):
            self.code(match.group(1), match.group(2), build=True)
            return
        if not DIRECTIVE.fullmatch(body):
            return
        directive = parse_directive(body)
        if "parent" in directive:
            return
        if "skip" in directive:
            next(elements, None)
            return
        if "list-of-records" in directive:
            table = next(elements, None)
            if not isinstance(table, Table):
                raise self.error("expected a table after a list-of-records directive")
            self.list_of_records(table, directive)
            return
        raise self.error(f"unknown directive: {body}")

    def rows(self, table: Table) -> tuple[list[str], list[list[Element]]]:
        header, *rows = table.children
        return [text_of(cell).strip() for cell in header.children], [row.children for row in rows]

    def table(self, table: Table) -> None:
        kind = self.section()
        if kind is None:
            return
        header, rows = self.rows(table)
        if kind == CONSTANT:
            expected = ["Name", "Value"]
        else:
            expected = ["Name", *(preset.capitalize() for preset in PRESETS)]
        if header[: len(expected)] != expected:
            raise self.error(f"a {kind} table must start with columns {expected}, not {header}")
        for cells in rows:
            name = code_of(cells[0])
            if name is None:
                raise self.error(f"table row has no name: {text_of(cells[0])}")
            if kind == CONSTANT:
                value = code_of(cells[1])
                if value is None:
                    raise self.error(f"`{name}` has no value")
                values: dict[str, str | Records] = dict.fromkeys(PRESETS, value)
            else:
                values = {}
                same = []
                for preset, cell in zip(PRESETS, cells[1 : 1 + len(PRESETS)], strict=True):
                    value = code_of(cell)
                    if value is None and preset != PRESETS[0] and text_of(cell).strip() == SAME:
                        value = values[PRESETS[0]]
                        same.append(preset)
                    if value is None:
                        raise self.error(f"`{name}` has no {preset} value")
                    values[preset] = value
                self.document.items.append(
                    Variable(name, kind, values, self.document.fork, self.path, tuple(same))
                )
                continue
            self.document.items.append(Variable(name, kind, values, self.document.fork, self.path))

    def list_of_records(self, table: Table, directive: dict[str, str]) -> None:
        name = directive["list-of-records"].upper()
        presets = directive["preset"].split(",") if "preset" in directive else list(PRESETS)
        if unknown := set(presets) - set(PRESETS):
            raise self.error(f"unknown presets for `{name}`: {sorted(unknown)}")
        header, rows = self.rows(table)
        while header and header[-1] in RECORD_NOTES:
            header.pop()
        fields = [re.sub(r"\s+", "_", column.upper()) for column in header]
        records = [
            {field: text_of(cell).strip() for field, cell in zip(fields, cells, strict=False)}
            for cells in rows
        ]
        if name not in self.records:
            variable = Variable(
                name, CONFIG, {preset: [] for preset in PRESETS}, self.document.fork, self.path
            )
            self.records[name] = variable
            self.document.items.append(variable)
        for preset in presets:
            self.records[name].values[preset] = records

    def removed(self, elements: Iterator[Element]) -> None:
        section = None
        for element in elements:
            if isinstance(element, Heading) and element.level == 2:
                section = text_of(element).strip()
                self.document.removed.setdefault(section, [])
            elif isinstance(element, List):
                if section is None:
                    raise self.error("a list of removed items must be under a section")
                for item in element.children:
                    name = code_of(item)
                    if name is None:
                        raise self.error(f"removed item has no name: {text_of(item)}")
                    self.document.removed[section].append(name)


def parse_document(path: Path, fork: str) -> Document:
    return Parser(path, fork).run()

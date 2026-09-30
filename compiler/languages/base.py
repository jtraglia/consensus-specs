import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import NamedTuple

from compiler.model import (
    Definition,
    Group,
    Item,
    Kind,
    PRESETS,
    Records,
    References,
    Shape,
    Spec,
    SpecError,
    Values,
    Variable,
)
from compiler.order import Node, order

SPEC_FIELDS = (
    "functions",
    "types",
    "constants",
    "presets",
    "configs",
    "containers",
    "dataclasses",
)
TYPE_FIELDS = {
    Shape.SCALAR: "types",
    Shape.COLLECTION: "types",
    Shape.CONTAINER: "containers",
    Shape.DATACLASS: "dataclasses",
}


class Declaration(NamedTuple):
    kind: Kind
    name: str
    source: str
    receiver: str | None = None


class Language(ABC):
    name: str

    @abstractmethod
    def declarations(self, source: str) -> list[Declaration]: ...

    @abstractmethod
    def references(self, source: str) -> References: ...


LANGUAGES: dict[str, Language] = {}


def register(language: Language) -> None:
    LANGUAGES[language.name] = language


class Foreign(Language):
    @abstractmethod
    def signature(self, definition: Definition) -> tuple[list[tuple[str, str]], str]: ...

    @abstractmethod
    def build(
        self, directory: Path, preset: str, definitions: list[Definition], cache: Path
    ) -> None: ...


class Target(Language):
    extension: str
    separator: str
    banner: str
    alias: str
    config_reference: str
    foreign_import: str

    @abstractmethod
    def rewrite(self, source: str, replace: Callable[[str], str | None]) -> str: ...

    @abstractmethod
    def shape(self, definition: Definition) -> Shape: ...

    @abstractmethod
    def expression(self, value: str | Records) -> str: ...

    @abstractmethod
    def variable(self, variable: Variable, value: str) -> str: ...

    @abstractmethod
    def configuration(self, configs: list[tuple[str, str | Records]]) -> str: ...

    @abstractmethod
    def protocol(self, name: str, methods: list[str]) -> str: ...

    @abstractmethod
    def header(self, imports: list[str], spec: Spec, preset: str) -> str: ...

    @abstractmethod
    def foreign_function(
        self,
        definition: Definition,
        parameters: list[tuple[str, str]],
        result: str,
        preset: str,
    ) -> str: ...

    @abstractmethod
    def write_forks(self, out: Path, parents: dict[str, str | None]) -> None: ...

    @abstractmethod
    def load(self, out: Path, fork: str, preset: str) -> Mapping[str, object]: ...

    @abstractmethod
    def source(self, definition: Definition) -> str: ...

    @abstractmethod
    def split_expression(self, value: str | Records) -> tuple[str | None, str]: ...

    @abstractmethod
    def literal(self, value: object, expression: str) -> str: ...

    def item_references(self, item: Item) -> References:
        if isinstance(item, Definition):
            return LANGUAGES[item.lang].references(item.source)
        sources = (self.expression(value) for value in item.values.values())
        return frozenset().union(*(self.references(source)[0] for source in sources)), frozenset()

    def write(self, out: Path, spec: Spec) -> Path:
        nodes = order(spec, self.item_references, self.shape)
        directory = out / "specs" / spec.fork
        directory.mkdir(parents=True, exist_ok=True)
        for preset in PRESETS:
            (directory / f"{preset}.{self.extension}").write_text(self.render(spec, nodes, preset))
        for language in LANGUAGES.values():
            if not isinstance(language, Foreign):
                continue
            definitions = [
                item
                for item in spec.items.values()
                if isinstance(item, Definition) and item.lang == language.name
            ]
            if any(item.key in spec.own for item in definitions):
                for preset in PRESETS:
                    language.build(directory, preset, definitions, out / "cache" / language.name)
        return directory

    def render(self, spec: Spec, nodes: list[Node], preset: str) -> str:
        configs = {
            key: item
            for key, item in spec.items.items()
            if isinstance(item, Variable) and item.kind == Kind.CONFIG
        }

        def to_config(name: str) -> str | None:
            return self.config_reference.format(name) if name in configs else None

        def emit(item: Item) -> str:
            if isinstance(item, Variable):
                value = self.expression(item.values[preset])
                return self.variable(item, self.rewrite(value, to_config))
            if item.lang == self.name:
                return self.rewrite(item.source, to_config)
            language = LANGUAGES[item.lang]
            assert isinstance(language, Foreign)
            return self.foreign_function(item, *language.signature(item), preset)

        def text(node: Node) -> str:
            if node.group == Group.ALIAS:
                return self.alias.format(name=node.key, module=spec.lineage[-2])
            if node.group == Group.CONFIGURATION:
                return self.render_configuration(configs, preset)
            if node.group == Group.PROTOCOL:
                return self.protocol(node.key, [emit(item) for item in node.items])
            return emit(node.items[0])

        blocks = [(node.group, text(node)) for node in nodes]
        used: set[str] = set()
        for _, block in blocks:
            used.update(*self.references(block))
        definitions = [item for item in spec.items.values() if isinstance(item, Definition)]
        imports = [item for item in definitions if item.kind == Kind.IMPORT]
        for item in imports:
            if item.fork == spec.fork and item.name not in used:
                raise SpecError(f"{item.path}: `{item.name}` is imported but not used")
        statements = [item.source for item in imports]
        if any(item.lang != self.name for item in definitions):
            statements.append(self.foreign_import)
        return self.header(statements, spec, preset) + self.separator + self.join(blocks) + "\n"

    def render_configuration(self, configs: dict[str, Variable], preset: str) -> str:
        for name, variable in configs.items():
            source = self.expression(variable.values[preset])
            if others := self.references(source)[0] & configs.keys():
                raise SpecError(
                    f"{variable.path}: config `{name}` must not reference other configs: "
                    f"{', '.join(sorted(others))}"
                )
        return self.configuration(
            [(name, variable.values[preset]) for name, variable in configs.items()]
        )

    def join(self, blocks: list[tuple[Group, str]]) -> str:
        text = ""
        previous = None
        for group, block in blocks:
            if previous is None or group != previous[0]:
                if previous is not None:
                    text += self.separator
                text += self.banner.format(group) + self.separator
            elif "\n" not in block and "\n" not in previous[1]:
                text += "\n"
            else:
                text += self.separator
            text += block
            previous = (group, block)
        return text

    def evaluate(self, out: Path, spec: Spec, preset: str) -> Values:
        namespace = self.load(out, spec.fork, preset)
        return {
            key: plain(namespace[key])
            for key, item in spec.items.items()
            if item.kind in (Kind.PRESET, Kind.CONFIG)
        }

    def spec_object(self, out: Path, spec: Spec) -> dict[str, dict]:
        namespaces = {preset: self.load(out, spec.fork, preset) for preset in PRESETS}

        def entry(item: Variable, preset: str) -> list:
            value = namespaces[preset][item.name]
            type_name, text = self.split_expression(item.values[preset])
            if item.kind != Kind.CONSTANT:
                text = self.literal(plain(value), self.expression(item.values[preset]))
            return [type_name or type(value).__name__, text]

        result: dict[str, dict] = {field: {} for field in SPEC_FIELDS}
        for key, item in spec.items.items():
            if isinstance(item, Variable) and item.kind == Kind.CONSTANT:
                result["constants"][key] = entry(item, PRESETS[0])
            elif isinstance(item, Variable):
                field = "presets" if item.kind == Kind.PRESET else "configs"
                result[field][key] = {preset: entry(item, preset) for preset in PRESETS}
            elif item.kind == Kind.FUNCTION:
                result["functions"][key] = (
                    self.source(item) if item.lang == self.name else item.source
                )
            elif item.kind == Kind.TYPE:
                result[TYPE_FIELDS[self.shape(item)]][item.name] = self.source(item)
        return result


def plain(value: object) -> object:
    if isinstance(value, bytes):
        return bytes(value)
    if isinstance(value, str):
        return value
    if isinstance(value, tuple):
        return tuple({key: plain(field) for key, field in record.items()} for record in value)
    assert isinstance(value, int)
    return int(value)


def hex_text(value: bytes, expression: object = None) -> str:
    text = "0x" + value.hex()
    if isinstance(expression, str):
        for literal in re.findall(r"0x[0-9a-fA-F]+", expression):
            if literal.lower() == text:
                return literal
    return text

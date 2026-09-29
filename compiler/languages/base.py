from abc import ABC, abstractmethod
from collections.abc import Callable
from pathlib import Path

from compiler.discover import DeclarationError
from compiler.model import (
    CONFIG,
    CONSTANT,
    Definition,
    FUNCTION,
    IMPORT,
    Item,
    PRESET,
    Records,
    Spec,
    TYPE,
    Variable,
)
from compiler.order import (
    ALIAS,
    CONFIGURATION,
    CONSTANTS,
    CONTAINER,
    DATACLASS,
    Node,
    PRESETS,
    PROTOCOL,
    TITLES,
    TYPE as TYPE_GROUP,
)
from compiler.values import Values

References = tuple[frozenset[str], frozenset[str]]

SPEC_FIELDS = (
    "functions",
    "types",
    "constants",
    "presets",
    "configs",
    "containers",
    "dataclasses",
)

SCALAR = "scalar"
COLLECTION = "collection"
STRUCTURE = "container"
RECORD = "dataclass"


class Language(ABC):
    name: str

    @abstractmethod
    def read_declaration(self, source: str) -> tuple[str, str, str | None]: ...

    @abstractmethod
    def split_imports(self, source: str) -> list[tuple[str, str]]: ...

    @abstractmethod
    def references(self, source: str) -> References: ...

    def item_references(self, item: Item) -> References:
        if isinstance(item, Definition):
            return LANGUAGES[item.lang].references(item.source)
        eager: frozenset[str] = frozenset()
        for value in item.values.values():
            if isinstance(value, str):
                sources = [value]
            else:
                sources = [field for record in value for field in record.values()]
            for source in sources:
                eager |= self.references(source)[0]
        return eager, frozenset()

    def all_references(self, item: Item) -> frozenset[str]:
        eager, deferred = self.item_references(item)
        return eager | deferred


LANGUAGES: dict[str, Language] = {}


def register(language: Language) -> None:
    LANGUAGES[language.name] = language


class Foreign(Language):
    @abstractmethod
    def signature(self, definition: Definition) -> tuple[list[tuple[str, str]], str]: ...

    @abstractmethod
    def build(self, directory: Path, preset: str, definitions: list[Definition]) -> None: ...


class Target(Language):
    separator: str

    # Reading

    @abstractmethod
    def rewrite(self, source: str, replace: Callable[[str], str | None]) -> str: ...

    @abstractmethod
    def shape(self, definition: Definition) -> str: ...

    # Writing

    @abstractmethod
    def config_reference(self, name: str) -> str: ...

    @abstractmethod
    def variable(self, variable: Variable, value: str) -> str: ...

    @abstractmethod
    def configuration(self, configs: list[tuple[str, str | Records]]) -> str: ...

    @abstractmethod
    def protocol(self, name: str, methods: list[str]) -> str: ...

    @abstractmethod
    def alias(self, name: str, module: str) -> str: ...

    @abstractmethod
    def banner(self, title: str) -> str: ...

    @abstractmethod
    def header(self, imports: list[str], spec: Spec, preset: str) -> str: ...

    # Values

    @abstractmethod
    def load(self, out: Path, fork: str, preset: str) -> object: ...

    @abstractmethod
    def lookup(self, module: object, variable: Variable) -> object: ...

    @abstractmethod
    def source(self, definition: Definition) -> str: ...

    @abstractmethod
    def split_expression(self, expression: str) -> tuple[str | None, str]: ...

    @abstractmethod
    def literal(self, value: object, expression: object) -> str: ...

    @abstractmethod
    def constant_hint(self, expression: str) -> str | None: ...

    @abstractmethod
    def records_type(self) -> str: ...

    @abstractmethod
    def foreign_function(
        self,
        definition: Definition,
        parameters: list[tuple[str, str]],
        result: str,
        preset: str,
    ) -> str: ...

    @abstractmethod
    def foreign_imports(self) -> list[str]: ...

    # Shared

    def classify(self, definition: Definition) -> str:
        shape = self.shape(definition)
        if shape == RECORD:
            return DATACLASS
        return TYPE_GROUP if shape == SCALAR else CONTAINER

    def render(self, spec: Spec, nodes: list[Node], preset: str) -> str:
        configs = {
            key: item
            for key, item in spec.items.items()
            if isinstance(item, Variable) and item.kind == CONFIG
        }

        def to_config(name: str) -> str | None:
            return self.config_reference(name) if name in configs else None

        def emit(item: Definition) -> str:
            if item.lang == self.name:
                return self.rewrite(item.source, to_config)
            language = LANGUAGES[item.lang]
            if not isinstance(language, Foreign) or item.kind != FUNCTION:
                raise DeclarationError(f"{item.path}: cannot emit `{item.name}` from {item.lang}")
            return self.foreign_function(item, *language.signature(item), preset)

        blocks: list[tuple[str, str]] = []
        for node in nodes:
            definitions = [item for item in node.items if isinstance(item, Definition)]
            if node.group == ALIAS:
                texts = [self.alias(node.key, spec.lineage[-2])]
            elif node.group == CONFIGURATION:
                texts = [self.render_configuration(configs, preset)]
            elif node.group == PROTOCOL:
                methods = [emit(item) for item in definitions]
                texts = [self.protocol(node.key, methods)]
            elif node.group in (CONSTANTS, PRESETS):
                texts = [
                    self.variable(item, self.rewrite(item.values[preset], to_config))
                    for item in node.items
                    if isinstance(item, Variable) and isinstance(item.values[preset], str)
                ]
            else:
                texts = [emit(item) for item in definitions]
            blocks.extend((node.group, text) for text in texts)

        imports = [
            item
            for item in spec.items.values()
            if isinstance(item, Definition) and item.kind == IMPORT
        ]
        used: set[str] = set()
        for _, text in blocks:
            used.update(*self.references(text))
        for item in imports:
            if item.fork == spec.fork and item.name not in used:
                raise DeclarationError(f"{item.path}: `{item.name}` is imported but not used")
        foreign = any(
            isinstance(item, Definition) and item.lang != self.name for item in spec.items.values()
        )
        statements = [item.source for item in imports]
        header = self.header(
            [*statements, *(self.foreign_imports() if foreign else [])], spec, preset
        )
        return header + self.separator + self.join(blocks) + "\n"

    def render_configuration(self, configs: dict[str, Variable], preset: str) -> str:
        entries: list[tuple[str, str | Records]] = []
        for name, variable in configs.items():
            value = variable.values[preset]
            if isinstance(value, str) and (others := self.references(value)[0] & configs.keys()):
                raise DeclarationError(
                    f"{variable.path}: config `{name}` must not reference other configs: "
                    f"{', '.join(sorted(others))}"
                )
            entries.append((name, value))
        return self.configuration(entries)

    def join(self, blocks: list[tuple[str, str]]) -> str:
        text = ""
        previous = None
        for group, block in blocks:
            if previous is None or group != previous[0]:
                if previous is not None:
                    text += self.separator
                text += self.banner(TITLES[group]) + self.separator
            elif "\n" not in block and "\n" not in previous[1]:
                text += "\n"
            else:
                text += self.separator
            text += block
            previous = (group, block)
        return text

    def evaluate(self, out: Path, spec: Spec, preset: str) -> Values:
        module = self.load(out, spec.fork, preset)
        return {
            key: plain(self.lookup(module, item))
            for key, item in spec.items.items()
            if isinstance(item, Variable) and item.kind in (PRESET, CONFIG)
        }

    def spec_object(self, spec: Spec, preset: str, values: Values) -> dict[str, dict]:
        result: dict[str, dict] = {field: {} for field in SPEC_FIELDS}
        for key, item in spec.items.items():
            if isinstance(item, Variable):
                expression = item.values[preset]
                if item.kind == CONSTANT:
                    assert isinstance(expression, str)
                    type_name, value = self.split_expression(expression)
                    result["constants"][key] = [
                        type_name,
                        value,
                        None,
                        self.constant_hint(expression),
                    ]
                    continue
                if isinstance(expression, str):
                    type_name = self.split_expression(expression)[0]
                else:
                    type_name = self.records_type()
                field = "presets" if item.kind == PRESET else "configs"
                result[field][key] = [type_name, self.literal(values[key], expression), None, None]
            elif item.kind == FUNCTION:
                result["functions"][key] = (
                    self.source(item) if item.lang == self.name else item.source
                )
            elif item.kind == TYPE:
                shape = self.shape(item)
                field = {RECORD: "dataclasses", STRUCTURE: "containers"}.get(shape, "types")
                result[field][item.name] = self.source(item)
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

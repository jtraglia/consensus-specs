from collections.abc import Callable
from dataclasses import dataclass, field

from .discover import SpecError
from .model import (
    CONFIG,
    CONSTANT,
    Definition,
    FUNCTION,
    IMPORT,
    Item,
    METHOD,
    PRESET,
    Spec,
    VALUE,
    Variable,
    WRAPPER,
)

ALIAS = "alias"
TYPE = "type"
CONSTANTS = "constant"
PRESETS = "preset"
CONFIGURATION = "configuration"
CONTAINER = "container"
DATACLASS = "dataclass"
PROTOCOL = "protocol"
CLASS = "class"
VALUES = "value"
HELPER = "helper"
FUNCTIONS = "function"
WRAPPERS = "wrapper"

GROUPS = (
    ALIAS,
    HELPER,
    TYPE,
    PRESETS,
    CONSTANTS,
    CONFIGURATION,
    CONTAINER,
    DATACLASS,
    PROTOCOL,
    CLASS,
    VALUES,
    FUNCTIONS,
    WRAPPERS,
)

References = Callable[[Item], tuple[frozenset[str], frozenset[str]]]
Classify = Callable[[Definition], str]


@dataclass
class Node:
    key: str
    group: str
    items: list[Item] = field(default_factory=list)
    eager: set[str] = field(default_factory=set)
    deferred: set[str] = field(default_factory=set)


def group_of(item: Item, classify: Classify) -> str:
    if isinstance(item, Variable):
        return {CONSTANT: CONSTANTS, PRESET: PRESETS, CONFIG: CONFIGURATION}[item.kind]
    if item.kind == METHOD:
        return PROTOCOL
    if item.kind == FUNCTION:
        return FUNCTIONS
    if item.kind == VALUE:
        return VALUES
    if item.kind == WRAPPER:
        return WRAPPERS
    return CLASS if item.build else classify(item)


def build_nodes(
    spec: Spec, aliases: set[str], references: References, classify: Classify
) -> dict[str, Node]:
    nodes: dict[str, Node] = {}
    owner: dict[str, str] = {}
    for key, item in spec.items.items():
        if item.kind == IMPORT:
            continue
        if key in aliases:
            nodes[key] = Node(key, ALIAS, [item])
            owner[key] = key
            continue
        group = group_of(item, classify)
        if group == CONFIGURATION:
            node_key = CONFIGURATION
        elif group == PROTOCOL:
            assert isinstance(item, Definition)
            assert item.receiver is not None
            node_key = item.receiver
        else:
            node_key = key
        node = nodes.setdefault(node_key, Node(node_key, group))
        node.items.append(item)
        if group != WRAPPERS:
            owner[item.receiver if group == PROTOCOL else item.name] = node_key

    for node in nodes.values():
        if node.group == ALIAS:
            continue
        for item in node.items:
            eager, deferred = references(item)
            for names, targets in ((eager, node.eager), (deferred, node.deferred)):
                for name in names:
                    target = owner.get(name)
                    if target is not None and target != node.key:
                        targets.add(target)
    return nodes


def requirements(nodes: dict[str, Node]) -> dict[str, set[str]]:
    functions = {key for key, node in nodes.items() if node.group == FUNCTIONS}
    needed: dict[str, set[str]] = {}
    for key, node in nodes.items():
        need = set(node.eager)
        if node.group not in (FUNCTIONS, WRAPPERS):
            pending = [reference for reference in need if reference in functions]
            while pending:
                function = nodes[pending.pop()]
                for reference in function.eager | function.deferred:
                    if reference not in need:
                        need.add(reference)
                        if reference in functions:
                            pending.append(reference)
        needed[key] = need
    for key, need in needed.items():
        if nodes[key].group not in (FUNCTIONS, WRAPPERS):
            for reference in need & functions:
                nodes[reference].group = HELPER
    return needed


def order(spec: Spec, aliases: set[str], references: References, classify: Classify) -> list[Node]:
    nodes = build_nodes(spec, aliases, references, classify)
    needed = requirements(nodes)
    rank = {group: index for index, group in enumerate(GROUPS)}
    remaining = dict(nodes)
    emitted: list[Node] = []
    done: set[str] = set()

    def ready() -> list[str]:
        return [key for key in remaining if needed[key] <= done]

    while remaining:
        candidates = ready()
        if not candidates:
            raise SpecError(f"{spec.fork}: definitions depend on each other: {sorted(remaining)}")
        group = min((remaining[key].group for key in candidates), key=rank.__getitem__)
        while batch := [key for key in ready() if remaining[key].group == group]:
            for key in batch:
                emitted.append(remaining.pop(key))
                done.add(key)
    return emitted

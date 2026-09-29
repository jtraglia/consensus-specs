from collections.abc import Callable
from dataclasses import dataclass, field

from .model import Definition, Group, Item, Kind, References, Shape, Spec, SpecError

ReferencesOf = Callable[[Item], References]
ShapeOf = Callable[[Definition], Shape]

KINDS = {
    Kind.CONSTANT: Group.CONSTANT,
    Kind.PRESET: Group.PRESET,
    Kind.CONFIG: Group.CONFIGURATION,
    Kind.METHOD: Group.PROTOCOL,
    Kind.FUNCTION: Group.FUNCTION,
    Kind.VALUE: Group.VALUE,
    Kind.WRAPPER: Group.CACHE,
}
SHAPES = {
    Shape.SCALAR: Group.TYPE,
    Shape.COLLECTION: Group.CONTAINER,
    Shape.CONTAINER: Group.CONTAINER,
    Shape.DATACLASS: Group.DATACLASS,
}
LATE = (Group.FUNCTION, Group.CACHE)


@dataclass
class Node:
    key: str
    group: Group
    items: list[Item] = field(default_factory=list)
    eager: set[str] = field(default_factory=set)
    deferred: set[str] = field(default_factory=set)


def aliases(spec: Spec, references: ReferencesOf) -> set[str]:
    if len(spec.lineage) == 1:
        return set()
    types = {
        key: frozenset().union(*references(item))
        for key, item in spec.items.items()
        if item.kind == Kind.TYPE and not item.build
    }
    redefined = {key for key in types if key in spec.own}
    candidates = set(types) - redefined
    while newly := {key for key in candidates if types[key] & redefined}:
        candidates -= newly
        redefined |= newly
    return candidates


def group_of(item: Item, shape: ShapeOf) -> Group:
    if isinstance(item, Definition) and item.kind == Kind.TYPE:
        return Group.CLASS if item.build else SHAPES[shape(item)]
    return KINDS[item.kind]


def build_nodes(spec: Spec, references: ReferencesOf, shape: ShapeOf) -> dict[str, Node]:
    shared = aliases(spec, references)
    nodes: dict[str, Node] = {}
    owner: dict[str, str] = {}
    for key, item in spec.items.items():
        if item.kind == Kind.IMPORT:
            continue
        if key in shared:
            nodes[key] = Node(key, Group.ALIAS, [item])
            owner[key] = key
            continue
        group = group_of(item, shape)
        if group == Group.PROTOCOL:
            assert isinstance(item, Definition)
            assert item.receiver is not None
            node_key = item.receiver
        elif group == Group.CONFIGURATION:
            node_key = group
        else:
            node_key = key
        nodes.setdefault(node_key, Node(node_key, group)).items.append(item)
        if group != Group.CACHE:
            owner[node_key if group == Group.PROTOCOL else item.name] = node_key

    for node in nodes.values():
        if node.group == Group.ALIAS:
            continue
        for item in node.items:
            eager, deferred = references(item)
            node.eager |= {owner[name] for name in eager if name in owner} - {node.key}
            node.deferred |= {owner[name] for name in deferred if name in owner} - {node.key}
    return nodes


def closure(node: Node, nodes: dict[str, Node], functions: set[str]) -> set[str]:
    need = set(node.eager)
    pending = list(need & functions)
    while pending:
        function = nodes[pending.pop()]
        for reference in (function.eager | function.deferred) - need:
            need.add(reference)
            if reference in functions:
                pending.append(reference)
    return need


def order(spec: Spec, references: ReferencesOf, shape: ShapeOf) -> list[Node]:
    nodes = build_nodes(spec, references, shape)
    functions = {key for key, node in nodes.items() if node.group == Group.FUNCTION}
    needed = {
        key: node.eager if node.group in LATE else closure(node, nodes, functions)
        for key, node in nodes.items()
    }
    early = [needed[key] for key, node in nodes.items() if node.group not in LATE]
    for key in functions & set().union(*early):
        nodes[key].group = Group.HELPER

    remaining = dict(nodes)
    emitted: list[Node] = []
    done: set[str] = set()

    def ready() -> list[str]:
        return [key for key in remaining if needed[key] <= done]

    while remaining:
        candidates = ready()
        if not candidates:
            raise SpecError(f"{spec.fork}: definitions depend on each other: {sorted(remaining)}")
        group = min((remaining[key].group for key in candidates), key=list(Group).index)
        while batch := [key for key in ready() if remaining[key].group == group]:
            emitted.extend(remaining.pop(key) for key in batch)
            done.update(batch)
    return emitted

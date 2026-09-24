from collections.abc import Callable
from dataclasses import dataclass, field

from .discover import SpecError
from .model import CONFIG, Definition, FUNCTION, IMPORT, Item, METHOD, Spec, Variable

ALIAS = "alias"
CONFIGURATION = "configuration"
DEFINITION = "definition"
PROTOCOL = "protocol"
VARIABLE = "variable"

References = Callable[[Item], tuple[frozenset[str], frozenset[str]]]


@dataclass
class Node:
    key: str
    kind: str
    items: list[Item] = field(default_factory=list)
    lazy: bool = False
    eager: set[str] = field(default_factory=set)
    deferred: set[str] = field(default_factory=set)


def build_nodes(spec: Spec, aliases: set[str], references: References) -> dict[str, Node]:
    nodes: dict[str, Node] = {}
    owner: dict[str, str] = {}
    for key, item in spec.items.items():
        if item.kind == IMPORT:
            continue
        if isinstance(item, Variable) and item.kind == CONFIG:
            node = nodes.setdefault(CONFIGURATION, Node(CONFIGURATION, CONFIGURATION))
        elif isinstance(item, Variable):
            node = nodes.setdefault(key, Node(key, VARIABLE))
        elif item.kind == METHOD:
            assert item.receiver is not None
            node = nodes.setdefault(item.receiver, Node(item.receiver, PROTOCOL))
        elif key in aliases:
            nodes[key] = Node(key, ALIAS, [item])
            owner[key] = key
            continue
        else:
            node = nodes.setdefault(key, Node(key, DEFINITION, lazy=item.kind == FUNCTION))
        node.items.append(item)
        owner[item.receiver if isinstance(item, Definition) and item.receiver else item.name] = (
            node.key
        )

    for node in nodes.values():
        if node.kind == ALIAS:
            continue
        for item in node.items:
            eager, deferred = references(item)
            for names, targets in ((eager, node.eager), (deferred, node.deferred)):
                for name in names:
                    target = owner.get(name)
                    if target is not None and target != node.key:
                        targets.add(target)
    return nodes


def order(spec: Spec, aliases: set[str], references: References) -> list[Node]:
    nodes = build_nodes(spec, aliases, references)
    emitted: dict[str, Node] = {}
    visiting: list[str] = []

    position = {key: index for index, key in enumerate(nodes)}

    def visit(key: str) -> None:
        if key in emitted:
            return
        node = nodes[key]
        if key in visiting:
            if node.lazy:
                return
            cycle = [*visiting[visiting.index(key) :], key]
            raise SpecError(f"{spec.fork}: definitions depend on each other: {' -> '.join(cycle)}")
        visiting.append(key)
        needed = node.eager | node.deferred if node.lazy else node.eager
        for reference in sorted(needed, key=position.__getitem__):
            visit(reference)
        visiting.pop()
        emitted[key] = node

    for key, node in nodes.items():
        if not node.lazy:
            visit(key)
    for key, node in nodes.items():
        if node.lazy and key not in emitted:
            emitted[key] = node
    return list(emitted.values())

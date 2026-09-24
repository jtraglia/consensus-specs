from collections.abc import Callable

from .discover import lineage, SpecError
from .model import (
    CONFIG,
    CONSTANT,
    Definition,
    Document,
    Fork,
    FUNCTION,
    Item,
    PRESET,
    Spec,
    TYPE,
    VALUE,
    Variable,
    WRAPPER,
)

REMOVABLE = {
    "Constants": (CONSTANT,),
    "Presets": (PRESET,),
    "Configs": (CONFIG,),
    "Types": (TYPE, VALUE),
    "Containers": (TYPE,),
    "Dataclasses": (TYPE,),
    "Functions": (FUNCTION,),
}


def same_variable(a: Item, b: Item) -> bool:
    return (
        isinstance(a, Variable)
        and isinstance(b, Variable)
        and (a.kind, a.values) == (b.kind, b.values)
    )


def fork_items(documents: list[Document]) -> dict[str, Item]:
    items: dict[str, Item] = {}
    for document in documents:
        for item in document.items:
            existing = items.get(item.key)
            if existing is None:
                items[item.key] = item
                continue
            new_build = isinstance(item, Definition) and item.build
            old_build = isinstance(existing, Definition) and existing.build
            if new_build == old_build and not same_variable(existing, item):
                raise SpecError(f"`{item.key}` is defined in both {existing.path} and {item.path}")
            if new_build and not old_build:
                items[item.key] = item
    return items


def remove(items: dict[str, Item], document: Document) -> None:
    for section, names in document.removed.items():
        if section not in REMOVABLE:
            raise SpecError(f"{document.path}: unknown section `{section}`")
        for name in names:
            item = items.get(name)
            if item is None:
                raise SpecError(f"{document.path}: `{name}` is not defined by an earlier fork")
            if item.kind not in REMOVABLE[section]:
                raise SpecError(f"{document.path}: `{name}` is a {item.kind}, not in {section}")
            del items[name]
            items.pop(f"{name}@{WRAPPER}", None)


def merge(forks: dict[str, Fork], documents: dict[str, list[Document]], fork: str) -> Spec:
    items: dict[str, Item] = {}
    own: set[str] = set()
    chain = lineage(forks, fork)
    for name in chain:
        new = fork_items(documents[name])
        removals = [document for document in documents[name] if document.removed]
        for document in removals:
            for names in document.removed.values():
                if clash := set(names) & set(new):
                    raise SpecError(
                        f"{document.path}: removed items are redefined: {sorted(clash)}"
                    )
        items.update(new)
        for document in removals:
            remove(items, document)
        if name == fork:
            own = set(new)
    return Spec(fork, chain, items, own)


def shared_types(spec: Spec, references: Callable[[Item], frozenset[str]]) -> set[str]:
    if len(spec.lineage) == 1:
        return set()
    types = {
        key: item
        for key, item in spec.items.items()
        if isinstance(item, Definition) and item.kind == TYPE and not item.build
    }
    built_from = {key: references(item) for key, item in types.items()}
    redefined = {key for key in types if key in spec.own}
    candidates = set(types) - redefined
    while newly := {key for key in candidates if built_from[key] & redefined}:
        candidates -= newly
        redefined |= newly
    return candidates

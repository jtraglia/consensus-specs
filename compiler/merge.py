from .discover import lineage
from .model import Document, Fork, Item, Kind, Spec, SpecError, Variable, wrapper_key

REMOVABLE = {
    "Constants": (Kind.CONSTANT,),
    "Presets": (Kind.PRESET,),
    "Configs": (Kind.CONFIG,),
    "Types": (Kind.TYPE, Kind.VALUE),
    "Containers": (Kind.TYPE,),
    "Dataclasses": (Kind.TYPE,),
    "Functions": (Kind.FUNCTION,),
    "Imports": (Kind.IMPORT,),
}


def same_variable(a: Item, b: Item) -> bool:
    return (
        isinstance(a, Variable)
        and isinstance(b, Variable)
        and (a.kind, a.values) == (b.kind, b.values)
    )


def fork_items(documents: list[Document], build: bool) -> dict[str, Item]:
    items: dict[str, Item] = {}
    for document in documents:
        for item in document.items:
            if item.build and not build:
                continue
            existing = items.get(item.key)
            if existing is None or (item.build and not existing.build):
                items[item.key] = item
            elif item.build == existing.build and not same_variable(existing, item):
                raise SpecError(f"`{item.key}` is defined in both {existing.path} and {item.path}")
    return items


def remove(items: dict[str, Item], document: Document, build: bool) -> None:
    for section, names in document.removed.items():
        if section not in REMOVABLE:
            raise SpecError(f"{document.path}: unknown section `{section}`")
        for name in names:
            item = items.pop(name, None)
            if item is None and build:
                raise SpecError(f"{document.path}: `{name}` is not defined by an earlier fork")
            if item is not None and item.kind not in REMOVABLE[section]:
                raise SpecError(f"{document.path}: `{name}` is a {item.kind}, not in {section}")
            items.pop(wrapper_key(name), None)


def merge(
    forks: dict[str, Fork], documents: dict[str, list[Document]], fork: str, build: bool = True
) -> Spec:
    items: dict[str, Item] = {}
    chain = lineage(forks, fork)
    for name in chain:
        new = fork_items(documents[name], build)
        removals = [document for document in documents[name] if document.removed]
        for document in removals:
            for names in document.removed.values():
                if clash := set(names) & set(new):
                    raise SpecError(
                        f"{document.path}: removed items are redefined: {sorted(clash)}"
                    )
        items.update(new)
        for document in removals:
            remove(items, document, build)
    return Spec(fork, chain, items)

"""
SSZ type layer for the consensus specs, built on the `eth-ssz-specs` package.

The upstream package provides the complete SSZ type system. The one adaptation
kept here: containers are mutable, so the spec and tests can prepare and update
state imperatively. Assigned values are coerced into the field's declared type,
matching construction semantics.
"""

from typing import Any

from pydantic import ConfigDict
from ssz import Container as _Container
from ssz.ssz_base import SSZCollection, SSZType


class Container(_Container):
    """SSZ container with mutable, coercing field assignment."""

    model_config = ConfigDict(frozen=False)

    def __setattr__(self, name: str, value: Any) -> None:
        field = type(self).model_fields.get(name)
        if field is not None:
            annotation = field.annotation
            if isinstance(annotation, type) and not isinstance(value, annotation):
                if issubclass(annotation, SSZCollection):
                    value = annotation(data=value)
                elif issubclass(annotation, SSZType):
                    value = annotation(value)
        super().__setattr__(name, value)

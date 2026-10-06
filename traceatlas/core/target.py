"""Target: a concrete thing the investigation is pointed at."""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.enums import EntityType
from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable


@dataclass
class Target:
    case_id: str
    entity_type: EntityType
    value: str
    confidence_hint: float = 1.0
    id: str = field(default_factory=lambda: new_id("target"))

    def to_dict(self) -> dict:
        return to_jsonable(self)

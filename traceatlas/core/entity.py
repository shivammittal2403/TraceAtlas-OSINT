"""Entity: a resolved real-world object observed during investigation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from traceatlas.core.enums import EntityType
from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable
from traceatlas.core.validation import utcnow


@dataclass
class Entity:
    case_id: str
    entity_type: EntityType
    display_name: str
    attributes: dict = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("ent"))
    created_at: datetime = field(default_factory=utcnow)
    observation_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return to_jsonable(self)

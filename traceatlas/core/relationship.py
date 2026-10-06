"""Relationship: a typed, evidenced edge between two entities."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from traceatlas.core.enums import RelationshipType
from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable
from traceatlas.core.validation import require, utcnow


@dataclass
class Relationship:
    case_id: str
    source_entity_id: str
    target_entity_id: str
    relationship_type: RelationshipType
    confidence: float = 0.0
    evidence_ids: list[str] = field(default_factory=list)
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    id: str = field(default_factory=lambda: new_id("rel"))
    created_at: datetime = field(default_factory=utcnow)

    def __post_init__(self) -> None:
        require(0.0 <= self.confidence <= 1.0, "relationship confidence out of range")

    def to_dict(self) -> dict:
        return to_jsonable(self)

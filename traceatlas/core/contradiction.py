"""Contradiction: a recorded conflict between two claims or observations."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from traceatlas.core.enums import RiskLevel
from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable
from traceatlas.core.validation import utcnow


@dataclass
class Contradiction:
    case_id: str
    left_ref: str            # claim/observation id
    right_ref: str
    kind: str                # value | temporal | identity | location | ownership | registration | source_disagreement | historical_current
    severity: RiskLevel = RiskLevel.LOW
    resolved: bool = False
    resolution_note: str = ""
    created_at: datetime = field(default_factory=utcnow)
    id: str = field(default_factory=lambda: new_id("contra"))

    def to_dict(self) -> dict:
        return to_jsonable(self)

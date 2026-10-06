"""Hypothesis: a testable explanation competing with alternatives."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable
from traceatlas.core.validation import utcnow


@dataclass
class Hypothesis:
    case_id: str
    statement: str
    alternative_to: list[str] = field(default_factory=list)  # sibling hypothesis ids
    predicted_observations: list[str] = field(default_factory=list)
    support_score: float = 0.0
    created_at: datetime = field(default_factory=utcnow)
    id: str = field(default_factory=lambda: new_id("hyp"))

    def to_dict(self) -> dict:
        return to_jsonable(self)

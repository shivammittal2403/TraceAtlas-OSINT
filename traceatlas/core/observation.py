"""Observation: a single atomic assertion extracted from one piece of evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable
from traceatlas.core.validation import utcnow


@dataclass
class Observation:
    case_id: str
    evidence_id: str
    predicate: str            # e.g. "domain.resolves_to", "page.mentions"
    subject: str
    obj: str
    attributes: dict = field(default_factory=dict)
    observed_at: datetime = field(default_factory=utcnow)
    id: str = field(default_factory=lambda: new_id("obs"))

    def to_dict(self) -> dict:
        return to_jsonable(self)

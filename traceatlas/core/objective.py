"""Objective: a natural-language goal attached to a case."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from traceatlas.constants import MAX_OBJECTIVE_LENGTH
from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable
from traceatlas.core.validation import require, utcnow


@dataclass
class Objective:
    case_id: str
    text: str
    id: str = field(default_factory=lambda: new_id("obj"))
    created_at: datetime = field(default_factory=utcnow)
    revised_from: str | None = None

    def __post_init__(self) -> None:
        require(bool(self.text.strip()), "objective text must not be empty")
        require(len(self.text) <= MAX_OBJECTIVE_LENGTH, "objective text too long")

    def to_dict(self) -> dict:
        return to_jsonable(self)

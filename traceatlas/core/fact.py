"""Fact: an observation promoted after deterministic validation.

A Fact is still tied to its supporting observations; it never stands alone.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable


@dataclass
class Fact:
    case_id: str
    statement: str
    observation_ids: list[str] = field(default_factory=list)
    confidence: float = 1.0
    id: str = field(default_factory=lambda: new_id("fact"))

    def to_dict(self) -> dict:
        return to_jsonable(self)

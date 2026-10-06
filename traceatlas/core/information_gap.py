"""InformationGap: an explicitly tracked unknown blocking an answer."""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable


@dataclass
class InformationGap:
    case_id: str
    question: str
    blocking_required_answer: bool = False
    candidate_actions: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: new_id("gap"))

    def to_dict(self) -> dict:
        return to_jsonable(self)

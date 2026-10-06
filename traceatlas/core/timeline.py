"""Timeline: ordered container of events for a case."""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable


@dataclass
class Timeline:
    case_id: str
    name: str = "primary"
    event_ids: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: new_id("tl"))

    def to_dict(self) -> dict:
        return to_jsonable(self)

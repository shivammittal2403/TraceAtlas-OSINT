"""Event: something that happened, with four distinct time dimensions.

- event_time:     when it occurred in the world (may be approximate/unknown)
- validity_time:  interval during which the statement held true
- observation_time: when we observed/collected it
- retrieval_time: when our source last served it
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable


@dataclass
class Event:
    case_id: str
    description: str
    entity_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    event_time: datetime | None = None
    event_time_precision: str = "unknown"  # second|minute|hour|day|month|year|unknown
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    observed_at: datetime | None = None
    id: str = field(default_factory=lambda: new_id("evt"))

    def sort_key(self) -> float:
        return self.event_time.timestamp() if self.event_time else float("inf")

    def to_dict(self) -> dict:
        return to_jsonable(self)

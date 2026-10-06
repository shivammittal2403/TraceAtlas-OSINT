"""Source: a catalogued place information can come from."""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.enums import SourceQualification
from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable


@dataclass
class Source:
    name: str
    url: str = ""
    kind: str = "website"          # website | api | registry | dataset | archive | feed
    qualification: SourceQualification = SourceQualification.DOCUMENTED
    requires_credentials: bool = False
    cost_per_query_usd: float = 0.0
    robots_respecting: bool = True
    id: str = field(default_factory=lambda: new_id("src"))

    def to_dict(self) -> dict:
        return to_jsonable(self)

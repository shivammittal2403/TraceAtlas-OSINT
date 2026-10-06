"""Citation: an explicit reference binding a report statement to evidence."""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable


@dataclass
class Citation:
    case_id: str
    statement: str
    evidence_ids: list[str] = field(default_factory=list)
    locator: str = ""       # page/section/paragraph/byte-range within evidence
    id: str = field(default_factory=lambda: new_id("cite"))

    def is_supported(self) -> bool:
        return bool(self.evidence_ids)

    def to_dict(self) -> dict:
        return to_jsonable(self)

"""SourceLineage: where a piece of content originally came from.

Used by the independence engine to detect syndication and copying.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable


@dataclass
class SourceLineage:
    evidence_id: str
    original_source_id: str            # best-known origin
    intermediate_source_ids: list[str] = field(default_factory=list)
    lineage_confidence: float = 0.0
    method: str = "declared"           # declared | citation_analysis | fingerprint | manual
    id: str = field(default_factory=lambda: new_id("lin"))

    def to_dict(self) -> dict:
        return to_jsonable(self)

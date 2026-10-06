"""Artifact: a produced file (report export, graph dump, capture bundle)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable
from traceatlas.core.validation import utcnow


@dataclass
class Artifact:
    case_id: str
    name: str
    artifact_type: str            # report_html | graph_gexf | capture_bundle | ...
    storage_key: str = ""
    sha256: str = ""
    size_bytes: int = 0
    created_at: datetime = field(default_factory=utcnow)
    id: str = field(default_factory=lambda: new_id("art"))

    def to_dict(self) -> dict:
        return to_jsonable(self)

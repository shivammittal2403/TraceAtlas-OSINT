"""Evidence: immutable, hash-addressed record of collected material."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from traceatlas.core.enums import EvidenceTier
from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable
from traceatlas.core.validation import require, utcnow


@dataclass
class EvidenceRecord:
    case_id: str
    tier: EvidenceTier
    sha256: str
    media_type: str = "application/octet-stream"
    size_bytes: int = 0
    storage_key: str = ""
    source_id: str = ""
    connector_id: str = ""
    url: str = ""
    captured_at: datetime = field(default_factory=utcnow)
    derived_from: list[str] = field(default_factory=list)  # parent evidence ids
    id: str = field(default_factory=lambda: new_id("ev"))

    def __post_init__(self) -> None:
        require(len(self.sha256) == 64, "sha256 digest must be 64 hex characters")

    def to_dict(self) -> dict:
        return to_jsonable(self)

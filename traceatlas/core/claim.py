"""Claim: an answer-relevant assertion that must be verified before reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from traceatlas.core.enums import ClaimStatus
from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable
from traceatlas.core.validation import require, utcnow


@dataclass
class Claim:
    case_id: str
    statement: str
    status: ClaimStatus = ClaimStatus.PROPOSED
    confidence: float = 0.0
    evidence_ids: list[str] = field(default_factory=list)
    fact_ids: list[str] = field(default_factory=list)
    contradiction_ids: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=utcnow)
    id: str = field(default_factory=lambda: new_id("claim"))

    def __post_init__(self) -> None:
        require(bool(self.statement.strip()), "claim statement must not be empty")

    @property
    def reportable(self) -> bool:
        """Only verified claims may appear as findings in reports."""
        return self.status == ClaimStatus.VERIFIED

    def to_dict(self) -> dict:
        return to_jsonable(self)

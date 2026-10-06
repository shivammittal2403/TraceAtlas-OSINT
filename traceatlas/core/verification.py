"""Verification records: decisions about claims with reasons and inputs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from traceatlas.core.enums import VerificationDecision
from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable
from traceatlas.core.validation import utcnow


@dataclass
class VerificationRecord:
    case_id: str
    claim_id: str
    decision: VerificationDecision
    rationale: str = ""
    independent_source_count: int = 0
    inputs: dict = field(default_factory=dict)
    verified_by: str = "system"   # or a human reviewer id
    created_at: datetime = field(default_factory=utcnow)
    id: str = field(default_factory=lambda: new_id("ver"))

    def to_dict(self) -> dict:
        return to_jsonable(self)

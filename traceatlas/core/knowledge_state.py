"""KnowledgeState: snapshot of what is known, believed, and unknown."""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.serialization import to_jsonable


@dataclass
class KnowledgeState:
    case_id: str
    verified_claim_ids: list[str] = field(default_factory=list)
    proposed_claim_ids: list[str] = field(default_factory=list)
    contradiction_ids: list[str] = field(default_factory=list)
    gap_ids: list[str] = field(default_factory=list)
    open_hypothesis_ids: list[str] = field(default_factory=list)

    @property
    def answered_ratio(self) -> float:
        total = len(self.verified_claim_ids) + len(self.proposed_claim_ids)
        return len(self.verified_claim_ids) / total if total else 0.0

    def to_dict(self) -> dict:
        return to_jsonable(self)

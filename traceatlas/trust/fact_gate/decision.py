"""Gate result container."""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.trust.model import FactDecision


@dataclass
class GateResult:
    candidate_id: str
    decision: FactDecision
    reasons: list[str] = field(default_factory=list)
    fact_id: str | None = None          # set when a Fact object was produced
    independent_clusters: int = 0
    needs_review: bool = False

    def to_dict(self) -> dict:
        return {"candidate_id": self.candidate_id, "decision": self.decision.value,
                "reasons": list(self.reasons), "fact_id": self.fact_id,
                "independent_clusters": self.independent_clusters,
                "needs_review": self.needs_review}

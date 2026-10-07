"""Dual AI review (§21).

Pass 1 = Primary Analyst, Pass 2 = Independent Skeptic. The skeptic initially
receives ONLY the evidence bundle — never Pass 1's answer — to avoid anchoring.
Outcomes: AGREE / PARTIAL_AGREEMENT / DISAGREE / PASS1_ONLY / PASS2_ONLY /
INSUFFICIENT_EVIDENCE.

Hard rule enforced in code: **AI agreement is not source corroboration.** A
review where both passes agree but the underlying claims lack evidence resolves
to INSUFFICIENT_EVIDENCE and can never upgrade a fact's independence count.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from traceatlas.trust.case_memory import CaseMemory
from traceatlas.trust.model import ReviewOutcome


@dataclass
class ReviewPass:
    reviewer_id: str
    role: str                       # "primary_analyst" | "independent_skeptic"
    statements: list[str] = field(default_factory=list)   # conclusions asserted
    cited_evidence_ids: list[str] = field(default_factory=list)
    concerns: list[str] = field(default_factory=list)


@dataclass
class DualReviewResult:
    subject_id: str
    outcome: ReviewOutcome
    pass1: ReviewPass
    pass2: ReviewPass
    overlap: list[str] = field(default_factory=list)
    disagreements: list[str] = field(default_factory=list)
    corroborated_by_ai_agreement: bool = False   # MUST stay False by design
    explanation: str = ""

    def to_dict(self) -> dict:
        return {"subject_id": self.subject_id, "outcome": self.outcome.value,
                "pass1": self.pass1.role, "pass2": self.pass2.role,
                "overlap": list(self.overlap),
                "disagreements": list(self.disagreements),
                "corroborated_by_ai_agreement": self.corroborated_by_ai_agreement,
                "explanation": self.explanation}


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower().rstrip("."))


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / max(1, len(a | b))


class DualReviewer:
    """Runs the two-pass protocol against a case memory."""

    def __init__(self, memory: CaseMemory) -> None:
        self.memory = memory

    def skeptic_input(self, evidence_ids: list[str]) -> dict:
        """Pass 2 payload: evidence ONLY — deliberately excludes Pass 1 output."""
        bundle = []
        for eid in evidence_ids:
            ev = self.memory.evidence.get(eid)
            if ev:
                bundle.append({"evidence_id": ev.id, "description": ev.description,
                               "source_id": ev.source_id})
        return {"evidence_only": bundle,
                "note": "Pass 2 receives evidence but NOT Pass 1 answer (no anchoring)"}

    def cross_check(self, subject_id: str, p1: ReviewPass, p2: ReviewPass) -> DualReviewResult:
        s1 = {_norm(x) for x in p1.statements}
        s2 = {_norm(x) for x in p2.statements}
        overlap = sorted(s1 & s2)
        disagreements = sorted(s1 ^ s2)

        # Evidence verification: conclusions must cite resolvable evidence.
        ungrounded_1 = [x for x in p1.cited_evidence_ids if x not in self.memory.evidence]
        ungrounded_2 = [x for x in p2.cited_evidence_ids if x not in self.memory.evidence]
        no_evidence = (not p1.cited_evidence_ids or not p2.cited_evidence_ids
                       or ungrounded_1 or ungrounded_2)

        if no_evidence:
            outcome = ReviewOutcome.INSUFFICIENT_EVIDENCE
            expl = ("two AI reviewers agree but evidence absent/unresolvable ⇒ unsupported "
                    "(§40). AI agreement NEVER counts as source corroboration.")
        elif not s1 and not s2:
            outcome = ReviewOutcome.INSUFFICIENT_EVIDENCE
            expl = "neither pass produced conclusions from the evidence bundle"
        else:
            sim = _jaccard(s1, s2)
            if s1 == s2:
                outcome = ReviewOutcome.AGREE
                expl = f"independent convergence on {len(s1)} conclusion(s); still not corroboration"
            elif sim >= 0.34:
                outcome = ReviewOutcome.PARTIAL_AGREEMENT
                expl = "shared core with divergent secondary conclusions"
            elif s1 and s2 and not overlap:
                outcome = ReviewOutcome.DISAGREE
                expl = "passes reached disjoint conclusions; retain disagreement"
            elif s1 and not s2:
                outcome = ReviewOutcome.PASS1_ONLY
                expl = "skeptic drew no conclusion from the same evidence"
            else:
                outcome = ReviewOutcome.PASS2_ONLY
                expl = "primary analyst silent; skeptic-only finding flagged for review"

        return DualReviewResult(
            subject_id=subject_id, outcome=outcome, pass1=p1, pass2=p2,
            overlap=overlap, disagreements=disagreements,
            corroborated_by_ai_agreement=False,   # structural guarantee (§21)
            explanation=expl,
        )

    def review_fact(self, fact_id: str, p1: ReviewPass, p2: ReviewPass) -> DualReviewResult:
        fact = self.memory.facts[fact_id]
        result = self.cross_check(fact_id, p1, p2)
        # an INSUFFICIENT_EVIDENCE dual review blocks promotion beyond current status
        if result.outcome == ReviewOutcome.INSUFFICIENT_EVIDENCE:
            fact.limitations.append("dual review: insufficient evidence — conclusions unsupported")
        return result

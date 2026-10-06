"""Analysis telemetry + evaluation metrics (§41).

Measures pipeline quality WITHOUT rewarding artificial agreement: false
agreement (both passes agree on something the evidence does not support) is
tracked explicitly because lower false-agreement is more valuable than higher
agreement.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AnalysisMetrics:
    primary_statements: int = 0
    secondary_statements: int = 0
    ai_agreement_rate: float = 0.0
    ai_false_agreement_rate: float = 0.0     # agree but NOT corroborated
    unsupported_claim_detection: float = 0.0 # uncited factual statements caught
    evidence_grounding_rate: float = 0.0
    disagreement_detection: float = 0.0
    temporal_error_flags: int = 0
    contradiction_flags: int = 0
    source_independence_accuracy_note: str = (
        "independence computed deterministically from lineage metadata")
    adjudication_rate: float = 0.0
    human_review_rate: float = 0.0
    per_run: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return self.__dict__


def compute_metrics(run) -> AnalysisMetrics:
    m = AnalysisMetrics()
    cc = run.cross_check
    if cc is None or not cc.items:
        return m
    items = cc.items
    agree = [i for i in items if i.ai_reasoning_agreement]
    false_agree = [i for i in agree if not i.evidence_corroboration]
    factual = [i for i in items if i.pass1_assessment.startswith(("fact", "observation"))
               or i.pass2_assessment.startswith(("fact", "observation"))]
    grounded = [i for i in factual if i.evidence_ids]
    ungrounded = [i for i in items
                  if i.conflict_reason == "model_hallucination_candidate"]
    total = len(items)
    m.primary_statements = run.primary.statements.__len__() if run.primary else 0
    m.secondary_statements = run.secondary.statements.__len__() if run.secondary else 0
    m.ai_agreement_rate = round(len(agree) / total, 3)
    m.ai_false_agreement_rate = round(len(false_agree) / max(len(agree), 1), 3)
    m.unsupported_claim_detection = round(len(ungrounded) / total, 3)
    m.evidence_grounding_rate = round(len(grounded) / max(len(factual), 1), 3)
    m.disagreement_detection = round(
        sum(1 for i in items if i.agreement_status in ("DISAGREE", "PASS1_ONLY",
                                                       "PASS2_ONLY")) / total, 3)
    m.temporal_error_flags = sum(1 for t in run.temporal
                                 if t.get("issue") == "stale_evidence")
    m.contradiction_flags = len(run.contradictions)
    m.adjudication_rate = 1.0 if run.adjudication is not None else 0.0
    if run.adjudication is not None:
        decs = run.adjudication.decisions
        m.human_review_rate = round(
            sum(1 for d in decs if d.requires_human_review) / max(len(decs), 1), 3)
    return m

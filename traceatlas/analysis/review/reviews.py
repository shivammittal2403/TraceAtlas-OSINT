"""Review-stage views over a completed DualAnalysisRun (§38 UI backing).

Each review module answers one mandated review question and is purely
deterministic (derived from stored artifacts) so reviews are reproducible.
"""

from __future__ import annotations


def factual_review(run) -> list[dict]:
    """Which claims survived the factuality gate; which were dropped."""
    out = []
    for item in run.cross_check.items if run.cross_check else []:
        out.append({"statement": item.statement,
                    "grounded": bool(item.evidence_ids),
                    "corroborated": item.evidence_corroboration,
                    "verdict": _verdict(run, item.statement)})
    return out


def source_review(run) -> dict:
    return {"independence_report": {k: v for k, v in run.independence.items()
                                   if k != "per_statement"},
            "model_diversity": run.model_diversity}


def evidence_review(run) -> dict:
    return {"primary_grounding": run.grounding_primary,
            "secondary_grounding": run.grounding_secondary,
            "validation_status": run.validation_status,
            "validation_issues": run.validation_issues}


def temporal_review(run) -> list[dict]:
    return list(run.temporal)


def identity_review(run) -> list[dict]:
    return list(run.entities)


def relationship_review(run) -> list[dict]:
    return list(run.relationships)


def hypothesis_review(run) -> list[dict]:
    hyps = []
    for p, label in ((run.primary, "pass1"), (run.secondary, "pass2")):
        if p is None:
            continue
        for st in p.statements:
            if st.kind == "hypothesis":
                hyps.append({"statement": st.statement, "produced_by": label,
                             "confidence": st.confidence,
                             "evidence_ids": st.evidence_ids,
                             "is_fact": False})   # never promoted by agreement
    for alt_src in (run.primary, run.secondary):
        if alt_src:
            for alt in alt_src.alternative_explanations:
                hyps.append({"statement": alt, "produced_by": "alternative",
                             "is_fact": False})
    return hyps


def contradiction_review(run) -> list[dict]:
    return list(run.contradictions)


def final_review(run) -> dict:
    from traceatlas.analysis.dual.escalation import escalations_for
    return {"synthesis": run.synthesis.model_dump() if run.synthesis else {},
            "escalations": escalations_for(run),
            "degraded": run.degraded}


def _verdict(run, statement: str) -> str:
    if run.adjudication is not None:
        for d in run.adjudication.decisions:
            if d.statement == statement:
                return d.verdict
    return ""

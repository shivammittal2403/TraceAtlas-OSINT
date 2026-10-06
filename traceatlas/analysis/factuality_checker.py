"""Factuality gate: facts require evidence; never model-vote-derived facts.

A statement of kind "fact" is factually admissible only when its citations
resolve against existing evidence AND at least one cited record passed the
deterministic validation gate. Two models calling X a fact does not make X a
fact (§2, §16: Fact must NEVER exist without evidence).
"""

from __future__ import annotations

from traceatlas.analysis.deterministic_grounding import FACTUAL_KINDS
from traceatlas.analysis.evidence_context import EvidenceContext
from traceatlas.analysis.result import PassAnalysis


def factuality_report(analysis: PassAnalysis, ctx: EvidenceContext,
                      grounding: dict) -> list[dict]:
    out = []
    by_id = ctx.evidence_by_id()
    for st in analysis.statements:
        if st.kind not in FACTUAL_KINDS:
            continue
        rec = grounding.get(st.statement, {})
        valid_cited = [e for e in st.evidence_ids
                       if e in by_id and by_id[e].validation_status == "VALID"]
        out.append({
            "statement": st.statement,
            "admissible_as_fact": bool(valid_cited) and rec.get("grounding") == "ok",
            "reason": ("grounded in validated evidence" if valid_cited and
                       rec.get("grounding") == "ok" else
                       rec.get("grounding", "uncited")),
            "evidence_ids": st.evidence_ids,
        })
    return out

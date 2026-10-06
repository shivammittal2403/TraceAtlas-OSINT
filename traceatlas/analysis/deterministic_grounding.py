"""Deterministic evidence-grounding check applied to BOTH passes (§2, §8, §40).

Rules enforced mechanically (no model involved):
1. FACTUAL kinds (fact/observation) MUST cite at least one evidence id that
   exists in the context -> otherwise grounding = "uncited".
2. A cited statement is "corroborated" only when its cited evidence comes from
   >= 2 GENUINELY INDEPENDENT sources (lineage-aware, §20). Model agreement
   never appears on this axis.
3. Statements citing evidence whose deterministic validation failed are marked
   "invalid_evidence".
This is what makes "both models hallucinate the same unsupported statement"
still fail verification: neither citation resolves against real evidence.
"""

from __future__ import annotations

from traceatlas.analysis.evidence_context import EvidenceContext
from traceatlas.analysis.result import PassAnalysis

FACTUAL_KINDS = {"fact", "observation"}
# inference/hypothesis/insight may reference evidence but are not themselves
# source-backed facts; they are kept with grounding "inference_only".


def _distinct_sources(ctx: EvidenceContext, ids: list[str]) -> set[str]:
    by_id = ctx.evidence_by_id()
    # lineage-aware: two records sharing an upstream publisher count as ONE
    sources: set[str] = set()
    for i in ids:
        item = by_id.get(i)
        if item is None:
            continue
        sources.add(item.upstream_source_id or item.source_id)
    return sources


def ground_pass(analysis: PassAnalysis, ctx: EvidenceContext) -> dict:
    """Return {statement_text: grounding_record} for one pass."""
    valid_ids = ctx.evidence_ids
    by_id = ctx.evidence_by_id()
    out: dict[str, dict] = {}
    for st in analysis.statements:
        unknown = [e for e in st.evidence_ids if e not in valid_ids]
        known = [e for e in st.evidence_ids if e in valid_ids]
        invalid_cited = [e for e in known
                         if by_id[e].validation_status != "VALID"]
        sources = _distinct_sources(ctx, known)
        rec = {
            "kind": st.kind,
            "evidence_ids": st.evidence_ids,
            "unknown_refs": unknown,
            "invalid_evidence_refs": invalid_cited,
            "distinct_independent_sources": sorted(sources),
            "source_count": len(sources),
            "grounding": "ok",
            "corroborated": False,
            "single_source": False,
        }
        if st.kind in FACTUAL_KINDS:
            if not st.evidence_ids or unknown:
                rec["grounding"] = "uncited_or_unknown"      # hallucination candidate
            elif invalid_cited and not set(known) - set(invalid_cited):
                rec["grounding"] = "invalid_evidence"
            else:
                rec["corroborated"] = len(sources) >= 2
                rec["single_source"] = len(sources) == 1
        else:
            rec["grounding"] = "inference_only"
        out[st.statement] = rec
    return out

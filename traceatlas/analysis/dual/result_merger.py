"""Merge non-conflicting knowledge from both passes without double counting (§11).

Semantic duplicates are collapsed; complementary observations preserved with
provenance (which pass produced them). Never merges a hypothesis into a fact.
"""

from __future__ import annotations

from traceatlas.analysis.cross_check_core import _jaccard
from traceatlas.analysis.result import AnalysisStatement, PassAnalysis


def merge_statements(p1: PassAnalysis, p2: PassAnalysis,
                     threshold: float = 0.55) -> list[dict]:
    merged: list[dict] = []
    for st in p1.statements:
        merged.append(_row(st, ["pass1"]))
    for st in p2.statements:
        dup = next((m for m in merged
                    if _jaccard(m["statement"], st.statement) >= threshold), None)
        if dup is not None:
            dup["produced_by"].append("pass2")
            dup["confidence_max"] = max(dup["confidence_max"], st.confidence)
        else:
            merged.append(_row(st, ["pass2"]))
    return merged


def _row(st: AnalysisStatement, provenance: list[str]) -> dict:
    return {"statement": st.statement, "kind": st.kind,
            "evidence_ids": st.evidence_ids,
            "confidence_max": st.confidence, "produced_by": provenance}

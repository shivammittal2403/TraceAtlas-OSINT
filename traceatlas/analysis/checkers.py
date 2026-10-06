"""Specialized deterministic checkers over the cross-check output:
contradiction, temporal, entity and relationship review (§19, §24, §25).
All logic is model-free so results are reproducible and auditable.
"""

from __future__ import annotations

import re

from traceatlas.analysis.evidence_context import EvidenceContext
from traceatlas.analysis.result import CrossCheckResult


def _tokens(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", text.lower()) if len(w) > 3}


def check_contradictions(ctx: EvidenceContext, cross: CrossCheckResult) -> list[dict]:
    """Disagreement-as-intelligence (§19): every DISAGREE row plus any
    pre-existing case contradiction that touches cited evidence."""
    out: list[dict] = []
    for item in cross.items:
        if item.agreement_status == "DISAGREE":
            out.append({
                "kind": "analytical_disagreement",
                "statement": item.statement,
                "reason": item.conflict_reason or "interpretation_difference",
                "pass1": item.pass1_assessment,
                "pass2": item.pass2_assessment,
                "evidence_ids": item.evidence_ids,
                "resolution": item.recommended_resolution or
                              "collect additional independent evidence",
                "final_status_hint": "INCONCLUSIVE",
            })
    ev_ids = {e.evidence_id for e in ctx.evidence}
    for c in ctx.existing_contradictions:
        refs = set(c.get("evidence_ids", [])) & ev_ids
        if refs:
            out.append({"kind": "case_contradiction", **c,
                        "touched_evidence": sorted(refs)})
    return out


def check_temporal(ctx: EvidenceContext, cross: CrossCheckResult) -> list[dict]:
    """Current vs historical confusion + stale citations (§9, §34)."""
    by_id = ctx.evidence_by_id()
    out: list[dict] = []
    for item in cross.items:
        stale = [e for e in item.evidence_ids
                 if e in by_id and by_id[e].validation_status == "STALE"]
        missing_time = [e for e in item.evidence_ids
                        if e in by_id and not by_id[e].event_time]
        if stale:
            out.append({"statement": item.statement, "issue": "stale_evidence",
                        "evidence_ids": stale,
                        "note": "observation may be historical; do not treat as current"})
        if missing_time and item.agreement_status in ("AGREE", "SEMANTIC_AGREEMENT"):
            out.append({"statement": item.statement, "issue": "undated_evidence",
                        "evidence_ids": missing_time,
                        "note": "cannot establish event time; temporal claims capped"})
        low = item.statement.lower()
        if ("last_seen" in low or "ownership" in low) and \
                any(e in low for e in ("own", "belong", "control")):
            out.append({"statement": item.statement,
                        "issue": "observation_vs_ownership",
                        "note": "'last_seen' records observation, NOT ownership (§9)"})
    return out


def check_entities(ctx: EvidenceContext, cross: CrossCheckResult) -> list[dict]:
    """Entity-resolution double check (§24): statements that assert a merge or
    same-operator identity need >=2 independent corroborating sources AND must
    survive both passes; otherwise keep candidate link only."""
    out: list[dict] = []
    merge_markers = ("same operator", "same person", "same actor", "same entity",
                     "identical identity", "merge", "belongs to the same",
                     "one individual", "same account")
    for item in cross.items:
        low = item.statement.lower()
        if any(m in low for m in merge_markers):
            ok = (item.evidence_corroboration
                  and item.independence == "independent"
                  and item.agreement_status in ("AGREE", "SEMANTIC_AGREEMENT"))
            out.append({
                "statement": item.statement,
                "proposed_merge": True,
                "decision": "ALLOWED_WITH_HUMAN_REVIEW" if ok else "CANDIDATE_LINK_ONLY",
                "rule": "DO NOT MERGE when evidence weak or models disagree (§24)",
                "evidence_ids": item.evidence_ids,
            })
    return out


def check_relationships(ctx: EvidenceContext, cross: CrossCheckResult,
                        entity_findings: list[dict]) -> list[dict]:
    """Relationship promotion gate (§25). Edge states: OBSERVED/CANDIDATE/
    PROBABLE/SUPPORTED/DISPUTED/HISTORICAL/EXPIRED."""
    merges_unresolved = any(e["decision"] == "CANDIDATE_LINK_ONLY"
                           for e in entity_findings)
    out: list[dict] = []
    rel_markers = ("connected to", "related to", "controlled by", "operates",
                   "infrastructure of", "same infrastructure", "linked to",
                   "communicates with", "uses the same")
    for item in cross.items:
        low = item.statement.lower()
        if not any(m in low for m in rel_markers):
            continue
        if item.agreement_status == "DISAGREE":
            state = "DISPUTED"
        elif item.temporal_consistency == "stale":
            state = "HISTORICAL"
        elif item.temporal_consistency == "conflicting":
            state = "EXPIRED"
        elif item.evidence_corroboration and item.independence == "independent":
            state = "SUPPORTED"
        elif item.ai_reasoning_agreement:
            state = "PROBABLE" if not merges_unresolved else "CANDIDATE"
        else:
            state = "OBSERVED"
        out.append({"statement": item.statement, "edge_state": state,
                    "evidence_ids": item.evidence_ids,
                    "promotion_allowed": state in ("SUPPORTED",),
                    "blocker": ("entity merge unresolved"
                                if state == "CANDIDATE" and merges_unresolved else "")})
    return out

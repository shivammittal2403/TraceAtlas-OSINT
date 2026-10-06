"""Statement-by-statement cross-check of the two independent passes (§6).

Produces CrossCheckResult rows with the TWO SEPARATE AXES mandated by §2:
  ai_reasoning_agreement  — do the two models say compatible things?
  evidence_corroboration  — do >=2 independent SOURCES back it? (deterministic)
Disagreement classification uses each side's grounding + lexical overlap to
pick a conflict_reason (§6 taxonomy).
"""

from __future__ import annotations

import re

from traceatlas.analysis.evidence_context import EvidenceContext
from traceatlas.analysis.result import (CrossCheckItem, CrossCheckResult,
                                       PassAnalysis)

_STOP = set("the a an is are was were of to in for and or on with by that this "
            "it its as at from be has have had may might can could not".split())


def _tokens(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", text.lower())
            if w not in _STOP and len(w) > 2}


def _overlap(a: str, b: str) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / min(len(ta), len(tb))


def _jaccard(a: str, b: str) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def _conflict_reason(g1: dict, g2: dict) -> str:
    if g1.get("grounding") in ("uncited_or_unknown",) or \
       g2.get("grounding") == "uncited_or_unknown":
        return "model_hallucination_candidate"
    if g1.get("invalid_evidence_refs") or g2.get("invalid_evidence_refs"):
        return "missing_evidence"
    s1, s2 = set(g1.get("distinct_independent_sources", [])), \
             set(g2.get("distinct_independent_sources", []))
    if s1 and s2 and s1 != s2 and not (s1 & s2):
        return "evidence_difference"
    if s1 == s2:
        return "interpretation_difference"
    return "unsupported_inference"


def run_cross_check(ctx: EvidenceContext, p1: PassAnalysis, p2: PassAnalysis,
                    g1: dict, g2: dict) -> CrossCheckResult:
    items: list[CrossCheckItem] = []
    used2: set[str] = set()

    for st1 in p1.statements:
        best, best_score = None, 0.0
        for st2 in p2.statements:
            score = _jaccard(st1.statement, st2.statement)
            if score > best_score:
                best, best_score = st2, score
        rec1 = g1.get(st1.statement, {})
        paired = best is not None and best_score >= 0.34
        if paired:
            assert best is not None
            rec2 = g2.get(best.statement, {})
            used2.add(best.statement)
            agree_ev = set(rec1.get("evidence_ids", [])) == set(rec2.get("evidence_ids", []))
            strong1 = st1.confidence >= 0.7
            strong2 = best.confidence >= 0.7
            corroborated = bool(rec1.get("corroborated") and rec2.get("corroborated"))
            if best_score >= 0.55 and agree_ev and (strong1 == strong2):
                status, reason = "AGREE", ""
            elif best_score >= 0.55:
                status, reason = "SEMANTIC_AGREEMENT", "semantic_overlap"
            else:
                status, reason = "PARTIAL_AGREEMENT", _conflict_reason(rec1, rec2)
            if _negated(st1.statement, best.statement):
                status, reason = "DISAGREE", _conflict_reason(rec1, rec2)
            ev_ids = sorted(set(rec1.get("evidence_ids", [])) |
                            set(rec2.get("evidence_ids", [])))
            reasoning_agree = status in ("AGREE", "SEMANTIC_AGREEMENT",
                                         "PARTIAL_AGREEMENT")
            n_src = max(rec1.get("source_count", 0), rec2.get("source_count", 0))
            src_support = ("multiple_independent_sources" if corroborated and n_src >= 2
                           else "multiple_sources" if n_src >= 2
                           else "single_source" if n_src == 1 else "none")
            resolution = _recommend(status, reason, corroborated, rec1, rec2)
            items.append(CrossCheckItem(
                statement=st1.statement,
                pass1_assessment=f"{st1.kind} conf={st1.confidence:.2f}",
                pass2_assessment=f"{best.kind} conf={best.confidence:.2f}",
                evidence_ids=ev_ids,
                agreement_status=status,
                conflict_reason=reason,          # type: ignore[arg-type]
                source_support=src_support,      # type: ignore[arg-type]
                independence=_independence(ev_ids, ctx),
                temporal_consistency=_temporal(ev_ids, ctx, reason),
                ai_reasoning_agreement=reasoning_agree,
                evidence_corroboration=corroborated,
                recommended_resolution=resolution))
        else:
            items.append(CrossCheckItem(
                statement=st1.statement,
                pass1_assessment=f"{st1.kind} conf={st1.confidence:.2f}",
                pass2_assessment="",
                evidence_ids=list(rec1.get("evidence_ids", [])),
                agreement_status="PASS1_ONLY",
                conflict_reason=("model_hallucination_candidate"
                                 if rec1.get("grounding") == "uncited_or_unknown"
                                 else "missing_evidence"),
                source_support="single_source" if rec1.get("source_count") == 1
                else "none",
                independence=_independence(rec1.get("evidence_ids", []), ctx),
                ai_reasoning_agreement=False,
                evidence_corroboration=False,
                recommended_resolution=_recommend("PASS1_ONLY", "", False, rec1, {})))

    for st2 in p2.statements:
        if st2.statement in used2:
            continue
        rec2 = g2.get(st2.statement, {})
        items.append(CrossCheckItem(
            statement=st2.statement,
            pass1_assessment="",
            pass2_assessment=f"{st2.kind} conf={st2.confidence:.2f}",
            evidence_ids=list(rec2.get("evidence_ids", [])),
            agreement_status="PASS2_ONLY",
            conflict_reason="" if rec2.get("grounding") == "ok"
            else "missing_evidence",
            source_support="single_source" if rec2.get("source_count") == 1 else "none",
            independence=_independence(rec2.get("evidence_ids", []), ctx),
            ai_reasoning_agreement=False,
            evidence_corroboration=False,
            recommended_resolution="retain as second-pass observation; "
                                   "primary did not surface it"))

    summary: dict[str, int] = {}
    for it in items:
        summary[it.agreement_status] = summary.get(it.agreement_status, 0) + 1
    return CrossCheckResult(case_id=ctx.case_id, items=items, summary=summary)


_NEG_MARKERS = ("not ", "no evidence", "insufficient", "unresolved", "cannot",
                "does not", "isn't", "wrong", "overreach", "too strong",
                "only demonstrates", "doesnt")


def _negated(a: str, b: str) -> bool:
    """Crude polarity detector: one side affirms, other refutes same topic."""
    na = any(m in a.lower() for m in _NEG_MARKERS)
    nb = any(m in b.lower() for m in _NEG_MARKERS)
    return na != nb


def _independence(ev_ids: list[str], ctx: EvidenceContext) -> str:
    by_id = ctx.evidence_by_id()
    upstream = {by_id[e].upstream_source_id or by_id[e].source_id
                for e in ev_ids if e in by_id}
    raw_sources = {by_id[e].source_id for e in ev_ids if e in by_id}
    if len(upstream) >= 2 and len(raw_sources) >= 2:
        return "independent"
    if len(upstream) >= 2:
        return "partially_independent"
    if len(raw_sources) >= 2 and len(upstream) == 1:
        return "dependent"          # copied/syndicated: many records, one origin
    return "unknown" if not ev_ids else "dependent"


def _temporal(ev_ids: list[str], ctx: EvidenceContext, reason: str) -> str:
    if reason == "temporal_mismatch":
        return "conflicting"
    by_id = ctx.evidence_by_id()
    stale = [e for e in ev_ids if e in by_id
             and by_id[e].validation_status == "STALE"]
    if stale:
        return "stale"
    return "consistent" if ev_ids else "unknown"


def _recommend(status: str, reason: str, corroborated: bool,
               rec1: dict, rec2: dict) -> str:
    if status in ("AGREE", "SEMANTIC_AGREEMENT") and corroborated:
        return "accept as source-corroborated finding"
    if status in ("AGREE", "SEMANTIC_AGREEMENT", "PARTIAL_AGREEMENT") and not corroborated:
        return ("AI reasoning agrees but evidence is single-source: keep as "
                "candidate; collect an independent source before promotion")
    if status == "DISAGREE":
        return "adjudicate against original evidence; default INCONCLUSIVE"
    if reason == "model_hallucination_candidate":
        return "discard unless re-grounded in existing evidence ids"
    if status == "PASS1_ONLY":
        return "verify against evidence; retain as hypothesis at most"
    return "review"

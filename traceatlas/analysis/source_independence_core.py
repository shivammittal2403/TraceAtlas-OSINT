"""Source-independence analysis BEFORE confidence (§20).

Multiple records are NOT multiple sources when they share an upstream origin
(five articles copying Reuters, three APIs on one upstream database, mirrors
of one breach dump). This module groups evidence by lineage key
(upstream_source_id or source_id) and reports per-statement independence.
AI agreement can never compensate for source dependence — independence is
computed purely from metadata, without any model.
"""

from __future__ import annotations

from traceatlas.analysis.evidence_context import EvidenceContext
from traceatlas.analysis.result import CrossCheckResult


def lineage_groups(ctx: EvidenceContext) -> dict[str, list[str]]:
    """upstream lineage key -> [source ids carrying the same origin]."""
    groups: dict[str, list[str]] = {}
    for item in ctx.evidence:
        key = item.upstream_source_id or item.source_id
        groups.setdefault(key, [])
        if item.source_id not in groups[key]:
            groups[key].append(item.source_id)
    return groups


def independence_report(ctx: EvidenceContext) -> dict:
    groups = lineage_groups(ctx)
    duplicated = {k: v for k, v in groups.items() if len(v) > 1}
    independent_origins = sorted(groups)
    return {
        "distinct_upstream_origins": independent_origins,
        "origin_count": len(independent_origins),
        "copied_lineages": duplicated,   # many records, one origin (§36 JARVIS line)
        "note": "records sharing an upstream origin count as ONE source",
    }


def independence_for_statement(ctx: EvidenceContext,
                               cross: CrossCheckResult) -> dict:
    """Attach per-statement independence + flag dependent corroboration."""
    rep = independence_report(ctx)
    by_id = ctx.evidence_by_id()
    per_statement: dict[str, dict] = {}
    for item in cross.items:
        origins = {by_id[e].upstream_source_id or by_id[e].source_id
                   for e in item.evidence_ids if e in by_id}
        raw_sources = {by_id[e].source_id for e in item.evidence_ids if e in by_id}
        status = ("independent" if len(origins) >= 2 else
                  "dependent" if len(raw_sources) >= 2 else
                  "single_source" if origins else "none")
        per_statement[item.statement] = {
            "origins": sorted(origins),
            "raw_source_count": len(raw_sources),
            "independence": status,
        }
        if status == "dependent" and item.ai_reasoning_agreement:
            # §2: models agree but sources are copies -> force corroboration off
            item.evidence_corroboration = False
            item.source_support = "multiple_sources"   # not *independent* sources
            if not item.recommended_resolution:
                item.recommended_resolution = (
                    "sources share an upstream origin; agreement is not "
                    "corroboration — collect a genuinely independent source")
    rep["per_statement"] = per_statement
    return rep

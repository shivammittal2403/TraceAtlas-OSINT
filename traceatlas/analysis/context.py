"""Build EvidenceContext from an InvestigationContext (§9, §12).

Bridges the running case state (observations, evidence records, claims,
hypotheses, contradictions) into the canonical ID-addressable bundle both AI
passes consume. Connector payload dicts are attached per source so the
deterministic gate can validate raw API fields, not just derived observations.
"""

from __future__ import annotations

import hashlib

from traceatlas.analysis.evidence_context import EvidenceContext, EvidenceItem
from traceatlas.investigation.context import InvestigationContext


def context_from_investigation(ctx: InvestigationContext, *, objective: str = "",
                               scope: str = "", questions: list[dict] | None = None,
                               connector_payloads: dict[str, dict] | None = None,
                               upstream_map: dict[str, str] | None = None) -> EvidenceContext:
    """connector_payloads: {source_id or connector_id: raw response dict}.
    upstream_map: {source_id: upstream_origin_id} for lineage/independence."""
    ec = EvidenceContext(case_id=ctx.case_id, objective=objective, scope=scope,
                         questions=questions or [])
    payloads = connector_payloads or {}
    upstream = upstream_map or {}

    # group observations by evidence record for citable summaries
    obs_by_ev: dict[str, list] = {}
    for obs in ctx.observations:
        obs_by_ev.setdefault(obs.evidence_id, []).append(obs)

    for ev_id, rec in sorted(ctx.evidence.items()):
        obs_list = obs_by_ev.get(ev_id, [])
        summary = "; ".join(f"{o.predicate}: {o.subject}->{o.obj}"
                            for o in obs_list[:8]) or "no derived observations"
        payload = payloads.get(rec.source_id) or payloads.get(rec.connector_id) or {}
        digest = hashlib.sha256(summary.encode()).hexdigest()[:10]
        ec.evidence.append(EvidenceItem(
            evidence_id=ev_id,
            source_id=rec.source_id or "unknown-source",
            connector_id=rec.connector_id,
            summary=f"{summary} [sha256:{digest}]",
            payload=payload,
            observation_ids=[o.id for o in obs_list],
            observed_at=rec.captured_at.isoformat(),
            event_time=str(payload.get("last_seen") or payload.get("observed_at") or ""),
            upstream_source_id=upstream.get(rec.source_id, ""),
        ))

    for rel in ctx.relationships:
        ec.graph_context.append({
            "source": rel.source_entity_id, "target": rel.target_entity_id,
            "type": rel.relationship_type.value if hasattr(rel.relationship_type, "value")
                    else str(rel.relationship_type),
            "confidence": rel.confidence, "evidence_ids": rel.evidence_ids})
    for claim in ctx.claims:
        ec.existing_claims.append(claim.to_dict() if hasattr(claim, "to_dict")
                                   else {"repr": str(claim)})
    for c in ctx.contradictions:
        ec.existing_contradictions.append(
            c.to_dict() if hasattr(c, "to_dict") else {"repr": str(c)})
    return ec


def context_from_payloads(case_id: str, *, objective: str, scope: str,
                          questions: list[dict],
                          records: list[dict],
                          upstream_map: dict[str, str] | None = None) -> EvidenceContext:
    """Lightweight constructor for direct API use/tests.

    Each record: {evidence_id, source_id, connector_id?, summary, payload,
                  event_time?}.
    """
    ec = EvidenceContext(case_id=case_id, objective=objective, scope=scope,
                         questions=questions)
    upstream = upstream_map or {}
    for r in records:
        ec.evidence.append(EvidenceItem(
            evidence_id=r["evidence_id"], source_id=r["source_id"],
            connector_id=r.get("connector_id", ""),
            summary=r.get("summary", ""), payload=r.get("payload", {}),
            observation_ids=r.get("observation_ids", []),
            event_time=r.get("event_time", ""),
            observed_at=r.get("observed_at", ""),
            upstream_source_id=upstream.get(r["source_id"], "")))
    return ec

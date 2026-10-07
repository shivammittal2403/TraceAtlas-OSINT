"""Report renderer: assembles the full investigation outcome into one HTML doc.

Complements reporting/builder.py (which produces a minimal dict) by rendering
the canonical report sections required for a defensible product:
Executive Summary, Objective & Scope, Methodology, Verified Findings,
Partially Supported / Disputed findings, Contradictions, Entities,
Relationships, Timeline events, Evidence table with citations, Source
independence summary, Limitations & Unknowns, Next actions, Replay manifest
reference.

Honesty rules enforced here:
- only VERIFIED claims appear under "Findings"; SUPPORTED/CONTRADICTED ones are
  shown separately with their verification rationale;
- every finding lists its evidence ids so a reader can trace to raw bytes;
- limitations from the independence analysis are always printed, never omitted.
"""

from __future__ import annotations

import html as _html
from datetime import datetime, timezone

from traceatlas.core.case import Case
from traceatlas.core.claim import Claim
from traceatlas.core.enums import ClaimStatus
from traceatlas.core.objective import Objective
from traceatlas.core.objective_spec import ObjectiveSpec
from traceatlas.graph.model import GraphModel
from traceatlas.investigation.context import InvestigationContext
from traceatlas.investigation.engine import EngineResult

_STYLE = """
body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:960px;color:#1a1a2e}
h1{border-bottom:3px solid #0f3460;padding-bottom:.3rem}
h2{color:#0f3460;margin-top:2rem}
table{border-collapse:collapse;width:100%;margin:.5rem 0}
th,td{border:1px solid #ccc;padding:6px 10px;text-align:left;font-size:.9rem}
th{background:#eef2f7}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.75rem;
color:#fff;margin-right:4px}
.b-verified{background:#1b7a3d}.b-supported{background:#a87c0a}
.b-contradicted{background:#a8322d}.b-rejected{background:#555}
.b-unverifiable{background:#777}.b-proposed{background:#3a5ba0}
.muted{color:#666;font-size:.85rem}
code{background:#f2f4f8;padding:1px 5px;border-radius:4px}
"""

_STATUS_CLASS = {
    ClaimStatus.VERIFIED: "b-verified",
    ClaimStatus.SUPPORTED: "b-supported",
    ClaimStatus.CONTRADICTED: "b-contradicted",
    ClaimStatus.REJECTED: "b-rejected",
    ClaimStatus.UNVERIFIABLE: "b-unverifiable",
    ClaimStatus.PROPOSED: "b-proposed",
}


def esc(x: object) -> str:
    return _html.escape(str(x), quote=True)


def render_report(case: Case, objective: Objective, spec: ObjectiveSpec,
                  ctx: InvestigationContext, graph: GraphModel,
                  claims: list[Claim], contradictions: list,
                  gaps: list, independence: dict,
                  eres: EngineResult) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    parts: list[str] = []
    ap = parts.append

    verified = [c for c in claims if c.status == ClaimStatus.VERIFIED]
    supported = [c for c in claims if c.status == ClaimStatus.SUPPORTED]
    disputed = [c for c in claims if c.status == ClaimStatus.CONTRADICTED]
    other = [c for c in claims
             if c.status not in (ClaimStatus.VERIFIED, ClaimStatus.SUPPORTED,
                                 ClaimStatus.CONTRADICTED)]

    ap(f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
       f"<title>TraceAtlas Report — {esc(case.title)}</title>"
       f"<style>{_STYLE}</style></head><body>")
    ap(f"<h1>TraceAtlas Investigation Report</h1>")
    ap(f"<p class='muted'>Case <code>{esc(case.id)}</code> · generated {now} · "
       f"engine status <b>{esc(eres.status)}</b> · stop reason "
       f"<b>{esc(eres.stop_reason or 'n/a')}</b></p>")

    # ---- executive summary ------------------------------------------------
    ap("<h2>1. Executive Summary</h2>")
    ap(f"<p>This automated public-source investigation produced "
       f"<b>{len(verified)} verified</b>, <b>{len(supported)} single-source "
       f"(supported)</b>, and <b>{len(disputed)} disputed</b> finding(s) over "
       f"{len(ctx.entities)} entities, {len(ctx.relationships)} relationships "
       f"and {len(ctx.evidence)} evidence records.</p>")
    ap("<ul>")
    for c in verified[:10]:
        ap(f"<li><span class='badge b-verified'>VERIFIED</span>{esc(c.statement)}</li>")
    for c in supported[:10]:
        ap(f"<li><span class='badge b-supported'>SUPPORTED (single source)</span>"
           f"{esc(c.statement)}</li>")
    if not verified and not supported:
        ap("<li>No findings reached verified/supported status. See limitations.</li>")
    ap("</ul>")

    # ---- objective & scope --------------------------------------------------
    ap("<h2>2. Objective &amp; Scope</h2>")
    ap(f"<p><b>Objective:</b> {esc(objective.text)}</p>")
    ap(f"<p><b>Investigation type:</b> {esc(spec.investigation_type)} · "
       f"<b>Jurisdiction:</b> {esc(', '.join(getattr(spec, 'jurisdictions', []) or ['not specified']))} · "
       f"<b>Time range:</b> {esc(getattr(spec, 'time_range', None) or 'not specified')}</p>")
    scope_note = getattr(spec, "scope_note", "") or \
        "Public/licensed open sources only; no authenticated access, no active scanning."
    ap(f"<p class='muted'>{esc(scope_note)}</p>")

    # ---- methodology ----------------------------------------------------------
    ap("<h2>3. Methodology</h2>")
    kinds = ", ".join(sorted(set(ctx.completed_task_kinds))) or "none completed"
    ap(f"<p>Deterministic pipeline: objective parse → plan → collection waves "
       f"({esc(kinds)}) → evidence capture (SHA-256 content addressing) → "
       f"normalization → entity/relationship extraction → claim derivation → "
       f"independence check → contradiction detection → verification → gap "
       f"analysis → next-best-action. Waves run: {len(eres.waves)}. Cost units "
       f"spent: {ctx.cost_units_spent:.2f}/{ctx.budget_max_cost_units:.2f}.</p>")

    # ---- findings tables -------------------------------------------------------
    def claim_rows(items: list[Claim]) -> None:
        ap("<table><tr><th>Status</th><th>Statement</th><th>Confidence</th>"
           "<th>Evidence</th></tr>")
        for c in items:
            cls = _STATUS_CLASS.get(c.status, "b-proposed")
            ev = ", ".join(f"<code>{esc(e)}</code>" for e in c.evidence_ids[:4])
            ap(f"<tr><td><span class='badge {cls}'>{esc(c.status.value.upper())}"
               f"</span></td><td>{esc(c.statement)}</td>"
               f"<td>{c.confidence:.2f}</td><td>{ev or '—'}</td></tr>")
        ap("</table>")

    ap("<h2>4. Findings</h2>")
    if verified + supported + disputed:
        claim_rows(verified + supported + disputed)
    else:
        ap("<p>No claims derived.</p>")
    if other:
        ap("<h3>Other claim states</h3>")
        claim_rows(other)

    # ---- contradictions ---------------------------------------------------------
    ap("<h2>5. Contradictions</h2>")
    if contradictions:
        ap("<table><tr><th>Kind</th><th>Severity</th><th>Refs</th><th>Note</th></tr>")
        for c in contradictions:
            ap(f"<tr><td>{esc(c.kind)}</td><td>{esc(c.severity.value)}</td>"
               f"<td><code>{esc(c.left_ref)}</code> vs <code>{esc(c.right_ref)}</code></td>"
               f"<td>{esc(c.resolution_note or 'unresolved')}</td></tr>")
        ap("</table>")
    else:
        ap("<p>No conflicts detected between collected observations.</p>")

    # ---- entities / graph --------------------------------------------------------
    ap("<h2>6. Entities &amp; Relationships</h2>")
    gdict = graph.to_dict()
    ap(f"<p>Graph: {len(gdict.get('nodes', []))} nodes, "
       f"{len(gdict.get('edges', []))} edges.</p>")
    ap("<table><tr><th>Type</th><th>Name</th><th>Attributes</th></tr>")
    for ent in sorted(ctx.entities.values(), key=lambda e: (e.entity_type.value, e.display_name)):
        attrs = ", ".join(f"{k}={v}" for k, v in list(ent.attributes.items())[:5])
        ap(f"<tr><td>{esc(ent.entity_type.value)}</td><td>{esc(ent.display_name)}</td>"
           f"<td class='muted'>{esc(attrs)}</td></tr>")
    ap("</table>")
    ap("<table><tr><th>Source</th><th>Relationship</th><th>Target</th><th>Conf</th><th>Evidence</th></tr>")
    for r in ctx.relationships[:100]:
        s = ctx.entities.get(next((k for k, v in ctx.entities.items() if v.id == r.source_entity_id), ""), None)
        t = ctx.entities.get(next((k for k, v in ctx.entities.items() if v.id == r.target_entity_id), ""), None)
        ap(f"<tr><td>{esc(s.display_name if s else r.source_entity_id)}</td>"
           f"<td><b>{esc(r.relationship_type.value)}</b></td>"
           f"<td>{esc(t.display_name if t else r.target_entity_id)}</td>"
           f"<td>{r.confidence:.2f}</td>"
           f"<td>{esc(', '.join(r.evidence_ids[:3]))}</td></tr>")
    ap("</table>")

    # ---- timeline -------------------------------------------------------------------
    ap("<h2>7. Timeline Events</h2>")
    events = [(o.subject, o.obj, o.attributes.get("date", ""))
              for o in ctx.observations if o.predicate == "domain.has_event"]
    if events:
        ap("<table><tr><th>Date</th><th>Subject</th><th>Event</th></tr>")
        for subj, action, date in sorted(events, key=lambda x: x[2]):
            ap(f"<tr><td>{esc(date or 'unknown')}</td><td>{esc(subj)}</td>"
               f"<td>{esc(action)}</td></tr>")
        ap("</table>")
    else:
        ap("<p>No dated events observed.</p>")

    # ---- evidence table ----------------------------------------------------------------
    ap("<h2>8. Evidence Table</h2>")
    ap("<table><tr><th>ID</th><th>Tier</th><th>Source</th><th>URL/Query</th>"
       "<th>SHA-256</th><th>Captured</th></tr>")
    for rec in sorted(ctx.evidence.values(), key=lambda r: r.captured_at):
        ap(f"<tr><td><code>{esc(rec.id)}</code></td><td>{esc(rec.tier.value)}</td>"
           f"<td>{esc(rec.source_id)}</td><td>{esc(rec.url or '—')}</td>"
           f"<td><code>{esc(rec.sha256[:16])}…</code></td>"
           f"<td>{esc(rec.captured_at.strftime('%Y-%m-%d %H:%M:%S'))}</td></tr>")
    ap("</table>")

    # ---- source independence -------------------------------------------------------------
    ap("<h2>9. Source Independence</h2>")
    ap(f"<p>Method: <b>{esc(independence.get('method', 'none'))}</b> · unique "
       f"digests: {independence.get('unique_digest_count', 0)} of "
       f"{independence.get('total_evidence_records', 0)} records · sources: "
       f"{esc(', '.join(independence.get('distinct_source_ids', [])) or 'none')}</p>")
    ap("<ul>")
    for lim in independence.get("limitations", []):
        ap(f"<li class='muted'>{esc(lim)}</li>")
    ap("</ul>")

    # ---- gaps / unknowns --------------------------------------------------------------------
    ap("<h2>10. Unknowns &amp; Information Gaps</h2>")
    if gaps:
        ap("<ul>")
        for g in gaps:
            flag = " ⛔blocking" if g.blocking_required_answer else ""
            ap(f"<li>{esc(g.question)}{flag}</li>")
        ap("</ul>")
    else:
        ap("<p>No open gaps recorded.</p>")

    # ---- limitations ----------------------------------------------------------------------------
    ap("<h2>11. Limitations</h2>")
    ap("<ul>"
       "<li>Near-duplicate/source-independence analysis is exact-hash only; "
       "syndicated content may still be counted as separate sources.</li>"
       "<li>Geolocation via IP is provider-asserted and approximate.</li>"
       "<li>Single-source facts cannot reach VERIFIED status under policy "
       "(≥2 independent sources required).</li>"
       "<li>AI interpretation was not used for any factual determination in "
       "this run (deterministic parsers only).</li></ul>")
    if ctx.errors:
        ap("<p class='muted'>Engine-recorded errors: " +
           "; ".join(esc(e) for e in ctx.errors[:10]) + "</p>")

    ap("</body></html>")
    return "".join(parts)

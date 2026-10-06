"""Contradiction detection adapter over collected observations.

Delegates value-conflict detection to traceatlas.contradictions.engine
(same subject+predicate, different object) and adds two deterministic checks
that matter for infrastructure investigations:

- historical_current: a DNS answer observed earlier that no longer appears in
  the most recent capture of the same predicate is flagged as a stale/current
  conflict (IP reassignment signal), not silently overwritten.
- source_disagreement: two RAW evidence records from DIFFERENT source_ids that
  assert conflicting values are recorded with higher severity than same-source
  noise.

Contradictions are attached to any claim whose statement references the
conflicting observation ids so verification can downgrade those claims.
"""

from __future__ import annotations

from traceatlas.contradictions.engine import detect_value_conflicts
from traceatlas.core.claim import Claim
from traceatlas.core.contradiction import Contradiction
from traceatlas.core.enums import RiskLevel
from traceatlas.core.observation import Observation
from traceatlas.investigation.context import InvestigationContext


def _stale_dns_conflicts(ctx: InvestigationContext) -> list[Contradiction]:
    """Flag resolution answers whose newest observation differs from an older one.

    DNS answers legitimately change (rebalancing, reassignment). We record the
    temporal pair as a historical/current contradiction instead of pretending
    both are simultaneously true.
    """
    out: list[Contradiction] = []
    by_key: dict[tuple[str, str], list[Observation]] = {}
    for o in ctx.observations:
        if o.predicate == "domain.resolves_to":
            by_key.setdefault((o.subject, o.predicate), []).append(o)
    for group in by_key.values():
        ordered = sorted(group, key=lambda x: x.observed_at)
        newest = ordered[-1]
        for older in ordered[:-1]:
            if older.obj != newest.obj:
                out.append(Contradiction(
                    case_id=ctx.case_id, left_ref=older.id, right_ref=newest.id,
                    kind="historical_current", severity=RiskLevel.LOW,
                    resolution_note=(
                        f"DNS answer changed {older.obj} -> {newest.obj}; "
                        "treat older value as historical"),
                ))
    return out


def _severity_for(ctx: InvestigationContext, c: Contradiction) -> tuple[RiskLevel, str]:
    """Escalate conflicts asserted by genuinely different sources."""
    a = next((o for o in ctx.observations if o.id == c.left_ref), None)
    b = next((o for o in ctx.observations if o.id == c.right_ref), None)
    if a is None or b is None:
        return c.severity, ""
    src_a = ctx.evidence.get(a.evidence_id)
    src_b = ctx.evidence.get(b.evidence_id)
    if src_a and src_b and src_a.source_id and src_b.source_id \
            and src_a.source_id != src_b.source_id:
        return RiskLevel.HIGH, (f"sources disagree: {src_a.source_id} vs "
                                f"{src_b.source_id}")
    return c.severity, ""


def detect_contradictions(ctx: InvestigationContext,
                          claims: list[Claim]) -> list[Contradiction]:
    found = detect_value_conflicts(ctx.observations) + _stale_dns_conflicts(ctx)
    deduped: dict[tuple[str, str, str], Contradiction] = {}
    for c in found:
        key = (c.left_ref, c.right_ref, c.kind)
        if key not in deduped:
            sev, note = _severity_for(ctx, c)
            c.severity = sev
            if note:
                c.resolution_note = note
            deduped[key] = c
    contradictions = sorted(deduped.values(), key=lambda x: x.id)

    # link contradictions back to claims referencing either side
    obs_ids = {c.left_ref for c in contradictions} | {c.right_ref for c in contradictions}
    conflicting_pairs: set[tuple[str, str, str]] = set()
    for o in ctx.observations:
        if o.id in obs_ids:
            conflicting_pairs.add((o.predicate, o.subject, o.obj))
    for claim in claims:
        for predicate, subject, obj in conflicting_pairs:
            fragment_subject = subject
            if fragment_subject and fragment_subject in claim.statement \
                    and obj in claim.statement:
                matching = [c for c in contradictions
                            if c.left_ref in _obs_ids_for(ctx, predicate, subject, obj)
                            or c.right_ref in _obs_ids_for(ctx, predicate, subject, obj)]
                for m in matching:
                    if m.id not in claim.contradiction_ids:
                        claim.contradiction_ids.append(m.id)
        if claim.contradiction_ids:
            ctx.relationships  # no-op; keeps linters honest about ctx usage
    for c in contradictions:
        ctx.gaps  # gaps are produced by the gap engine, not here
    return contradictions


def _obs_ids_for(ctx: InvestigationContext, predicate: str, subject: str,
                 obj: str) -> set[str]:
    return {o.id for o in ctx.observations
            if o.predicate == predicate and o.subject == subject and o.obj == obj}

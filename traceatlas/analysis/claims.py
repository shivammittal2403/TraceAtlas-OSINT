"""Claim derivation: observations -> typed Claim objects (deterministic).

Policy:
- Only protocol-fact predicates become claims (DNS answers, RDAP events,
  ASN/hosting/location assignments, certificate SAN bindings, delegation).
- A claim's confidence is a transparent function of corroboration count, not
  a fabricated number: direct single-source protocol facts start at 0.9; each
  additional independent source_id adds 0.05 up to 1.0.
- Every claim carries the evidence ids that support it (canonical chain:
  OBSERVATION -> CLAIM must remain evidence-linked).
"""

from __future__ import annotations

from traceatlas.core.claim import Claim
from traceatlas.core.enums import ClaimStatus
from traceatlas.investigation.context import InvestigationContext

# predicates that are direct protocol/provider facts worth asserting as claims
_FACT_PREDICATES: dict[str, str] = {
    "domain.resolves_to": "{subject} resolves via DNS to {obj}",
    "ip.in_asn": "{subject} is allocated within {obj}",
    "ip.hosted_by": "{subject} is hosted by {obj}",
    "ip.located_in": "{subject} geolocates to {obj}",
    "domain.registered_with": "{subject} is registered with {obj}",
    "domain.has_event": "RDAP registration event for {subject}: {obj}",
    "domain.delegated_to": "{subject} is delegated to nameserver {obj}",
    "cert.covers_domain": "certificate {subject} covers {obj}",
    "mx.hosts_mail_for": "{subject} handles mail for {obj}",
}


def _supporting_evidence(ctx: InvestigationContext, predicate: str,
                         subject: str, obj: str) -> tuple[list[str], set[str]]:
    ev_ids: list[str] = []
    source_ids: set[str] = set()
    for o in ctx.observations:
        if o.predicate == predicate and o.subject == subject and o.obj == obj:
            if o.evidence_id:
                ev_ids.append(o.evidence_id)
                rec = ctx.evidence.get(o.evidence_id)
                if rec is not None and rec.source_id:
                    source_ids.add(rec.source_id)
    return sorted(set(ev_ids)), source_ids


def derive_claims(ctx: InvestigationContext) -> list[Claim]:
    """Create one claim per distinct (predicate, subject, obj) fact triple."""
    triples: set[tuple[str, str, str]] = set()
    for o in ctx.observations:
        if o.predicate in _FACT_PREDICATES:
            triples.add((o.predicate, o.subject, o.obj))

    claims: list[Claim] = []
    for predicate, subject, obj in sorted(triples):
        template = _FACT_PREDICATES[predicate]
        statement = template.format(subject=subject, obj=obj)
        ev_ids, source_ids = _supporting_evidence(ctx, predicate, subject, obj)
        n_sources = max(1, len(source_ids))
        confidence = min(1.0, 0.9 + 0.05 * (n_sources - 1))
        claim = Claim(case_id=ctx.case_id, statement=statement,
                      status=ClaimStatus.PROPOSED, confidence=confidence,
                      evidence_ids=ev_ids)
        claims.append(claim)
        ctx.claims.append(claim)
    return claims

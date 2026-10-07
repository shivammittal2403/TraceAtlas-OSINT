"""Information-gap detection: what the objective still does not know.

Deterministic rules over the knowledge state after collection waves:
- required evidence categories with zero observations
- entities that were produced but never corroborated (single-source)
- claims left SUPPORTED/INCONCLUSIVE because independence was unavailable
- failed/skipped task kinds recorded in ctx.errors
Every gap carries candidate_actions so the NBA engine can rank follow-ups.
"""

from __future__ import annotations

from traceatlas.core.claim import Claim
from traceatlas.core.enums import ClaimStatus
from traceatlas.core.information_gap import InformationGap
from traceatlas.core.objective_spec import ObjectiveSpec
from traceatlas.investigation.context import InvestigationContext

# expected observation predicates per investigation type (infrastructure first)
_EXPECTED: dict[str, list[str]] = {
    "infrastructure": ["domain.resolves_to", "ip.in_asn"],
    "company": ["company.registered_with"],
    "general": [],
}


def find_gaps(spec: ObjectiveSpec, ctx: InvestigationContext,
              claims: list[Claim]) -> list[InformationGap]:
    gaps: list[InformationGap] = []
    present = {o.predicate for o in ctx.observations}

    # 1. expected-but-missing evidence categories
    for predicate in _EXPECTED.get(spec.investigation_type, []):
        if predicate not in present:
            gaps.append(InformationGap(
                case_id=ctx.case_id,
                question=f"No observations collected for '{predicate}' — is a "
                         f"connector available and authorized for it?",
                blocking_required_answer=True,
                candidate_actions=[f"collect.{predicate.split('.')[0]}"],
            ))

    # 2. single-source claims cannot reach VERIFIED under policy
    uncorroborated = [c for c in claims
                      if c.status in (ClaimStatus.SUPPORTED, ClaimStatus.PROPOSED)]
    if uncorroborated:
        gaps.append(InformationGap(
            case_id=ctx.case_id,
            question=(f"{len(uncorroborated)} claim(s) rest on a single source; "
                      "which independent sources could corroborate them?"),
            blocking_required_answer=False,
            candidate_actions=["search.corroborating_sources",
                               "analyze.independence"],
        ))

    # 3. contradictions left unresolved
    open_contra = [c for c in ctx.contradictions if not c.resolved]
    if open_contra:
        gaps.append(InformationGap(
            case_id=ctx.case_id,
            question=(f"{len(open_contra)} unresolved contradiction(s): which "
                      "value is current and why?"),
            blocking_required_answer=True,
            candidate_actions=["verify.temporal_consistency", "ask_human"],
        ))

    # 4. honest record of failed collection steps
    for err in ctx.errors:
        gaps.append(InformationGap(
            case_id=ctx.case_id,
            question=f"Collection step failed ({err}); retry via an alternate "
                     "source or accept partial coverage?",
            blocking_required_answer=False,
            candidate_actions=["retry.with_fallback_source", "accept_partial"],
        ))

    ctx.gaps.extend(gaps)
    return gaps

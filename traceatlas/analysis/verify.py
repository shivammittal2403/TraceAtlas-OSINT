"""Verification adapter: run claims through the verification engine.

Uses traceatlas.verification.engine.verify_claim (which enforces the >=2
distinct-source rule for VERIFIED status) and feeds it source counts computed
by analysis.independence AFTER exact-duplicate collapsing — so copied bytes
never inflate corroboration. Verification records are appended to the claim's
evidence trail via ctx.claims; statuses are written back onto each Claim.
"""

from __future__ import annotations

from traceatlas.analysis.independence import independent_source_ids_for
from traceatlas.core.claim import Claim
from traceatlas.core.contradiction import Contradiction
from traceatlas.core.enums import ClaimStatus
from traceatlas.core.verification import VerificationRecord
from traceatlas.investigation.context import InvestigationContext
from traceatlas.verification.engine import verify_claim


def verify_claims(claims: list[Claim], ctx: InvestigationContext,
                  contradictions: list[Contradiction],
                  independence_report: dict) -> list[VerificationRecord]:
    """Verify every claim in place; return the verification records produced."""
    records: list[VerificationRecord] = []
    unresolved = {c.id for c in contradictions if not c.resolved}
    for claim in claims:
        # integrity precondition: a claim must reference at least one evidence
        # record that actually exists in this context
        existing_ev = [e for e in claim.evidence_ids if e in ctx.evidence]
        if not existing_ev:
            claim.status = ClaimStatus.UNVERIFIABLE
            from traceatlas.core.enums import VerificationDecision
            rec = VerificationRecord(
                case_id=claim.case_id, claim_id=claim.id,
                decision=VerificationDecision.REJECTED,
                rationale="no retrievable supporting evidence",
                independent_source_count=0,
                inputs={"reason": "integrity check failed: evidence ids unknown"},
            )
            records.append(rec)
            continue
        sources = independent_source_ids_for(ctx, existing_ev)
        n_contra = len(set(claim.contradiction_ids) & unresolved)
        outcome = verify_claim(claim, sources, contradiction_count=n_contra)
        claim.status = outcome.new_status
        # annotate honesty flag from the independence report
        outcome.record.inputs["independence_method"] = \
            independence_report.get("method", "none")
        outcome.record.inputs["independence_limitations"] = \
            independence_report.get("limitations", [])
        records.append(outcome.record)
    ctx.verifications.extend(records)
    return records

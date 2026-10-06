"""Verification engine (minimal, deterministic core).

Policy enforced here:
- A claim may only reach VERIFIED with >= 2 distinct supporting sources.
- Independence counting is conservative because the independence engine is
  not yet implemented: distinct source_ids are counted and the verification
  record explicitly notes that independence has NOT been verified.
"""

from __future__ import annotations

from dataclasses import dataclass

from traceatlas.constants import MIN_CONFIDENCE_FOR_CLAIM
from traceatlas.core.claim import Claim
from traceatlas.core.enums import ClaimStatus, VerificationDecision
from traceatlas.core.verification import VerificationRecord


@dataclass
class VerificationOutcome:
    record: VerificationRecord
    new_status: ClaimStatus


def verify_claim(claim: Claim, independent_source_ids: set[str],
                 contradiction_count: int = 0) -> VerificationOutcome:
    n = len({s for s in independent_source_ids if s})
    if contradiction_count > 0:
        decision, status = VerificationDecision.INCONCLUSIVE, ClaimStatus.CONTRADICTED
        rationale = f"{contradiction_count} unresolved contradiction(s) recorded"
    elif n >= 2 and claim.confidence >= MIN_CONFIDENCE_FOR_CLAIM:
        decision, status = VerificationDecision.ACCEPTED, ClaimStatus.VERIFIED
        rationale = f"corroborated by {n} distinct sources"
    elif n == 0:
        decision, status = VerificationDecision.REJECTED, ClaimStatus.REJECTED
        rationale = "no supporting evidence sources"
    else:
        decision, status = VerificationDecision.INCONCLUSIVE, ClaimStatus.SUPPORTED
        rationale = f"only {n} distinct source(s); >=2 required for VERIFIED"
    rec = VerificationRecord(
        case_id=claim.case_id,
        claim_id=claim.id,
        decision=decision,
        rationale=rationale,
        independent_source_count=n,
        inputs={
            "source_ids": sorted(independent_source_ids),
            "independence_engine_implemented": False,
        },
    )
    return VerificationOutcome(record=rec, new_status=status)

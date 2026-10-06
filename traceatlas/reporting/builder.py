"""Report builder: assembles a JSON report from case records.

Hard rule enforced here: findings include ONLY claims with status VERIFIED.
Proposed/supported/contradicted claims appear under "open_questions".
"""

from __future__ import annotations

from traceatlas.core.case import Case
from traceatlas.core.claim import Claim
from traceatlas.core.serialization import to_json


def build_report(case: Case, claims: list[Claim], limitations: list[str] | None = None) -> dict:
    verified = [c for c in claims if c.reportable]
    open_items = [c for c in claims if not c.reportable]
    return {
        "report_version": "0.1",
        "case_id": case.id,
        "case_title": case.title,
        "generated_by": "TraceAtlas-Automator (rule-based reporter)",
        "findings": [
            {"statement": c.statement, "confidence": c.confidence,
             "evidence_ids": c.evidence_ids} for c in verified
        ],
        "open_questions": [
            {"statement": c.statement, "status": c.status.value} for c in open_items
        ],
        "limitations": (limitations or []) + [
            "Source independence has not been machine-verified.",
            "Collection was limited to sources qualified at report time.",
        ],
    }

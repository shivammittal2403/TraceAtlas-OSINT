"""Disagreement-as-intelligence view (§19)."""
from traceatlas.analysis.checkers import check_contradictions  # noqa: F401


def disagreement_cards(cross) -> list[dict]:
    cards = []
    for item in cross.items:
        if item.agreement_status in ("DISAGREE", "PASS1_ONLY", "PASS2_ONLY"):
            cards.append({
                "statement": item.statement,
                "status": item.agreement_status,
                "conflict_reason": item.conflict_reason,
                "pass1": item.pass1_assessment,
                "pass2": item.pass2_assessment,
                "evidence_ids": item.evidence_ids,
                "independence": item.independence,
                "resolution": item.recommended_resolution,
            })
    return cards

"""Agreement classification helpers (§6)."""
from traceatlas.analysis.result import CrossCheckItem  # noqa: F401

AGREEING = ("AGREE", "SEMANTIC_AGREEMENT")
MATERIAL_DISAGREEMENT = ("DISAGREE",)


def agreement_rate(items: list[CrossCheckItem]) -> float:
    if not items:
        return 0.0
    return sum(1 for i in items if i.agreement_status in AGREEING) / len(items)


def false_agreement_items(items: list[CrossCheckItem]) -> list[CrossCheckItem]:
    """AI reasoning agrees but evidence does NOT corroborate (§2)."""
    return [i for i in items
            if i.ai_reasoning_agreement and not i.evidence_corroboration]

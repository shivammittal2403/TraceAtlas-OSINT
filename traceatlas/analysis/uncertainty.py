"""Uncertainty aggregation across passes.

overall_uncertainty rises when: passes disagree, grounding fails, evidence is
single-source/stale, or MODEL_DIVERSITY=LOW. Used by the cost policy (§39) to
decide whether a MEDIUM-importance result warrants a second pass.
"""

from __future__ import annotations

_ORDER = {"low": 0, "medium": 1, "high": 2}


def combine(p1: str | None, p2: str | None, *, disagreements: int = 0,
            ungrounded: int = 0, single_source: int = 0, low_diversity: bool = False) -> str:
    score = max(_ORDER.get(p1 or "medium", 1), _ORDER.get(p2 or "medium", 1))
    score += min(2, disagreements) + min(1, 1 if ungrounded else 0) \
        + (1 if single_source else 0) + (1 if low_diversity else 0)
    return "high" if score >= 3 else "medium" if score >= 1 else "low"

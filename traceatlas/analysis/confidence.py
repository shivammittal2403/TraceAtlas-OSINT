"""Confidence computation with independence penalties (§20, §41).

Caps applied deterministically:
- single upstream origin ...................... max MEDIUM (0.69)
- dependent copies masquerading as sources .... max LOW-MEDIUM (0.55)
- stale evidence .............................. one level down
- unresolved disagreement ..................... INCONCLUSIVE (no confidence)
- both models agree but no independent evidence -> capped at PROBABLE band;
  model agreement NEVER raises the ceiling (§2).
"""

from __future__ import annotations

from traceatlas.core.enums import ConfidenceLevel


def cap_for(item) -> float:
    """Max numeric confidence allowed for a CrossCheckItem."""
    if item.agreement_status == "DISAGREE":
        return 0.0
    if not item.evidence_ids:
        return 0.3
    if item.independence == "dependent":
        return 0.55
    if item.source_support in ("none", "single_source"):
        return 0.69
    ceiling = 0.85
    if item.temporal_consistency == "stale":
        ceiling -= 0.15
    elif item.temporal_consistency == "conflicting":
        ceiling -= 0.3
    return max(0.0, min(ceiling, 0.95))


def degrade_confidence_for_dependence(level: ConfidenceLevel,
                                      independence: str) -> ConfidenceLevel:
    order = [ConfidenceLevel.LOW, ConfidenceLevel.MEDIUM_LOW,
             ConfidenceLevel.MEDIUM, ConfidenceLevel.MEDIUM_HIGH,
             ConfidenceLevel.HIGH, ConfidenceLevel.VERY_HIGH]
    idx = order.index(level) if level in order else 2
    penalty = {"dependent": 2, "unknown": 1}.get(independence, 0)
    return order[max(0, idx - penalty)]


def confidence_level(score: float) -> ConfidenceLevel:
    if score >= 0.9:
        return ConfidenceLevel.VERY_HIGH
    if score >= 0.75:
        return ConfidenceLevel.HIGH
    if score >= 0.6:
        return ConfidenceLevel.MEDIUM_HIGH
    if score >= 0.45:
        return ConfidenceLevel.MEDIUM
    if score >= 0.3:
        return ConfidenceLevel.MEDIUM_LOW
    return ConfidenceLevel.LOW

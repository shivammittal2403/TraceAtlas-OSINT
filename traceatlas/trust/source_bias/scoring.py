"""Qualitative bias-risk aggregation.

Risk level reflects how much bias could affect downstream confidence —
it NEVER discards the source or the evidence.
"""
from __future__ import annotations

from traceatlas.trust.model import BiasType, ConfidenceLevel
from traceatlas.trust.source_bias.model import BiasFlags

_HIGH_RISK = {BiasType.ADVERSARIAL, BiasType.SELF_INTEREST, BiasType.PROMOTIONAL}
_MED_RISK = {BiasType.POLITICAL, BiasType.COMMERCIAL, BiasType.ADVOCACY,
             BiasType.INSTITUTIONAL, BiasType.PUBLICATION}


def risk_level_for(flags: BiasFlags) -> ConfidenceLevel:
    types = set(flags.types)
    if not types:
        return ConfidenceLevel.LOW          # no detected bias vectors ⇒ low bias risk
    if types & _HIGH_RISK:
        return ConfidenceLevel.HIGH
    if types & _MED_RISK:
        return ConfidenceLevel.MODERATE
    return ConfidenceLevel.LOW

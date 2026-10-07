"""Human-readable bias explanation builder (feeds JARVIS brief + report §38)."""
from __future__ import annotations

from traceatlas.trust.model import BiasAssessment


def explain_bias(assessment: BiasAssessment) -> str:
    parts = []
    types = ", ".join(b.value for b in assessment.bias_types) or "none detected"
    parts.append(f"Bias types: {types}.")
    parts.append(f"Position: {assessment.primary_or_secondary.value}; "
                 f"independence: {assessment.independence_status.value}.")
    if assessment.possible_incentives:
        parts.append("Possible incentives: " + "; ".join(assessment.possible_incentives) + ".")
    if assessment.known_limitations:
        parts.append("Known limitations: " + "; ".join(assessment.known_limitations) + ".")
    parts.append("Bias annotation does not discard evidence; weigh accordingly.")
    return " ".join(parts)

"""Plain-language explanation of a gate decision (feeds reports + JARVIS)."""

from __future__ import annotations

from traceatlas.trust.fact_gate.decision import GateResult


def explain_decision(result: GateResult) -> str:
    lines = [f"Candidate {result.candidate_id}: {result.decision.value}"]
    if result.reasons:
        lines.append("Reasons:")
        lines += [f"  - {r}" for r in result.reasons]
    else:
        lines.append("Reasons: all checks passed.")
    lines.append(f"Independent source clusters: {result.independent_clusters}")
    if result.needs_review:
        lines.append("Flagged for human/skeptic review.")
    return "\n".join(lines)

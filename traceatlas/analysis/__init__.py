"""Analysis adapters: thin, deterministic bridges between the investigation
execution context and the verification / independence / contradictions /
reporting subsystems.

These modules contain NO network access and NO LLM calls. They operate purely
on knowledge already captured in InvestigationContext (observations,
relationships, evidence records) and produce typed domain products
(Claim, Contradiction, InformationGap, NextAction, VerificationRecord).
"""

from traceatlas.analysis.claims import derive_claims
from traceatlas.analysis.contradictions import detect_contradictions
from traceatlas.analysis.gaps import find_gaps
from traceatlas.analysis.independence import analyze_independence
from traceatlas.analysis.nba import next_best_actions
from traceatlas.analysis.verify import verify_claims

__all__ = [
    "derive_claims",
    "detect_contradictions",
    "analyze_independence",
    "verify_claims",
    "find_gaps",
    "next_best_actions",
]

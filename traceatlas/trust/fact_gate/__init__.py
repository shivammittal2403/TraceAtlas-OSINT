"""Fact Gate (§13): the mandatory chokepoint between observations and facts.

Decisions: ACCEPT_AS_SUPPORTED_FACT / ACCEPT_AS_PARTIAL_FACT / KEEP_AS_OBSERVATION
/ DISPUTED / INSUFFICIENT_EVIDENCE / REJECT. The hypothesis engine consumes ONLY
approved fact/observation sets produced here.
"""

from traceatlas.trust.fact_gate.candidate import FactCandidate
from traceatlas.trust.fact_gate.decision import GateResult
from traceatlas.trust.fact_gate.gate import FactGate

__all__ = ["FactCandidate", "GateResult", "FactGate"]

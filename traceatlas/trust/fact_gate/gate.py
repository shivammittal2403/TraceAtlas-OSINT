"""FactGate — the mandatory chokepoint (§13, §37).

Ordering inside the gate mirrors §37:
  evidence validation → source check → bias coverage → temporal → entity →
  independence → contradiction → decision.

Outputs Fact objects carrying their decision, so CaseMemory can enforce that
only gated facts enter canonical state.
"""

from __future__ import annotations

from traceatlas.trust.case_memory import CaseMemory
from traceatlas.trust.fact_gate.candidate import FactCandidate
from traceatlas.trust.fact_gate.decision import GateResult
from traceatlas.trust.fact_gate.explanation import explain_decision
from traceatlas.trust.fact_gate.validator import validate_candidate
from traceatlas.trust.model import (
    ConfidenceLevel,
    Fact,
    FactDecision,
    VerificationStatus,
)


class FactGate:
    def __init__(self, memory: CaseMemory) -> None:
        self.memory = memory
        self.decisions: list[GateResult] = []

    def evaluate(self, candidate: FactCandidate) -> GateResult:
        report = validate_candidate(candidate, self.memory)

        if report.hard_failures:
            decision = (FactDecision.REJECT
                        if any("future" in r or "unknown" in r for r in report.hard_failures)
                        else FactDecision.INSUFFICIENT_EVIDENCE)
            return self._record(GateResult(
                candidate_id=candidate.id, decision=decision,
                reasons=report.hard_failures + report.soft_flags))

        if report.contradictions:
            for c in report.contradictions:
                self.memory.add_contradiction(c)
            fact = self._build_fact(candidate, report, VerificationStatus.DISPUTED,
                                    ConfidenceLevel.LOW)
            fact.decision = FactDecision.DISPUTED
            # disputed facts are RETAINED on record but excluded from approved set
            self.memory.facts[fact.id] = fact
            self.memory._audit("add_disputed_fact", fact.id)
            return self._record(GateResult(
                candidate_id=candidate.id, decision=FactDecision.DISPUTED,
                reasons=["contradicts existing material statements (retained, not deleted)"],
                fact_id=fact.id, independent_clusters=report.independent_clusters,
                needs_review=True))

        if report.soft_flags:
            # missing bias assessment ⇒ demote to observation (bias check is mandatory §10)
            if any("bias assessment" in r for r in report.soft_flags):
                return self._record(GateResult(
                    candidate_id=candidate.id, decision=FactDecision.KEEP_AS_OBSERVATION,
                    reasons=report.soft_flags,
                    independent_clusters=report.independent_clusters))
            # stale data ⇒ partial fact with limitations annotated
            fact = self._build_fact(candidate, report, VerificationStatus.PARTIAL,
                                    ConfidenceLevel.MODERATE)
            fact.decision = FactDecision.ACCEPT_AS_PARTIAL_FACT
            fact.limitations.extend(report.soft_flags)
            self.memory.add_fact(fact)
            return self._record(GateResult(
                candidate_id=candidate.id, decision=FactDecision.ACCEPT_AS_PARTIAL_FACT,
                reasons=report.soft_flags, fact_id=fact.id,
                independent_clusters=report.independent_clusters))

        confidence = (ConfidenceLevel.HIGH if report.independent_clusters >= 2
                      else ConfidenceLevel.MODERATE)
        fact = self._build_fact(candidate, report, VerificationStatus.SUPPORTED, confidence)
        fact.decision = FactDecision.ACCEPT_AS_SUPPORTED_FACT
        self.memory.add_fact(fact)
        return self._record(GateResult(
            candidate_id=candidate.id, decision=FactDecision.ACCEPT_AS_SUPPORTED_FACT,
            fact_id=fact.id, independent_clusters=report.independent_clusters))

    def _build_fact(self, candidate: FactCandidate, report, status,
                    confidence: ConfidenceLevel) -> Fact:
        obs = [self.memory.observations[o] for o in candidate.observation_ids
               if o in self.memory.observations]
        evidence_ids = list(candidate.evidence_ids) or [e for o in obs for e in o.evidence_ids]
        source_ids = list(candidate.source_ids) or sorted({
            self.memory.evidence[e].source_id for e in evidence_ids})
        return Fact(
            statement=candidate.statement,
            case_id=candidate.case_id,
            evidence_ids=evidence_ids,
            source_ids=source_ids,
            observation_ids=list(candidate.observation_ids),
            entity_ids=list(candidate.entity_ids),
            event_time=candidate.event_time,
            verification_status=status,
            source_independence=report.independence_status,
            independent_cluster_count=report.independent_clusters,
            confidence=confidence,
        )

    def _record(self, result: GateResult) -> GateResult:
        self.decisions.append(result)
        self.memory._audit("fact_gate_decision",
                           f"{result.candidate_id}:{result.decision.value}")
        return result

    def explain(self, result: GateResult) -> str:
        return explain_decision(result)

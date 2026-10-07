"""Candidate-level validation orchestration used by the gate."""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.trust.case_memory import CaseMemory
from traceatlas.trust.fact_gate.bias_check import check_bias_coverage
from traceatlas.trust.fact_gate.candidate import FactCandidate
from traceatlas.trust.fact_gate.contradiction_check import find_contradictions
from traceatlas.trust.fact_gate.entity_check import check_entities
from traceatlas.trust.fact_gate.evidence_check import check_evidence
from traceatlas.trust.fact_gate.independence_check import check_independence
from traceatlas.trust.fact_gate.source_check import check_sources
from traceatlas.trust.fact_gate.temporal_check import check_temporal
from traceatlas.trust.model import IndependenceStatus


@dataclass
class ValidationReport:
    hard_failures: list[str] = field(default_factory=list)   # ⇒ REJECT / INSUFFICIENT
    soft_flags: list[str] = field(default_factory=list)      # ⇒ PARTIAL / annotation
    independent_clusters: int = 0
    independence_status: IndependenceStatus = IndependenceStatus.UNKNOWN
    contradictions: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.hard_failures


def validate_candidate(candidate: FactCandidate, memory: CaseMemory) -> ValidationReport:
    report = ValidationReport()

    ok, probs = check_evidence(candidate, memory)
    if not ok:
        report.hard_failures += probs
    ok2, probs2 = check_sources(candidate, memory)
    if not ok2:
        report.hard_failures += probs2
    ok3, probs3 = check_bias_coverage(candidate, memory)
    report.soft_flags += probs3           # missing bias ⇒ demote, not reject
    ok4, probs4 = check_temporal(candidate, memory)
    if not ok4:
        report.hard_failures += probs4
    else:
        report.soft_flags += probs4
    ok5, probs5 = check_entities(candidate)
    if not ok5:
        report.hard_failures += probs5

    if candidate.source_ids and not report.hard_failures:
        status, n_clusters, _ = check_independence(candidate.source_ids, memory)
        report.independent_clusters = n_clusters
        report.independence_status = status

    if not report.hard_failures:
        report.contradictions = find_contradictions(candidate, memory)
    return report

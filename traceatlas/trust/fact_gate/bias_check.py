"""Bias gate requirement: material sources MUST have a BiasAssessment before a
candidate can be promoted (§10). Missing assessment ⇒ keep as observation."""

from __future__ import annotations

from traceatlas.trust.case_memory import CaseMemory
from traceatlas.trust.fact_gate.candidate import FactCandidate
from traceatlas.trust.model import BiasAssessment
from traceatlas.trust.source_bias.analyzer import SourceBiasAnalyzer


def ensure_bias_assessments(candidate: FactCandidate, memory: CaseMemory,
                            analyzer: SourceBiasAnalyzer | None = None) -> list[BiasAssessment]:
    """Create (and register) any missing bias assessments for cited sources."""
    analyzer = analyzer or SourceBiasAnalyzer()
    out: list[BiasAssessment] = []
    assessed = {b.source_id: b for b in memory.bias_assessments.values()}
    for sid in candidate.source_ids:
        if sid in assessed:
            out.append(assessed[sid])
            continue
        src = memory.sources.get(sid)
        if src is None:
            continue
        a = analyzer.assess(src)
        memory.add_assessment(a)
        out.append(a)
    return out


def check_bias_coverage(candidate: FactCandidate, memory: CaseMemory) -> tuple[bool, list[str]]:
    problems = []
    for sid in candidate.source_ids:
        if not any(b.source_id == sid for b in memory.bias_assessments.values()):
            problems.append(f"source {sid} has no bias assessment — run bias analysis first (§10)")
    return (not problems), problems

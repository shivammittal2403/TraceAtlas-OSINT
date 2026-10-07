"""Evidence validation: every candidate must cite resolvable evidence (§8/§9)."""

from __future__ import annotations

from traceatlas.trust.case_memory import CaseMemory
from traceatlas.trust.fact_gate.candidate import FactCandidate


def check_evidence(candidate: FactCandidate, memory: CaseMemory) -> tuple[bool, list[str]]:
    problems: list[str] = []
    if not candidate.evidence_ids:
        problems.append("candidate has no evidence ids — not a fact (§9)")
        return False, problems
    missing = [e for e in candidate.evidence_ids if e not in memory.evidence]
    if missing:
        problems.append(f"evidence ids not present in case evidence store: {missing}")
        return False, problems
    srcs = {memory.evidence[e].source_id for e in candidate.evidence_ids}
    unknown_srcs = [s for s in srcs if s not in memory.sources]
    if unknown_srcs:
        problems.append(f"evidence references unregistered sources: {unknown_srcs}")
        return False, problems
    return True, problems

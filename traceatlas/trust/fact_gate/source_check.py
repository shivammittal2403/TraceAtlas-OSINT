"""Source registration check."""

from __future__ import annotations

from traceatlas.trust.case_memory import CaseMemory
from traceatlas.trust.fact_gate.candidate import FactCandidate


def check_sources(candidate: FactCandidate, memory: CaseMemory) -> tuple[bool, list[str]]:
    problems: list[str] = []
    if not candidate.source_ids:
        problems.append("candidate cites no sources")
        return False, problems
    missing = [s for s in candidate.source_ids if s not in memory.sources]
    if missing:
        problems.append(f"unregistered sources cited: {missing}")
        return False, problems
    return True, problems

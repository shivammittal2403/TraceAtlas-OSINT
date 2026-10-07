"""Entity resolution guard (§40): identity merges require justification.

Rule encoded here: username similarity ALONE never merges two person entities.
"""

from __future__ import annotations

from traceatlas.trust.fact_gate.candidate import FactCandidate

_USERNAME_ONLY_MARKERS = ("username match", "handle match", "same nickname")
_MERGE_STRENGTH_MARKERS = ("document id", "registry filing",
                           "self-disclosed with corroboration",
                           "biographical convergence",
                           "multiple independent identifiers")


def merge_allowed(justification: str) -> bool:
    j = justification.lower()
    username_only = any(m in j for m in _USERNAME_ONLY_MARKERS)
    strong = any(m in j for m in _MERGE_STRENGTH_MARKERS)
    if username_only and not strong:
        return False   # same username only → no person merge
    return bool(justification.strip())


def check_entities(candidate: FactCandidate) -> tuple[bool, list[str]]:
    """Candidates may reference entities; ensure entity claims carry evidence."""
    problems = []
    if candidate.entity_ids and not candidate.evidence_ids:
        problems.append("entity claims without evidence")
    return (not problems), problems

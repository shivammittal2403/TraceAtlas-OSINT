"""Flag objective ambiguities that require human clarification."""

from __future__ import annotations

import re

from traceatlas.core.objective_spec import ObjectiveSpec

_PRONOUN_RE = re.compile(r"\b(he|she|they|it|this company|that person)\b", re.I)
_VAGUE_RE = re.compile(r"\b(everything|all about|deep dive|dig into|everything you can)\b", re.I)


def detect_ambiguities(text: str, spec: ObjectiveSpec) -> list[str]:
    issues: list[str] = []
    if not spec.target_entities:
        issues.append("No concrete target entity could be extracted from the objective.")
    if _PRONOUN_RE.search(text):
        issues.append("Objective contains pronouns without a clear antecedent.")
    if _VAGUE_RE.search(text):
        issues.append("Objective scope is vague ('everything'-style); needs bounded questions.")
    if len(text) < 15:
        issues.append("Objective is too short to determine required answers reliably.")
    return issues

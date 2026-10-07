"""Contradiction detection between a candidate and existing approved facts.

Negation-aware deterministic check: 'X does not Y' contradicts 'X Y'.
Contradictions are RETAINED (§29) — they mark facts disputed, never deleted.
"""

from __future__ import annotations

import re

from traceatlas.trust.case_memory import CaseMemory
from traceatlas.trust.fact_gate.candidate import FactCandidate
from traceatlas.trust.model import Contradiction, ConfidenceLevel

_NEG = re.compile(
    r"\b(does not|doesn't|did not|didn't|is not|isn't|are not|aren't|"
    r"no longer|never|not)\b")


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9][a-z0-9._-]*", text.lower()))


def _negated(text: str) -> bool:
    return bool(_NEG.search(text))


def find_contradictions(candidate: FactCandidate, memory: CaseMemory) -> list[Contradiction]:
    found: list[Contradiction] = []
    c_tok, c_neg = _tokens(candidate.statement), _negated(candidate.statement)
    corpus = {f.id: f for f in memory.approved_facts}
    corpus.update({f.id: f for f in memory.facts.values() if f.decision is not None})
    for fact in corpus.values():
        f_tok, f_neg = _tokens(fact.statement), _negated(fact.statement)
        overlap = len(c_tok & f_tok) / max(1, min(len(c_tok), len(f_tok)))
        # high lexical overlap but opposite polarity ⇒ contradiction
        if overlap >= 0.6 and c_neg != f_neg:
            found.append(Contradiction(
                statement_a=candidate.statement, statement_b=fact.statement,
                ref_a=candidate.id, ref_b=fact.id,
                severity=ConfidenceLevel.HIGH, case_id=candidate.case_id,
            ))
    return found

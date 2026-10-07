"""Falsification machinery (§19).

The FalsificationEmployee uses this to try to DISPROVE the leading hypothesis.
It must not treat a 'winning' hypothesis as something to defend: any approved
fact that contradicts the hypothesis statement weakens/falsifies it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from traceatlas.trust.case_memory import CaseMemory
from traceatlas.trust.model import Hypothesis, HypothesisStatus

_FALSIFY_MARKERS = {
    "ownership": ["no ownership record", "different owner", "owner mismatch",
                  "unrelated registration"],
    "timeline": ["timeline conflict", "did not exist at the time", "after the event",
                 "impossible date"],
    "identity": ["identity mismatch", "different person", "not the same entity"],
    "infrastructure": ["cdn", "shared hosting", "proxy", "parked domain",
                       "common hosting provider"],
    "source_dependency": ["single upstream source", "all derived from", "syndicated"],
    "stale": ["historical association", "no longer", "expired", "former configuration"],
    "parsing_error": ["parse error", "malformed record", "scanner false positive"],
}

_NEG = re.compile(r"\b(does not|didn't|doesnt|is not|was not|never|no longer)\b")


@dataclass
class FalsificationReport:
    hypothesis_id: str
    attempted_tests: list[str] = field(default_factory=list)
    breaking_facts: list[str] = field(default_factory=list)
    alternative_explanations_found: list[str] = field(default_factory=list)
    outcome: HypothesisStatus = HypothesisStatus.INCONCLUSIVE
    explanation: str = ""

    def to_dict(self) -> dict:
        return {"hypothesis_id": self.hypothesis_id,
                "attempted_tests": list(self.attempted_tests),
                "breaking_facts": list(self.breaking_facts),
                "alternative_explanations_found": list(self.alternative_explanations_found),
                "outcome": self.outcome.value, "explanation": self.explanation}


def falsification_questions(hypothesis: Hypothesis) -> list[str]:
    """§19 standard question set the falsifier must ask."""
    return [
        "what fact would make this hypothesis false?",
        "what identity mismatch could break it?",
        "what timeline conflict could break it?",
        "what source dependency weakens it?",
        "what alternative explanation fits the same facts?",
        "what independent source can test it?",
    ]


class FalsificationEngine:
    def __init__(self, memory: CaseMemory) -> None:
        self.memory = memory

    def test(self, hypothesis: Hypothesis) -> FalsificationReport:
        report = FalsificationReport(hypothesis_id=hypothesis.id)
        report.attempted_tests = falsification_questions(hypothesis)

        # 1) explicitly declared falsification conditions matched by approved facts
        approved = self.memory.approved_facts
        for cond in hypothesis.falsification_conditions:
            low = cond.lower()
            for fact in approved:
                stmt = fact.statement.lower()
                markers = next((ms for k, ms in _FALSIFY_MARKERS.items() if k in low), [])
                hit = any(m in stmt for m in markers) or _topic_overlap(cond, fact.statement)
                if hit and fact.id not in hypothesis.supporting_facts:
                    report.breaking_facts.append(fact.id)

        # 2) opposing facts already recorded against the hypothesis
        for fid in hypothesis.opposing_facts:
            if fid in {f.id for f in approved} and fid not in report.breaking_facts:
                report.breaking_facts.append(fid)

        # 3) alternatives that fit the same evidence better
        for other in self.memory.hypotheses.values():
            if other.id != hypothesis.id and set(other.supporting_facts) >= set(hypothesis.supporting_facts):
                if other not in report.alternative_explanations_found:
                    report.alternative_explanations_found.append(other.statement)

        if report.breaking_facts:
            decisive = len(report.breaking_facts) >= max(1, len(approved) // 2)
            report.outcome = (HypothesisStatus.FALSIFIED if decisive
                              else HypothesisStatus.WEAKENED)
            report.explanation = (
                f"{len(report.breaking_facts)} approved fact(s) contradict the hypothesis; "
                f"outcome={report.outcome.value}. The falsifier defends evidence, not the story.")
        elif report.alternative_explanations_found:
            report.outcome = HypothesisStatus.INCONCLUSIVE
            report.explanation = ("no direct falsifier found, but an alternative explains all "
                                  "supporting facts equally: ambiguity retained (§17)")
        else:
            report.outcome = HypothesisStatus.TESTING
            report.explanation = "no falsifying evidence yet; required tests remain open"
        return report

    def apply(self, hypothesis: Hypothesis, report: FalsificationReport) -> Hypothesis:
        hypothesis.status = report.outcome
        hypothesis.contradictions.extend(report.breaking_facts)
        if report.outcome == HypothesisStatus.FALSIFIED:
            hypothesis.confidence = hypothesis.confidence.VERY_LOW \
                if hasattr(hypothesis.confidence, "VERY_LOW") else hypothesis.confidence
        return hypothesis


def _topic_overlap(a: str, b: str) -> bool:
    ta = {w for w in re.findall(r"[a-z0-9._-]{5,}", a.lower())}
    tb = {w for w in re.findall(r"[a-z0-9._-]{5,}", b.lower())}
    if not ta or not tb:
        return False
    overlap = len(ta & tb) / min(len(ta), len(tb))
    neg_a, neg_b = bool(_NEG.search(a)), bool(_NEG.search(b))
    return overlap >= 0.5 and neg_a != neg_b

"""Analysis of Competing Hypotheses matrix (§18).

Cell values: C=CONSISTENT, I=INCONSISTENT, N=NEUTRAL, ?=UNKNOWN.
Ranking prefers FEWER IMPORTANT inconsistencies — it deliberately does NOT
simply count supporting facts (classic ACH anti-pattern).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.trust.case_memory import CaseMemory
from traceatlas.trust.model import ConfidenceLevel, Fact, Hypothesis

C, I, N, Q = "C", "I", "N", "?"


@dataclass
class ACHMatrix:
    hypotheses: list[Hypothesis]
    facts: list[Fact]
    cells: dict[tuple[str, str], str] = field(default_factory=dict)   # (fact_id, hyp_id) -> char
    important_fact_ids: set[str] = field(default_factory=set)

    def inconsistency_count(self, hyp_id: str) -> int:
        return sum(1 for (fid, hid), v in self.cells.items()
                   if hid == hyp_id and v == I)

    def important_inconsistency_count(self, hyp_id: str) -> int:
        return sum(1 for (fid, hid), v in self.cells.items()
                   if hid == hyp_id and v == I and fid in self.important_fact_ids)

    def ranking(self) -> list[dict]:
        rows = []
        for h in self.hypotheses:
            rows.append({
                "hypothesis_id": h.id,
                "statement": h.statement,
                "inconsistencies": self.inconsistency_count(h.id),
                "important_inconsistencies": self.important_inconsistency_count(h.id),
                "unknowns": sum(1 for (fid, hid), v in self.cells.items()
                                if hid == h.id and v == Q),
            })
        rows.sort(key=lambda r: (r["important_inconsistencies"], r["inconsistencies"]))
        for rank, row in enumerate(rows, start=1):
            row["rank"] = rank
        return rows

    def to_markdown(self) -> str:
        head = "| Fact | " + " | ".join(f"H{i+1}" for i in range(len(self.hypotheses))) + " |"
        sep = "|---" * (len(self.hypotheses) + 1) + "|"
        lines = [head, sep]
        for f in self.facts:
            mark = "*" if f.id in self.important_fact_ids else ""
            row = [f"{f.id[-6:]}{mark}"]
            for h in self.hypotheses:
                row.append(self.cells.get((f.id, h.id), Q))
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")
        lines.append("Legend: C=consistent, I=inconsistent, N=neutral, ?=unknown; "
                     "* marks high-importance facts. Lower (important_)inconsistency rank wins.")
        return "\n".join(lines)


def _fact_consistent_with(fact: Fact, hyp: Hypothesis) -> str | None:
    """Deterministic consistency evaluation via explicit id membership."""
    if fact.id in hyp.supporting_facts:
        return C
    if fact.id in hyp.opposing_facts:
        return I
    return None


def build_matrix(memory: CaseMemory, hypotheses: list[Hypothesis],
                 facts: list[Fact] | None = None) -> ACHMatrix:
    facts = facts if facts is not None else memory.approved_facts
    matrix = ACHMatrix(hypotheses=hypotheses, facts=facts)
    for f in facts:
        if f.confidence in (ConfidenceLevel.HIGH, ConfidenceLevel.VERY_HIGH):
            matrix.important_fact_ids.add(f.id)
        for h in hypotheses:
            verdict = _fact_consistent_with(f, h)
            matrix.cells[(f.id, h.id)] = verdict if verdict else N
    return matrix

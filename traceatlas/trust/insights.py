"""Insight layer (§15): derived ONLY from Fact-Gate-approved facts."""

from __future__ import annotations

from traceatlas.trust.case_memory import CaseMemory
from traceatlas.trust.model import ConfidenceLevel, Insight, TrustError


class InsightGenerationBeforeFactsError(TrustError):
    pass


def generate_insight(memory: CaseMemory, statement: str, supporting_fact_ids: list[str],
                     why_it_matters: str = "", scope: str = "",
                     limitations: list[str] | None = None,
                     confidence: ConfidenceLevel = ConfidenceLevel.MODERATE) -> Insight:
    """Every cited fact must exist in canonical state AND be gate-approved.

    Disputed / rejected facts cannot support insights (they may be referenced as
    contradictions elsewhere). Empty approved-fact sets block insight generation.
    """
    if not memory.approved_facts:
        raise InsightGenerationBeforeFactsError(
            "no approved facts — insights require a gated fact set (§37)")
    approved = {f.id for f in memory.approved_facts}
    bad = [fid for fid in supporting_fact_ids if fid not in approved]
    if bad:
        raise InsightGenerationBeforeFactsError(
            f"insight cites non-approved facts {bad}: insights derive only from gated facts")
    ins = Insight(statement=statement, supporting_fact_ids=supporting_fact_ids,
                  why_it_matters=why_it_matters, scope=scope,
                  limitations=list(limitations or []), confidence=confidence,
                  case_id=memory.case_id)
    return memory.add_insight(ins)

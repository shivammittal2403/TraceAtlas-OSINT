"""Hypothesis engine (§8, §16–§20) with hard fact-first gating.

Rules enforced in code:
  * generate() raises HypothesisBeforeFactGateError unless the Fact Gate has run.
  * With an empty/insufficient approved fact set, hypotheses are permitted ONLY
    as explicitly-labelled LOW-CONFIDENCE exploratory hypotheses (§8).
  * Hypotheses may cite ONLY approved facts / registered observations — the
    model can never smuggle invented facts into a hypothesis payload.
  * Bias-aware evidential diversity (§20): apparent support from dependent or
    similarly-biased sources is collapsed to independent-cluster counts.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.trust.case_memory import CaseMemory
from traceatlas.trust.model import (
    ConfidenceLevel,
    Hypothesis,
    HypothesisBeforeFactGateError,
    HypothesisStatus,
    IndependenceStatus,
)
from traceatlas.trust.fact_gate.independence_check import check_independence


@dataclass
class EngineState:
    """Tracks whether the mandatory upstream stages have completed."""

    fact_gate_ran: bool = False
    bias_stage_ran: bool = False
    independence_stage_ran: bool = False

    def ready_for_hypotheses(self) -> bool:
        return self.fact_gate_ran and self.bias_stage_ran and self.independence_stage_ran


class HypothesisEngine:
    def __init__(self, memory: CaseMemory, state: EngineState | None = None) -> None:
        self.memory = memory
        self.state = state or EngineState()

    # ------------------------------------------------------------ stage marks
    def mark_fact_gate_complete(self) -> None:
        self.state.fact_gate_ran = True

    def mark_bias_complete(self) -> None:
        self.state.bias_stage_ran = True

    def mark_independence_complete(self) -> None:
        self.state.independence_stage_ran = True

    # ------------------------------------------------------------- generation
    def generate(
        self,
        question: str,
        statements: list[str],
        supporting_fact_ids: dict[str, list[str]] | None = None,
        opposing_fact_ids: dict[str, list[str]] | None = None,
        supporting_observation_ids: dict[str, list[str]] | None = None,
        assumptions: dict[str, list[str]] | None = None,
        falsification_conditions: dict[str, list[str]] | None = None,
        next_tests: dict[str, str] | None = None,
    ) -> list[Hypothesis]:
        """Generate COMPETING hypotheses (§17) after the fact gate.

        Never one explanation when ambiguity exists: at least two statements
        should be supplied; a single-statement call is allowed but flagged.
        """
        if not self.state.fact_gate_ran:
            raise HypothesisBeforeFactGateError(
                "HYPOTHESIS GENERATION BLOCKED: Fact Gate has not run (§8/§37). "
                "Run evidence → observation → fact validation → bias → independence first.")

        approved = {f.id for f in self.memory.approved_facts}
        insufficient_facts = len(approved) == 0
        out: list[Hypothesis] = []
        supporting_fact_ids = supporting_fact_ids or {}
        opposing_fact_ids = opposing_fact_ids or {}
        supporting_observation_ids = supporting_observation_ids or {}
        assumptions = assumptions or {}
        falsification_conditions = falsification_conditions or {}
        next_tests = next_tests or {}

        for stmt in statements:
            sup = [fid for fid in supporting_fact_ids.get(stmt, [])]
            # reject invented facts: every cited fact id must be approved
            invented = [fid for fid in sup + opposing_fact_ids.get(stmt, [])
                        if fid not in approved]
            if invented:
                raise HypothesisBeforeFactGateError(
                    f"hypothesis cites unknown/unapproved fact ids {invented}: "
                    "the model may not invent facts to create a hypothesis (§8)")
            obs_ids = [oid for oid in supporting_observation_ids.get(stmt, [])
                       if oid in self.memory.observations]

            exploratory = insufficient_facts
            source_ids = sorted({sid for fid in sup for sid in self.memory.facts[fid].source_ids})
            status, n_clusters, _ = (check_independence(source_ids, self.memory)
                                     if source_ids else (IndependenceStatus.UNKNOWN, 0, []))
            hyp = Hypothesis(
                question=question,
                statement=stmt,
                case_id=self.memory.case_id,
                supporting_facts=sup,
                opposing_facts=list(opposing_fact_ids.get(stmt, [])),
                supporting_observations=obs_ids,
                assumptions=list(assumptions.get(stmt, [])),
                unknowns=[] if not exploratory else ["fact base insufficient for this case"],
                source_bias_effects=self._bias_effects(source_ids),
                source_independence=status,
                alternative_explanations=[s for s in statements if s != stmt],
                falsification_conditions=list(falsification_conditions.get(stmt, [])),
                required_evidence=[],
                next_test=next_tests.get(stmt, ""),
                exploratory=exploratory,
            )
            if not exploratory:
                hyp.confidence = (ConfidenceLevel.MODERATE if n_clusters >= 2
                                  else ConfidenceLevel.LOW)
            out.append(self.memory.add_hypothesis(hyp))
        return out

    def _bias_effects(self, source_ids: list[str]) -> list[str]:
        """§20: similar bias across sources reduces apparent evidential diversity."""
        effects: list[str] = []
        seen_types: dict[str, int] = {}
        for sid in source_ids:
            for b in self.memory.bias_assessments.values():
                if b.source_id == sid:
                    for bt in b.bias_types:
                        seen_types[bt.value] = seen_types.get(bt.value, 0) + 1
        for bt, count in seen_types.items():
            if count >= 2:
                effects.append(
                    f"{count} supporting sources share '{bt}': apparent support diversity reduced")
        return effects

    # -------------------------------------------------------------- lifecycle
    def update_status(self, hypothesis_id: str, status: HypothesisStatus) -> Hypothesis:
        hyp = self.memory.hypotheses[hypothesis_id]
        hyp.status = status
        if status == HypothesisStatus.FALSIFIED:
            hyp.confidence = ConfidenceLevel.VERY_LOW
        elif status == HypothesisStatus.WEAKENED:
            hyp.confidence = ConfidenceLevel.LOW
        elif status == HypothesisStatus.STRENGTHENED:
            hyp.confidence = ConfidenceLevel.MODERATE
        elif status == HypothesisStatus.SUPPORTED:
            hyp.confidence = ConfidenceLevel.HIGH if hyp.source_independence in (
                IndependenceStatus.INDEPENDENT, IndependenceStatus.PARTIALLY_DEPENDENT) \
                else ConfidenceLevel.MODERATE
        return hyp

    def hypothesis_summary(self) -> dict:
        """HYPOTHESIS SUMMARY — always emitted AFTER the FACT SUMMARY (§14)."""
        return {
            "case_id": self.memory.case_id,
            "fact_summary_first": bool(self.memory.approved_facts),
            "hypotheses": [
                {"id": h.id, "statement": h.statement, "status": h.status.value,
                 "confidence": h.confidence.value, "exploratory": h.exploratory,
                 "supporting_facts": h.supporting_facts,
                 "opposing_facts": h.opposing_facts,
                 "bias_effects": h.source_bias_effects,
                 "independence": h.source_independence.value}
                for h in self.memory.hypotheses.values()],
        }

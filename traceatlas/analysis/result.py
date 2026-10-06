"""Strict Pydantic schemas for every AI analytical output (§32).

No prose parsing of mission-critical intelligence: all model outputs must
validate against these schemas or the run is marked MODEL_OUTPUT_INVALID.
Schemas store conclusions, reasons, evidence references and uncertainty only —
never chain-of-thought (§4).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class AnalysisStatement(BaseModel):
    """One atomic analytical assertion produced by a pass."""
    statement: str = Field(min_length=3, max_length=1200)
    kind: Literal["fact", "observation", "insight", "inference",
                  "hypothesis", "contradiction", "unknown", "gap"] = "observation"
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    rationale: str = ""
    entities: list[str] = Field(default_factory=list)
    question_id: str = ""       # investigative question this addresses (§10)

    @field_validator("evidence_ids")
    @classmethod
    def _dedup(cls, v: list[str]) -> list[str]:
        return sorted(set(v))


class PassAnalysis(BaseModel):
    """Output of one independent analysis pass (Pass 1 or Pass 2)."""
    statements: list[AnalysisStatement] = Field(default_factory=list)
    unsupported_claims_flagged: list[str] = Field(default_factory=list)
    alternative_explanations: list[str] = Field(default_factory=list)
    source_limitations: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    recommended_next_actions: list[str] = Field(default_factory=list)
    overall_uncertainty: Literal["low", "medium", "high"] = "medium"


AgreementStatus = Literal["AGREE", "PARTIAL_AGREEMENT", "SEMANTIC_AGREEMENT",
                          "DISAGREE", "PASS1_ONLY", "PASS2_ONLY",
                          "INSUFFICIENT_EVIDENCE"]

AdjudicationVerdict = Literal["SUPPORTED", "PARTIALLY_SUPPORTED", "DISPUTED",
                              "INCONCLUSIVE", "UNSUPPORTED",
                              "HUMAN_REVIEW_REQUIRED"]


class CrossCheckItem(BaseModel):
    """Statement-by-statement comparison row (§6)."""
    statement: str
    pass1_assessment: str = ""
    pass2_assessment: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    agreement_status: AgreementStatus = "INSUFFICIENT_EVIDENCE"
    conflict_reason: Literal["", "evidence_difference", "interpretation_difference",
                             "entity_mismatch", "temporal_mismatch", "source_ambiguity",
                             "unsupported_inference", "missing_evidence",
                             "model_hallucination_candidate", "schema_parser_issue",
                             "semantic_overlap"] = ""
    source_support: Literal["none", "single_source", "multiple_sources",
                            "multiple_independent_sources"] = "none"
    independence: Literal["unknown", "dependent", "partially_independent",
                          "independent"] = "unknown"
    temporal_consistency: Literal["unknown", "consistent", "stale",
                                  "conflicting"] = "unknown"
    ai_reasoning_agreement: bool = False   # §2: reasoning agreement != corroboration
    evidence_corroboration: bool = False   # §2: separate axis
    recommended_resolution: str = ""


class CrossCheckResult(BaseModel):
    case_id: str = ""
    items: list[CrossCheckItem] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)  # status -> count


class AdjudicatedStatement(BaseModel):
    statement: str
    verdict: AdjudicationVerdict
    reason: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    requires_human_review: bool = False


class AdjudicationResult(BaseModel):
    case_id: str = ""
    decisions: list[AdjudicatedStatement] = Field(default_factory=list)
    invoked_because: str = ""    # which trigger from §7 fired


class FinalSynthesis(BaseModel):
    """Machine-readable final synthesis product (§15 subset carried by AI;
    the full FinalInvestigationSynthesis lives in traceatlas/synthesis)."""
    what_we_know: list[str] = Field(default_factory=list)
    what_we_think: list[str] = Field(default_factory=list)
    what_we_do_not_know: list[str] = Field(default_factory=list)
    what_conflicts: list[str] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)
    falsifiers: list[str] = Field(default_factory=list)   # what would disprove it

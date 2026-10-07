"""Dual-analysis result schemas + deterministic evidence grounding.

Core invariant (enforced here, not by prompt etiquette):
  A statement is EVIDENCE_GROUNDED only if every evidence_id it cites
  actually exists in the InvestigationContext. AI agreement between two
  models NEVER substitutes for evidence: both passes hallucinating the same
  unsupported statement still fails grounding.

AI_REASONING_AGREEMENT and EVIDENCE_CORROBORATION are tracked as separate
fields on every cross-checked statement — they must never be conflated.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum


class Importance(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AgreementStatus(str, Enum):
    AGREE = "agree"
    PARTIAL_AGREEMENT = "partial_agreement"
    SEMANTIC_AGREEMENT = "semantic_agreement"
    DISAGREE = "disagree"
    PASS1_ONLY = "pass1_only"
    PASS2_ONLY = "pass2_only"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class AdjudicationOutcome(str, Enum):
    SUPPORTED = "supported"
    PARTIALLY_SUPPORTED = "partially_supported"
    DISPUTED = "disputed"
    INCONCLUSIVE = "inconclusive"
    UNSUPPORTED = "unsupported"
    HUMAN_REVIEW_REQUIRED = "human_review_required"


class StatementKind(str, Enum):
    FACT = "fact"                # directly supported by cited evidence
    OBSERVATION = "observation"  # what a source literally returned
    INSIGHT = "insight"          # why it matters
    INFERENCE = "inference"      # interpretation beyond literal data
    HYPOTHESIS = "hypothesis"    # testable explanation
    UNKNOWN = "unknown"          # explicit gap


@dataclass
class AnalyzedStatement:
    """One conclusion produced by an analysis pass."""
    statement_id: str
    text: str
    kind: StatementKind
    importance: Importance = Importance.MEDIUM
    evidence_ids: list[str] = field(default_factory=list)
    entity_keys: list[str] = field(default_factory=list)
    question: str = ""              # which investigation question it serves
    uncertainty: float = 0.5        # 0 = certain .. 1 = fully uncertain
    reasoning_summary: str = ""     # stored rationale (NOT chain-of-thought)

    def to_dict(self) -> dict:
        return {"statement_id": self.statement_id, "text": self.text,
                "kind": self.kind.value, "importance": self.importance.value,
                "evidence_ids": list(self.evidence_ids),
                "entity_keys": list(self.entity_keys), "question": self.question,
                "uncertainty": self.uncertainty,
                "reasoning_summary": self.reasoning_summary}


@dataclass
class AnalysisPassResult:
    pass_name: str                  # "primary" | "secondary" | "adjudicator"
    model_provider: str
    model_id: str
    statements: list[AnalyzedStatement] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    run_ms: float = 0.0
    degraded: bool = False          # True when AI unavailable & fallback used
    error: str = ""

    def to_dict(self) -> dict:
        return {"pass": self.pass_name, "provider": self.model_provider,
                "model": self.model_id, "degraded": self.degraded,
                "error": self.error, "run_ms": round(self.run_ms, 1),
                "statements": [s.to_dict() for s in self.statements],
                "limitations": list(self.limitations)}


@dataclass
class CrossCheckItem:
    statement: str
    pass1_assessment: str = ""
    pass2_assessment: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    agreement_status: AgreementStatus = AgreementStatus.INSUFFICIENT_EVIDENCE
    conflict_reason: str = ""
    evidence_grounded: bool = False
    independent_source_count: int = 0
    temporal_consistency: str = "unchecked"
    recommended_resolution: str = ""

    def to_dict(self) -> dict:
        return {"statement": self.statement,
                "pass1": self.pass1_assessment, "pass2": self.pass2_assessment,
                "evidence_ids": list(self.evidence_ids),
                "agreement": self.agreement_status.value,
                "conflict_reason": self.conflict_reason,
                "evidence_grounded": self.evidence_grounded,
                "independent_sources": self.independent_source_count,
                "temporal_consistency": self.temporal_consistency,
                "resolution": self.recommended_resolution}


def statement_fingerprint(text: str) -> str:
    """Normalized fingerprint for matching statements across passes.

    Lowercase, collapse whitespace, strip trailing punctuation. Deliberately
    conservative: semantic near-matches fall into PASS1_ONLY/PASS2_ONLY rather
    than being silently merged (preserving disagreement as intelligence).
    """
    norm = " ".join(text.lower().split()).rstrip(".")
    return hashlib.sha256(norm.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# structured-output schema validators (used with BaseProvider.run(schema=...))
# ---------------------------------------------------------------------------

ANALYSIS_SCHEMA_HINT = (
    'JSON: {"statements": [{"text": str, "kind": one of '
    '"fact","observation","insight","inference","hypothesis","unknown", '
    '"importance": "low|medium|high|critical", "evidence_ids": [str], '
    '"entity_keys": [str], "question": str, "uncertainty": 0..1, '
    '"reasoning_summary": str}], "limitations": [str]}')


def validate_analysis_payload(payload: dict) -> tuple[bool, list[str]]:
    errors: list[str] = []
    stmts = payload.get("statements")
    if not isinstance(stmts, list):
        return False, ["'statements' must be a list"]
    valid_kinds = {k.value for k in StatementKind}
    valid_imp = {i.value for i in Importance}
    for i, s in enumerate(stmts):
        if not isinstance(s, dict):
            errors.append(f"statements[{i}] not an object")
            continue
        if not isinstance(s.get("text"), str) or not s["text"].strip():
            errors.append(f"statements[{i}].text missing/empty")
        if s.get("kind") not in valid_kinds:
            errors.append(f"statements[{i}].kind invalid: {s.get('kind')!r}")
        if s.get("importance") not in valid_imp:
            errors.append(f"statements[{i}].importance invalid: {s.get('importance')!r}")
        ev = s.get("evidence_ids", [])
        if not isinstance(ev, list) or any(not isinstance(x, str) for x in ev):
            errors.append(f"statements[{i}].evidence_ids must be list[str]")
        u = s.get("uncertainty", 0.5)
        if not isinstance(u, (int, float)) or not (0.0 <= float(u) <= 1.0):
            errors.append(f"statements[{i}].uncertainty must be 0..1")
    lims = payload.get("limitations", [])
    if not isinstance(lims, list):
        errors.append("'limitations' must be a list")
    return (len(errors) == 0), errors


def parse_analysis_payload(payload: dict, pass_name: str, provider: str,
                           model_id: str) -> AnalysisPassResult:
    res = AnalysisPassResult(pass_name=pass_name, model_provider=provider,
                             model_id=model_id)
    for i, s in enumerate(payload.get("statements", [])):
        fid = statement_fingerprint(s["text"])
        res.statements.append(AnalyzedStatement(
            statement_id=f"{pass_name}:{fid}",
            text=s["text"],
            kind=StatementKind(s["kind"]),
            importance=Importance(s.get("importance", "medium")),
            evidence_ids=list(s.get("evidence_ids", [])),
            entity_keys=list(s.get("entity_keys", [])),
            question=s.get("question", ""),
            uncertainty=float(s.get("uncertainty", 0.5)),
            reasoning_summary=s.get("reasoning_summary", ""),
        ))
    res.limitations = [str(x) for x in payload.get("limitations", [])]
    return res


# ---------------------------------------------------------------------------
# deterministic evidence grounding
# ---------------------------------------------------------------------------

def ground_statements(statements: list[AnalyzedStatement], known_evidence_ids: set[str]
                      ) -> list[tuple[AnalyzedStatement, list[str]]]:
    """Return (statement, unknown_refs) pairs; unknown_refs non-empty => NOT grounded.

    Deterministic check that runs AFTER any AI pass: an AI cannot cite its way
    to credibility with fabricated ids.
    """
    out = []
    for s in statements:
        unknown = [e for e in s.evidence_ids if e not in known_evidence_ids]
        out.append((s, unknown))
    return out

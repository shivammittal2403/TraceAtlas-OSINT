"""Evidence context: canonical, ID-addressable evidence bundle for AI passes.

Everything an analysis pass is allowed to see is assembled here, with stable
evidence IDs so that every model statement can be grounded and later checked
deterministically (evidence grounding §4/§8: statements citing unknown evidence
IDs are treated as hallucination candidates).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from traceatlas.analysis.validation_gate import ValidationResult


@dataclass
class EvidenceItem:
    """One citable piece of evidence exposed to the analysts."""
    evidence_id: str
    source_id: str
    connector_id: str = ""
    summary: str = ""                 # what the data LITERALLY says (§42)
    payload: dict = field(default_factory=dict)
    observation_ids: list[str] = field(default_factory=list)
    event_time: str = ""              # ISO or "" if unknown
    observed_at: str = ""
    validation_status: str = "VALID"  # from deterministic gate (§8)
    validation_issues: list[str] = field(default_factory=list)
    upstream_source_id: str = ""      # lineage: original publisher/upstream (§20)
    limitations: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "source_id": self.source_id,
            "connector_id": self.connector_id,
            "summary": self.summary,
            "payload": self.payload,
            "observation_ids": self.observation_ids,
            "event_time": self.event_time,
            "observed_at": self.observed_at,
            "validation_status": self.validation_status,
            "validation_issues": self.validation_issues,
            "upstream_source_id": self.upstream_source_id,
            "limitations": self.limitations,
        }


@dataclass
class EvidenceContext:
    """Full input context for one dual-analysis run (§4, §5)."""
    case_id: str
    objective: str = ""
    scope: str = ""                                   # authorized scope
    questions: list[dict] = field(default_factory=list)   # [{id, text}]
    evidence: list[EvidenceItem] = field(default_factory=list)
    graph_context: list[dict] = field(default_factory=list)     # edges/nodes
    timeline_context: list[dict] = field(default_factory=list)
    existing_claims: list[dict] = field(default_factory=list)
    existing_hypotheses: list[dict] = field(default_factory=list)
    existing_contradictions: list[dict] = field(default_factory=list)
    determinate_validation: ValidationResult | None = None

    @property
    def evidence_ids(self) -> set[str]:
        return {e.evidence_id for e in self.evidence}

    def evidence_by_id(self) -> dict[str, EvidenceItem]:
        return {e.evidence_id: e for e in self.evidence}

    def render_for_prompt(self, *, include_ids: set[str] | None = None) -> str:
        """Deterministic JSON rendering — identical bytes for both passes when
        the same items are included (isolation guarantee, §33)."""
        items = [e.as_dict() for e in self.evidence
                 if include_ids is None or e.evidence_id in include_ids]
        doc = {
            "case_id": self.case_id,
            "objective": self.objective,
            "authorized_scope": self.scope,
            "investigation_questions": self.questions,
            "evidence": items,
            "graph_context": self.graph_context,
            "timeline_context": self.timeline_context,
            "existing_claims": self.existing_claims,
            "existing_hypotheses": self.existing_hypotheses,
            "existing_contradictions": self.existing_contradictions,
        }
        return json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str)

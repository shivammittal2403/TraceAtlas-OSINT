"""Result protocols (§35): EmployeeResult / ManagerResult / DepartmentResult."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from traceatlas.core.identifiers import new_id


class ResultStatus(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    NO_FINDINGS = "no_findings"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass
class EntityMention:
    kind: str
    value: str
    id: str = field(default_factory=lambda: new_id("em"))


@dataclass
class RelationshipMention:
    source: str
    target: str
    kind: str
    evidence_id: str = ""
    id: str = field(default_factory=lambda: new_id("rm"))


@dataclass
class EventMention:
    description: str
    when: str = ""
    evidence_id: str = ""
    id: str = field(default_factory=lambda: new_id("vm"))


@dataclass
class CandidateFactPayload:
    """What an employee PROPOSES as fact. Promotion happens only via FactGate."""

    statement: str
    evidence_ids: list[str] = field(default_factory=list)
    source_ids: list[str] = field(default_factory=list)
    observation_ids: list[str] = field(default_factory=list)
    entity_ids: list[str] = field(default_factory=list)


@dataclass
class EmployeeResult:
    """§35 result protocol for specialist employees."""

    employee_id: str
    task_id: str
    status: ResultStatus
    observations: list[dict] = field(default_factory=list)       # normalized dicts w/ evidence ids
    candidate_facts: list[CandidateFactPayload] = field(default_factory=list)
    entities: list[EntityMention] = field(default_factory=list)
    relationships: list[RelationshipMention] = field(default_factory=list)
    events: list[EventMention] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    source_ids: list[str] = field(default_factory=list)
    bias_notes: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    suggested_next_actions: list[str] = field(default_factory=list)
    confidence: str = "unknown"
    cost_used: float = 0.0
    latency_ms: int = 0
    schema_compliant: bool = True
    id: str = field(default_factory=lambda: new_id("er"))

    def to_dict(self) -> dict:
        return {k: (v.value if isinstance(v, Enum) else v) for k, v in self.__dict__.items()}


@dataclass
class ManagerResult:
    """Synthesized department-level output (§35/§36)."""

    manager_id: str
    task_id: str
    status: ResultStatus
    merged_results: list[EmployeeResult] = field(default_factory=list)
    duplicates_removed: int = 0
    disagreements: list[str] = field(default_factory=list)
    department_assessment: str = ""
    gaps: list[str] = field(default_factory=list)
    handoff_requests: list[dict] = field(default_factory=list)   # cross-department (§23)
    id: str = field(default_factory=lambda: new_id("mr"))


# alias per spec wording
DepartmentResult = ManagerResult

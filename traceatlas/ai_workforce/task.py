"""Typed task protocol (§7, §34).

No worker accepts arbitrary untyped free-form commands: everything is a Task /
TaskAssignment with scope, authorization and evidence requirements attached.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from traceatlas.core.identifiers import new_id


class TaskStatus(str, Enum):
    QUEUED = "queued"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED_COMPLIANCE = "blocked_compliance"
    REASSIGNED = "reassigned"
    CANCELLED = "cancelled"


class Priority(int, Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Scope:
    """Authorized investigation scope."""

    entities: list[str] = field(default_factory=list)     # domains/IPs/orgs in scope
    source_kinds: list[str] = field(default_factory=list)
    max_cost_units: float = 10.0
    max_requests: int = 50
    geography: list[str] = field(default_factory=list)
    time_window: tuple[str, str] | None = None


@dataclass
class Authorization:
    granted_by: str = ""
    basis: str = ""                 # e.g. "public_osint_policy_v1"
    case_id: str = ""
    expires: str = ""
    valid: bool = True


@dataclass
class Task:
    question: str                    # an intelligence question, not free chat
    case_id: str
    objective: str = ""
    parent_task: str | None = None
    manager: str = ""
    employee: str | None = None
    required_skills: list[str] = field(default_factory=list)
    inputs: dict = field(default_factory=dict)
    scope: Scope = field(default_factory=Scope)
    authorization: Authorization = field(default_factory=Authorization)
    evidence_requirements: list[str] = field(default_factory=list)  # e.g. ["primary_source_capture"]
    priority: Priority = Priority.NORMAL
    budget_cost: float = 1.0
    deadline: str = ""
    status: TaskStatus = TaskStatus.QUEUED
    id: str = field(default_factory=lambda: new_id("task"))

    def validate_contract(self) -> list[str]:
        """§34: tasks must be typed and complete before any worker accepts one."""
        problems = []
        if not self.question.strip():
            problems.append("task has no intelligence question")
        if not self.case_id:
            problems.append("task missing case_id")
        if not self.required_skills:
            problems.append("task declares no required_skills")
        if not self.authorization.valid:
            problems.append("task authorization invalid/expired")
        if not self.evidence_requirements:
            problems.append("task declares no evidence_requirements")
        return problems


@dataclass
class TaskAssignment:
    """Manager→employee delegation record (§7)."""

    task_id: str
    manager_id: str
    employee_id: str
    mission: str
    question: str
    inputs: dict = field(default_factory=dict)
    scope: Scope = field(default_factory=Scope)
    authorization: Authorization = field(default_factory=Authorization)
    required_skills: list[str] = field(default_factory=list)
    required_outputs: list[str] = field(default_factory=list)
    evidence_requirements: list[str] = field(default_factory=list)
    deadline: str = ""
    budget: float = 1.0
    priority: Priority = Priority.NORMAL
    id: str = field(default_factory=lambda: new_id("assign"))

    @classmethod
    def from_task(cls, task: Task, manager_id: str, employee_id: str,
                  mission: str) -> "TaskAssignment":
        return cls(
            task_id=task.id, manager_id=manager_id, employee_id=employee_id,
            mission=mission, question=task.question, inputs=dict(task.inputs),
            scope=task.scope, authorization=task.authorization,
            required_skills=list(task.required_skills),
            required_outputs=["observations", "candidate_facts", "evidence_ids"],
            evidence_requirements=list(task.evidence_requirements),
            deadline=task.deadline, budget=task.budget_cost, priority=task.priority,
        )

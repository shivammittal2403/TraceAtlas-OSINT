"""Specialist AI Employee runtime (§4, §6, §28).

An employee is NOT a persona prompt. It is an executable unit with:
  * a JobDescription (mission, responsibilities, contracts, quality gates),
  * a skill manifest — it may execute ONLY declared skills (§5),
  * a PermissionSet enforced outside any model prompt (§30),
  * deterministic handlers registered per skill (real code paths),
  * budget accounting and performance metrics (§28).

Execution contract:
  Task -> validate_contract() -> permission/skill checks -> handler(inputs)
       -> EmployeeResult (typed, §35). Handlers return raw payloads; the
  employee wraps them into the result protocol and records metrics. A missing
  handler or denied action produces status BLOCKED/FAILED — never fabricated
  findings.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from traceatlas.ai_workforce.permissions import GLOBAL_PROHIBITED, PermissionSet
from traceatlas.ai_workforce.result import EmployeeResult, ResultStatus
from traceatlas.ai_workforce.task import Task, TaskAssignment
from traceatlas.core.identifiers import new_id


@dataclass
class JobDescription:
    """§6 — explicit job description prevents generic 'do anything' agents."""

    role: str
    mission: str
    responsibilities: list[str] = field(default_factory=list)
    accepted_tasks: list[str] = field(default_factory=list)      # task kinds
    required_skills: list[str] = field(default_factory=list)
    required_evidence: list[str] = field(default_factory=list)   # evidence req tags
    allowed_sources: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    prohibited_actions: list[str] = field(default_factory=list)
    expected_output: str = "EmployeeResult"
    quality_threshold: str = "schema_compliant_and_evidenced"
    escalation_conditions: list[str] = field(default_factory=list)

    def accepts_task(self, task: Task) -> bool:
        kind = task.inputs.get("task_kind", "")
        if not self.accepted_tasks:
            return False
        return kind in self.accepted_tasks or not kind


@dataclass
class ModelPolicy:
    """§43 — every employee declares its model policy; local-only capable."""

    provider: str = "deterministic"     # deterministic|ollama|openai|anthropic|...
    model: str = ""
    allow_cloud: bool = True
    fallback: str = "deterministic"

    def usable_in_local_only_mode(self) -> bool:
        return self.provider in ("deterministic", "ollama")


@dataclass
class EmployeeMetrics:
    """§28 — performance tracked on evidence grounding, never verbosity."""

    tasks_completed: int = 0
    tasks_failed: int = 0
    tasks_blocked: int = 0
    unsupported_claims: int = 0
    schema_violations: int = 0
    human_corrections: int = 0
    total_cost: float = 0.0
    total_latency_ms: int = 0
    handoffs_accepted: int = 0

    @property
    def evidence_grounding_rate(self) -> float:
        total = self.tasks_completed + self.unsupported_claims
        return 1.0 if total == 0 else self.tasks_completed / total


class Employee:
    def __init__(
        self,
        name: str,
        role: str,
        department: str,
        job: JobDescription,
        skills: list[str],
        permissions: PermissionSet | None = None,
        model_policy: ModelPolicy | None = None,
        cost_per_call: float = 0.0,
        employee_id: str | None = None,
    ) -> None:
        self.id = employee_id or new_id("emp")
        self.name = name
        self.role = role
        self.department = department
        self.job = job
        self.skills = set(skills)
        self.permissions = permissions or PermissionSet(
            allowed_actions=set(skills),
            prohibited_actions=set(job.prohibited_actions) | GLOBAL_PROHIBITED,
            allowed_source_kinds=set(job.allowed_sources),
        )
        self.model_policy = model_policy or ModelPolicy()
        self.cost_per_call = cost_per_call
        self.metrics = EmployeeMetrics()
        self._handlers: dict[str, Callable[[dict], dict]] = {}
        self.health = "ready"          # ready | degraded | unhealthy
        self.workload = 0

    # ------------------------------------------------------------ registration
    def register_handler(self, skill: str, fn: Callable[[dict], dict]) -> None:
        """Bind REAL code to a declared skill. Undeclared skills are rejected."""
        if skill not in self.skills:
            raise ValueError(
                f"{self.name} cannot register handler for undeclared skill {skill!r} (§5)")
        self._handlers[skill] = fn

    # ------------------------------------------------------------- delegation
    def can_accept(self, assignment: TaskAssignment) -> tuple[bool, list[str]]:
        problems: list[str] = []
        if self.health == "unhealthy":
            problems.append(f"employee {self.name} is unhealthy")
        missing = [s for s in assignment.required_skills if s not in self.skills]
        if missing:
            problems.append(f"missing required skills: {missing}")
        if not assignment.authorization.valid:
            problems.append("assignment authorization invalid/expired")
        for skill in assignment.required_skills:
            if not self.permissions.can(skill):
                problems.append(f"action {skill!r} not permitted by policy")
        return (not problems), problems

    # --------------------------------------------------------------- execute
    def run(self, task: Task, primary_skill: str | None = None) -> EmployeeResult:
        start = time.monotonic()
        base_kwargs = dict(employee_id=self.id, task_id=task.id)

        problems = task.validate_contract()
        if problems:
            self.metrics.tasks_blocked += 1
            return EmployeeResult(status=ResultStatus.BLOCKED,
                                  limitations=["task contract invalid: " + "; ".join(problems)],
                                  **base_kwargs)

        skill = primary_skill or (task.required_skills[0] if task.required_skills else "")
        if skill not in self.skills:
            self.metrics.tasks_blocked += 1
            return EmployeeResult(status=ResultStatus.BLOCKED,
                                  limitations=[f"skill {skill!r} not in manifest of {self.name} (§5)"],
                                  **base_kwargs)
        if not self.permissions.can(skill):
            self.metrics.tasks_blocked += 1
            return EmployeeResult(status=ResultStatus.BLOCKED,
                                  limitations=[f"permission denied for action {skill!r} (§30)"],
                                  **base_kwargs)
        handler = self._handlers.get(skill)
        if handler is None:
            self.metrics.tasks_failed += 1
            return EmployeeResult(status=ResultStatus.FAILED,
                                  limitations=[f"no real implementation bound to skill {skill!r}; "
                                               "refusing to fabricate findings"],
                                  **base_kwargs)
        self.workload += 1
        try:
            payload = handler(dict(task.inputs))
        except Exception as exc:  # structured failure, never invented data
            self.workload -= 1
            self.metrics.tasks_failed += 1
            return EmployeeResult(status=ResultStatus.FAILED,
                                  limitations=[f"handler error: {type(exc).__name__}: {exc}"],
                                  **base_kwargs)
        self.workload -= 1
        self.metrics.tasks_completed += 1
        self.metrics.total_cost += self.cost_per_call
        latency = int((time.monotonic() - start) * 1000)
        self.metrics.total_latency_ms += latency

        result = EmployeeResult(**base_kwargs, **_normalize_payload(payload))
        result.cost_used = self.cost_per_call
        result.latency_ms = latency
        if result.candidate_facts and not all(
                cf.evidence_ids and cf.source_ids for cf in result.candidate_facts):
            self.metrics.unsupported_claims += 1
            result.limitations.append(
                "some candidate facts lack full evidence/source citation — Fact Gate will demote them")
        return result


def _normalize_payload(payload: dict) -> dict:
    """Coerce a handler payload into EmployeeResult fields (schema compliance)."""
    known = {"observations", "candidate_facts", "entities", "relationships", "events",
             "evidence_ids", "source_ids", "bias_notes", "limitations", "contradictions",
             "unknowns", "suggested_next_actions", "confidence", "status"}
    out = {k: v for k, v in payload.items() if k in known}
    out.setdefault("status", ResultStatus.OK)
    if isinstance(out["status"], str):
        try:
            out["status"] = ResultStatus(out["status"])
        except ValueError:
            out["status"] = ResultStatus.FAILED
    return out

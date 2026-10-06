"""Task: a unit of work assigned to an employee/worker."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from traceatlas.core.enums import TaskStatus
from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable
from traceatlas.core.validation import utcnow


@dataclass
class Task:
    case_id: str
    kind: str                     # e.g. "collect.dns", "verify.claim"
    payload: dict = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    depends_on: list[str] = field(default_factory=list)
    assigned_employee: str = ""
    attempts: int = 0
    max_attempts: int = 3
    cost_estimate_units: float = 0.0
    created_at: datetime = field(default_factory=utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    id: str = field(default_factory=lambda: new_id("task"))

    def can_retry(self) -> bool:
        return self.attempts < self.max_attempts

    def to_dict(self) -> dict:
        return to_jsonable(self)

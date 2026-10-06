"""Employee base class: governed unit of AI labor."""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.identifiers import new_id


@dataclass
class EmployeeContext:
    case_id: str
    investigation_id: str
    scope_summary: str = ""
    budget_remaining_units: float = 0.0


class BaseEmployee:
    """All employees are manifest-driven, permission-bounded and auditable."""

    name: str = "base"
    allowed_task_kinds: tuple[str, ...] = ()

    def __init__(self) -> None:
        self.employee_id = new_id("emp")

    def can_handle(self, task_kind: str) -> bool:
        return task_kind in self.allowed_task_kinds

    def execute(self, task, context: EmployeeContext):
        raise NotImplementedError(f"{self.name}: execute() not implemented")

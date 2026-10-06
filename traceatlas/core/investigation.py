"""Investigation: a planned, executed attempt to answer an Objective."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from traceatlas.core.enums import InvestigationStatus
from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable
from traceatlas.core.validation import utcnow


@dataclass
class Investigation:
    case_id: str
    objective_id: str
    status: InvestigationStatus = InvestigationStatus.DRAFT
    plan_id: str | None = None
    budget_max_cost_units: float = 100.0
    cost_units_spent: float = 0.0
    started_at: datetime | None = None
    finished_at: datetime | None = None
    id: str = field(default_factory=lambda: new_id("inv"))
    created_at: datetime = field(default_factory=utcnow)

    def budget_remaining(self) -> float:
        return max(0.0, self.budget_max_cost_units - self.cost_units_spent)

    def to_dict(self) -> dict:
        return to_jsonable(self)

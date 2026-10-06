"""Budget: cost and quota ceilings enforced before dispatching work."""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.exceptions import BudgetExceeded
from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable


@dataclass
class Budget:
    scope_id: str                    # investigation or case id
    max_cost_units: float = 100.0
    max_requests_per_source: int = 50
    spent_cost_units: float = 0.0
    requests_per_source: dict = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("bud"))

    def check(self, cost_units: float = 0.0, source_id: str = "") -> None:
        if self.spent_cost_units + cost_units > self.max_cost_units:
            raise BudgetExceeded("cost budget exhausted")
        if source_id and self.requests_per_source.get(source_id, 0) >= self.max_requests_per_source:
            raise BudgetExceeded(f"per-source request cap reached for {source_id}")

    def consume(self, cost_units: float = 0.0, source_id: str = "") -> None:
        self.check(cost_units, source_id)
        self.spent_cost_units += cost_units
        if source_id:
            self.requests_per_source[source_id] = self.requests_per_source.get(source_id, 0) + 1

    def to_dict(self) -> dict:
        return to_jsonable(self)

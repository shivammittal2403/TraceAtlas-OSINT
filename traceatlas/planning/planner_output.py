"""Plan data structures produced by the planner."""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable


@dataclass
class PlannedTask:
    kind: str                       # task kind, e.g. "collect.dns"
    payload: dict = field(default_factory=dict)
    depends_on_kinds: list[str] = field(default_factory=list)
    cost_estimate_units: float = 1.0
    wave: int = 0
    requires_human_approval: bool = False
    id: str = field(default_factory=lambda: new_id("ptask"))


@dataclass
class Plan:
    objective_spec_id: str
    tasks: list[PlannedTask] = field(default_factory=list)
    stop_conditions: list[str] = field(default_factory=list)
    estimated_cost_units: float = 0.0
    estimated_waves: int = 0
    warnings: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: new_id("plan"))

    def to_dict(self) -> dict:
        return to_jsonable(self)

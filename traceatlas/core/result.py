"""Result: outcome envelope returned by a task execution."""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable


@dataclass
class Result:
    task_id: str
    ok: bool
    observations: list[dict] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    error: str = ""
    cost_units_spent: float = 0.0
    duration_ms: int = 0
    id: str = field(default_factory=lambda: new_id("res"))

    def to_dict(self) -> dict:
        return to_jsonable(self)

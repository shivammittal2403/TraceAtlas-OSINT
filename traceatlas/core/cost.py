"""Cost accounting primitives (abstract 'cost units', USD mapping is per-source)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CostLedger:
    entries: list[dict] = field(default_factory=list)

    def record(self, *, scope_id: str, actor: str, cost_units: float, note: str = "") -> None:
        self.entries.append(
            {"scope_id": scope_id, "actor": actor, "cost_units": cost_units, "note": note}
        )

    @property
    def total(self) -> float:
        return sum(e["cost_units"] for e in self.entries)

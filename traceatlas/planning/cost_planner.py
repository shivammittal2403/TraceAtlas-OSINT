"""Sum planned cost estimates; refuse plans exceeding remaining budget."""

from __future__ import annotations

from traceatlas.planning.planner_output import Plan


def estimate_cost(plan: Plan) -> float:
    return round(sum(t.cost_estimate_units for t in plan.tasks), 3)

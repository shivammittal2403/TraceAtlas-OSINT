"""Structural validation of a plan before execution may start."""

from __future__ import annotations

from traceatlas.planning.planner_output import Plan


def validate_plan(plan: Plan) -> list[str]:
    problems: list[str] = []
    kinds = {t.kind for t in plan.tasks}
    for t in plan.tasks:
        for dep in t.depends_on_kinds:
            if dep not in kinds:
                problems.append(f"task {t.kind} depends on unknown kind {dep}")
    if not any(k.startswith("report.") for k in kinds):
        problems.append("plan produces no report task")
    if not any(k.startswith("verify.") for k in kinds):
        problems.append("plan contains no verification step — claims would be unverified")
    return problems

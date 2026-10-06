"""Assign execution waves via topological layering over kind dependencies."""

from __future__ import annotations

from traceatlas.exceptions import ValidationError
from traceatlas.planning.planner_output import Plan


def assign_waves(plan: Plan) -> None:
    by_kind = {t.kind: t for t in plan.tasks}
    depth: dict[str, int] = {}

    def resolve(kind: str, stack: set[str]) -> int:
        if kind in stack:
            raise ValidationError(f"cyclic dependency at {kind}")
        if kind in depth:
            return depth[kind]
        task = by_kind.get(kind)
        deps = task.depends_on_kinds if task else []
        d = 0 if not deps else 1 + max(resolve(x, stack | {kind}) for x in deps)
        depth[kind] = d
        return d

    for t in plan.tasks:
        t.wave = resolve(t.kind, set())

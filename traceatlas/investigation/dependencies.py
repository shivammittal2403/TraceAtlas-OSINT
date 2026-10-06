"""Dependency resolution helpers bridging PlannedTask kinds to Task ids."""

from __future__ import annotations

from traceatlas.core.task import Task
from traceatlas.planning.planner_output import PlannedTask


def plan_to_tasks(plan_tasks: list[PlannedTask], case_id: str,
                  investigation_id: str) -> list[Task]:
    """Instantiate core Tasks from planned tasks, wiring kind-deps to id-deps."""
    by_kind: dict[str, str] = {}
    created: list[Task] = []
    kind_to_task: dict[str, Task] = {}
    for pt in plan_tasks:
        t = Task(case_id=case_id, kind=pt.kind,
                 payload={**pt.payload, "investigation_id": investigation_id,
                          "planned_task_id": pt.id},
                 cost_estimate_units=pt.cost_estimate_units)
        created.append(t)
        kind_to_task[pt.kind] = t
        by_kind.setdefault(pt.kind, t.id)
    for pt, t in zip(plan_tasks, created):
        t.depends_on = [by_kind[k] for k in pt.depends_on_kinds if k in by_kind]
    return created


def unsatisfied_dependencies(task: Task, tasks_by_id: dict[str, Task]) -> list[str]:
    return [d for d in task.depends_on
            if d in tasks_by_id and tasks_by_id[d].status.value != "succeeded"]

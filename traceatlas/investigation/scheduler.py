"""Wave scheduler: orders ready tasks into waves respecting the DAG."""

from __future__ import annotations

from traceatlas.core.enums import TaskStatus
from traceatlas.core.task import Task
from traceatlas.investigation.task_graph import CycleError, TaskGraph


class Scheduler:
    def __init__(self, graph: TaskGraph) -> None:
        self.graph = graph

    def next_wave(self) -> list[Task]:
        return sorted(self.graph.ready_tasks(), key=lambda t: (-t.cost_estimate_units, t.kind))

    def plan_waves(self) -> list[list[Task]]:
        """Full static schedule from current DAG state."""
        waves_ids = self.graph.topo_waves()
        return [[self.graph.tasks[tid] for tid in w] for w in waves_ids]

    def mark_ready(self) -> None:
        for t in self.graph.tasks.values():
            if t.status == TaskStatus.PENDING and self.graph.is_ready(t.id):
                t.status = TaskStatus.READY

    def skip_downstream_of_failed(self) -> list[Task]:
        """Tasks whose dependencies can never succeed get SKIPPED."""
        skipped: list[Task] = []
        changed = True
        while changed:
            changed = False
            for t in self.graph.tasks.values():
                if t.status not in (TaskStatus.PENDING, TaskStatus.READY):
                    continue
                parents = self.graph.parents.get(t.id, set())
                blocked = any(self.graph.tasks[p].status in
                              (TaskStatus.FAILED, TaskStatus.SKIPPED, TaskStatus.CANCELLED)
                              for p in parents)
                if blocked:
                    t.status = TaskStatus.SKIPPED
                    skipped.append(t)
                    changed = True
        return skipped

    __all__ = ["Scheduler", "CycleError"]

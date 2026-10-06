"""DAG over Task records: topological waves, cycle detection, readiness."""

from __future__ import annotations

from collections import defaultdict, deque

from traceatlas.core.enums import TaskStatus
from traceatlas.core.task import Task


class CycleError(Exception):
    pass


class TaskGraph:
    def __init__(self, tasks: list[Task] | None = None) -> None:
        self.tasks: dict[str, Task] = {}
        self.parents: dict[str, set[str]] = defaultdict(set)   # task -> deps it waits on
        self.children: dict[str, set[str]] = defaultdict(set)
        for t in tasks or []:
            self.add(t)

    def add(self, task: Task) -> None:
        self.tasks[task.id] = task
        for dep in task.depends_on:
            if dep not in self.tasks:
                raise KeyError(f"task {task.id} depends on unknown task {dep}")
            self.parents[task.id].add(dep)
            self.children[dep].add(task.id)

    def is_ready(self, task_id: str) -> bool:
        return all(self.tasks[d].status == TaskStatus.SUCCEEDED
                   for d in self.parents.get(task_id, set()))

    def ready_tasks(self) -> list[Task]:
        out = []
        for t in self.tasks.values():
            if t.status in (TaskStatus.PENDING, TaskStatus.READY) and self.is_ready(t.id):
                out.append(t)
        return out

    def topo_waves(self) -> list[list[str]]:
        """Layered topological order; raises CycleError on cycles."""
        indeg = {tid: len(self.parents.get(tid, set())) for tid in self.tasks}
        q = deque(sorted(tid for tid, d in indeg.items() if d == 0))
        waves: list[list[str]] = []
        seen = 0
        while q:
            wave = sorted(q)
            waves.append(wave)
            nxt: list[str] = []
            for tid in wave:
                seen += 1
                for child in self.children.get(tid, set()):
                    indeg[child] -= 1
                    if indeg[child] == 0:
                        nxt.append(child)
            q = deque(sorted(nxt))
        if seen != len(self.tasks):
            raise CycleError("dependency cycle detected in task graph")
        return waves

    def downstream(self, task_id: str) -> set[str]:
        out: set[str] = set()
        q = deque([task_id])
        while q:
            for c in self.children.get(q.popleft(), set()):
                if c not in out:
                    out.add(c)
                    q.append(c)
        return out

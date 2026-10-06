"""Progress tracking: wave/task accounting surfaced to UI and CLI."""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.enums import TaskStatus


@dataclass
class ProgressSnapshot:
    total_tasks: int
    succeeded: int
    failed: int
    skipped: int
    running: int
    pending: int
    current_wave: int
    percent: float
    cost_units_spent: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_tasks": self.total_tasks, "succeeded": self.succeeded,
            "failed": self.failed, "skipped": self.skipped, "running": self.running,
            "pending": self.pending, "current_wave": self.current_wave,
            "percent": round(self.percent, 1),
            "cost_units_spent": round(self.cost_units_spent, 3),
        }


class ProgressTracker:
    def __init__(self, total_tasks: int = 0, budget: float = 100.0) -> None:
        self.total_tasks = total_tasks
        self.counts: dict[str, int] = {s.value: 0 for s in TaskStatus}
        self.current_wave = 0
        self.budget = budget
        self.cost_spent = 0.0
        self.listeners: list = field(default_factory=list) if False else []

    def set_wave(self, wave: int) -> None:
        self.current_wave = wave

    def update(self, task: "object", new_status: TaskStatus) -> None:
        old = getattr(task, "status", None)
        if old is not None:
            self.counts[old.value] = max(0, self.counts.get(old.value, 0) - 1)
        self.counts[new_status.value] = self.counts.get(new_status.value, 0) + 1
        for fn in self.listeners:
            fn(self.snapshot())

    def charge(self, units: float) -> None:
        self.cost_spent += units

    def snapshot(self) -> ProgressSnapshot:
        finished = self.counts[TaskStatus.SUCCEEDED.value] + \
            self.counts[TaskStatus.FAILED.value] + self.counts[TaskStatus.SKIPPED.value]
        pct = (finished / self.total_tasks * 100.0) if self.total_tasks else 0.0
        return ProgressSnapshot(
            total_tasks=self.total_tasks,
            succeeded=self.counts[TaskStatus.SUCCEEDED.value],
            failed=self.counts[TaskStatus.FAILED.value],
            skipped=self.counts[TaskStatus.SKIPPED.value],
            running=self.counts[TaskStatus.RUNNING.value],
            pending=self.counts[TaskStatus.PENDING.value] + self.counts[TaskStatus.READY.value],
            current_wave=self.current_wave, percent=pct, cost_units_spent=self.cost_spent,
        )

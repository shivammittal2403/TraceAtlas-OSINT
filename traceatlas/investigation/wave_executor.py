"""Executes one wave of dependency-independent tasks (bounded concurrency)."""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.enums import TaskStatus
from traceatlas.core.task import Task
from traceatlas.investigation.cancellation import CancellationToken
from traceatlas.investigation.executor import ExecutionOutcome, TaskExecutor
from traceatlas.investigation.parallel_executor import ParallelRunner


@dataclass
class WaveResult:
    wave: int
    outcomes: list[ExecutionOutcome] = field(default_factory=list)

    @property
    def failed(self) -> list[ExecutionOutcome]:
        return [o for o in self.outcomes if o.status == TaskStatus.FAILED]

    @property
    def succeeded(self) -> list[ExecutionOutcome]:
        return [o for o in self.outcomes if o.status == TaskStatus.SUCCEEDED]

    @property
    def all_ok(self) -> bool:
        return not self.failed and not any(
            o.status == TaskStatus.CANCELLED for o in self.outcomes)


class WaveExecutor:
    def __init__(self, executor: TaskExecutor, max_parallel: int = 4) -> None:
        self.executor = executor
        self.max_parallel = max(1, max_parallel)

    def run_wave(self, wave: int, tasks: list[Task], ctx: object,
                 token: CancellationToken | None = None) -> WaveResult:
        token = token or CancellationToken(name=f"wave:{wave}")
        result = WaveResult(wave=wave)
        runners = [(t, lambda t=t, tk=self._child(token): self.executor.execute(t, ctx, tk))
                   for t in tasks]
        # deterministic order-preserving parallel execution with bounded workers
        outcomes = ParallelRunner(max_workers=self.max_parallel).map(runners)
        for o in outcomes:
            result.outcomes.append(o)
            if o.status == TaskStatus.SUCCEEDED:
                pass  # context accounting happens in the engine loop
        return result

    @staticmethod
    def _child(token: CancellationToken) -> CancellationToken:
        return token.child("wave-task")

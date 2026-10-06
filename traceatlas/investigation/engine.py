"""Investigation engine: plan -> waves -> knowledge context -> outcome.

The engine is the deterministic heart of TraceAtlas. It does NOT call LLMs;
it executes a validated Plan by mapping task kinds to transform-backed or
analysis-backed runners, respecting budget, kill switch and cancellation at
every dispatch. Output is an InvestigationContext populated exclusively with
evidence-linked entities/relationships produced by real connectors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from traceatlas.core.enums import TaskStatus
from traceatlas.core.objective_spec import ObjectiveSpec
from traceatlas.core.task import Task
from traceatlas.investigation.audit import AuditTrail
from traceatlas.investigation.cancellation import CancelledError, CancellationToken
from traceatlas.investigation.checkpoints import CheckpointStore
from traceatlas.investigation.context import InvestigationContext
from traceatlas.investigation.executor import ExecutionOutcome, TaskExecutor
from traceatlas.investigation.kill_switch import KillSwitch
from traceatlas.investigation.progress import ProgressTracker
from traceatlas.investigation.resumability import build_checkpoint
from traceatlas.investigation.retry import RetryPolicy
from traceatlas.investigation.scheduler import Scheduler
from traceatlas.investigation.task_graph import TaskGraph
from traceatlas.investigation.wave_executor import WaveExecutor, WaveResult
from traceatlas.planning.planner_output import Plan

Runner = Callable[[Task, InvestigationContext], tuple[bool, str]]


@dataclass
class EngineResult:
    status: str                    # completed | failed | cancelled | budget_exhausted
    context: InvestigationContext
    waves: list[WaveResult] = field(default_factory=list)
    outcomes: list[ExecutionOutcome] = field(default_factory=list)
    stop_reason: str = ""

    @property
    def summary(self) -> dict:
        s = self.context.to_summary()
        s.update({"status": self.status, "stop_reason": self.stop_reason,
                  "waves_run": len(self.waves)})
        return s


class InvestigationEngine:
    def __init__(self, runners: dict[str, Runner], capture_root: str = ".traceatlas-evidence",
                 max_parallel: int = 4, budget_units: float = 100.0,
                 audit: AuditTrail | None = None,
                 kill_switch: KillSwitch | None = None,
                 checkpoint_store: CheckpointStore | None = None,
                 retry_policy: RetryPolicy | None = None) -> None:
        self.runners = runners
        self.max_parallel = max_parallel
        self.budget_units = budget_units
        self.audit = audit or AuditTrail()
        self.kill_switch = kill_switch or KillSwitch()
        self.checkpoints = checkpoint_store or CheckpointStore()
        self.retry_policy = retry_policy or RetryPolicy()

    # ------------------------------------------------------------------ run
    def run(self, plan: Plan, ctx: InvestigationContext,
            token: CancellationToken | None = None) -> EngineResult:
        token = token or CancellationToken(name=f"inv:{ctx.investigation_id}")
        tasks = [Task(case_id=ctx.case_id, kind=pt.kind,
                      payload={**pt.payload, "investigation_id": ctx.investigation_id},
                      cost_estimate_units=pt.cost_estimate_units,
                      depends_on=[]) for pt in plan.tasks]
        # wire dependencies by planned kind
        kind_to_id = {t.kind: t.id for t in tasks}
        for pt, t in zip(plan.tasks, tasks):
            t.depends_on = [kind_to_id[k] for k in pt.depends_on_kinds if k in kind_to_id]

        graph = TaskGraph(tasks)
        scheduler = Scheduler(graph)
        executor = TaskExecutor(runner=self._dispatch, audit=self.audit,
                                retry_policy=self.retry_policy,
                                kill_switch=self.kill_switch)
        wave_exec = WaveExecutor(executor, max_parallel=self.max_parallel)
        progress = ProgressTracker(total_tasks=len(tasks), budget=self.budget_units)

        result = EngineResult(status="running", context=ctx)
        try:
            for wave_no, wave_tasks in enumerate(scheduler.plan_waves()):
                token.check()
                self.kill_switch.check()
                if ctx.budget_exhausted():
                    result.status = "budget_exhausted"
                    result.stop_reason = "BUDGET_EXHAUSTED"
                    break
                runnable = [t for t in wave_tasks if t.status in (TaskStatus.PENDING, TaskStatus.READY)]
                if not runnable:
                    continue
                progress.set_wave(wave_no)
                wr = wave_exec.run_wave(wave_no, runnable, ctx, token)
                result.waves.append(wr)
                result.outcomes.extend(wr.outcomes)
                for o in wr.outcomes:
                    t = graph.tasks[o.task_id]
                    progress.update(t, o.status)
                    if o.status == TaskStatus.SUCCEEDED:
                        ctx.charge(t.cost_estimate_units)
                        ctx.completed_task_kinds.append(t.kind)
                    elif o.status == TaskStatus.FAILED:
                        ctx.errors.append(f"{t.kind}: {o.error}")
                scheduler.skip_downstream_of_failed()
                self.checkpoints.write(build_checkpoint(ctx.investigation_id, ctx,
                                                        list(graph.tasks.values()), wave_no))
            else:
                failed = [o for o in result.outcomes if o.status == TaskStatus.FAILED]
                skipped = sum(1 for t in graph.tasks.values() if t.status == TaskStatus.SKIPPED)
                if failed and len(failed) + skipped == len(tasks):
                    result.status = "failed"
                    result.stop_reason = "SYSTEM_FAILURE"
                else:
                    result.status = "completed"
                    result.stop_reason = ("SOURCES_EXHAUSTED" if failed else
                                          "OBJECTIVE_SATISFIED")
        except CancelledError as ce:
            result.status = "cancelled"
            result.stop_reason = "CANCELLED" if ce.scope != "kill_switch" else "POLICY_BLOCK"
            ctx.errors.append(str(ce))
        return result

    # -------------------------------------------------------------- dispatch
    def _dispatch(self, task: Task, ctx: object) -> tuple[bool, str]:
        """Kill-switch-safe runner selection; unknown kinds fail honestly."""
        self.kill_switch.check()
        runner = self.runners.get(task.kind)
        if runner is None:
            return False, f"no runner registered for task kind {task.kind!r}"
        return runner(task, ctx)  # type: ignore[arg-type]

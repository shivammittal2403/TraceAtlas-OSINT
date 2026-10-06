"""Single-task executor: runs one Task with timeout, cancellation and retry."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from traceatlas.core.enums import TaskStatus
from traceatlas.core.task import Task
from traceatlas.investigation.audit import AuditTrail
from traceatlas.investigation.cancellation import CancelledError, CancellationToken
from traceatlas.investigation.kill_switch import KillSwitch
from traceatlas.investigation.retry import RetryPolicy
from traceatlas.investigation.state import task_transition
from traceatlas.investigation.timeout import TaskTimeout, TimeoutGuard

# A TaskRunner takes (task, context) and returns (ok: bool, error: str).
TaskRunner = Callable[[Task, object], tuple[bool, str]]


@dataclass
class ExecutionOutcome:
    task_id: str
    kind: str
    status: TaskStatus
    attempts: int
    duration_ms: float
    error: str = ""
    retried: bool = False


class TaskExecutor:
    def __init__(self, runner: TaskRunner, audit: AuditTrail | None = None,
                 retry_policy: RetryPolicy | None = None,
                 kill_switch: KillSwitch | None = None,
                 default_timeout_s: float = 60.0,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.runner = runner
        self.audit = audit or AuditTrail()
        self.retry = retry_policy or RetryPolicy()
        self.kill_switch = kill_switch or KillSwitch()
        self.default_timeout_s = default_timeout_s
        self._sleep = sleep

    def execute(self, task: Task, ctx: object,
                token: CancellationToken | None = None) -> ExecutionOutcome:
        start = time.monotonic()
        token = token or CancellationToken(name=f"task:{task.kind}")
        task.status = task_transition(task.status, TaskStatus.RUNNING)
        task.started_at = utcnow_safe()
        last_error = ""
        while True:
            self.kill_switch.check()
            token.check()
            task.attempts += 1
            guard = TimeoutGuard(task.payload.get("timeout_s", self.default_timeout_s),
                                 task_id=task.id)
            guard.start()
            try:
                ok, err = self.runner(task, ctx)
                error = "" if ok else (err or "runner reported failure")
            except CancelledError:
                guard.cancel()
                task.status = task_transition(task.status, TaskStatus.CANCELLED)
                return ExecutionOutcome(task.id, task.kind, TaskStatus.CANCELLED,
                                        task.attempts, _ms(start), error="cancelled")
            except TaskTimeout as te:
                error = str(te)
                ok = False
            except Exception as e:  # noqa: BLE001 - engine must survive any worker bug
                error = f"{type(e).__name__}: {e}"
                ok = False
            finally:
                guard.cancel()
            self.audit.emit(task.case_id, "task.attempt", actor="executor",
                            subject_id=task.id,
                            detail={"kind": task.kind, "attempt": task.attempts,
                                    "ok": ok, "error": error})
            if ok:
                task.status = task_transition(task.status, TaskStatus.SUCCEEDED)
                task.finished_at = utcnow_safe()
                return ExecutionOutcome(task.id, task.kind, TaskStatus.SUCCEEDED,
                                        task.attempts, _ms(start))
            retry_now, delay = self.retry.evaluate(task.attempts, error)
            if retry_now and task.can_retry():
                task.status = task_transition(task.status, TaskStatus.FAILED)
                task.status = task_transition(task.status, TaskStatus.READY)
                task.status = task_transition(task.status, TaskStatus.RUNNING)
                if delay:
                    self._sleep(min(delay, 5.0))  # bounded in tests/dev
                continue
            task.status = task_transition(task.status, TaskStatus.FAILED)
            task.finished_at = utcnow_safe()
            return ExecutionOutcome(task.id, task.kind, TaskStatus.FAILED,
                                    task.attempts, _ms(start), error=error,
                                    retried=task.attempts > 1)


def _ms(start: float) -> float:
    return (time.monotonic() - start) * 1000


def utcnow_safe():
    from traceatlas.core.validation import utcnow

    return utcnow()

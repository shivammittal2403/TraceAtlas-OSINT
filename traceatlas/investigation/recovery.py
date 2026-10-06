"""Recovery: rebuild a resumable run from the latest checkpoint."""

from __future__ import annotations

from dataclasses import dataclass

from traceatlas.core.enums import TaskStatus
from traceatlas.investigation.checkpoints import Checkpoint, CheckpointStore
from traceatlas.planning.planner_output import Plan


@dataclass
class RecoveryResult:
    found: bool
    checkpoint: Checkpoint | None
    pending_task_ids: list[str]
    reason: str = ""


class RecoveryManager:
    def __init__(self, store: CheckpointStore | None = None) -> None:
        self.store = store or CheckpointStore()

    def recover(self, investigation_id: str, plan: Plan) -> RecoveryResult:
        cp = self.store.read(investigation_id)
        if cp is None:
            return RecoveryResult(found=False, checkpoint=None,
                                  pending_task_ids=[t.id for t in plan.tasks],
                                  reason="no checkpoint; start fresh")
        done = {tid for tid, st in cp.task_states.items()
                if st in (TaskStatus.SUCCEEDED.value, TaskStatus.SKIPPED.value)}
        pending = [t.id for t in plan.tasks if t.id not in done]
        return RecoveryResult(found=True, checkpoint=cp, pending_task_ids=pending,
                              reason=f"resumed at wave {cp.wave}, {len(pending)} tasks pending")

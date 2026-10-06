"""Persisted investigation state machine with guarded transitions."""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.enums import InvestigationStatus, TaskStatus

INVESTIGATION_TRANSITIONS: dict[InvestigationStatus, set[InvestigationStatus]] = {
    InvestigationStatus.DRAFT: {InvestigationStatus.PLANNED, InvestigationStatus.CANCELLED},
    InvestigationStatus.PLANNED: {InvestigationStatus.RUNNING, InvestigationStatus.CANCELLED},
    InvestigationStatus.RUNNING: {
        InvestigationStatus.PAUSED,
        InvestigationStatus.NEEDS_HUMAN,
        InvestigationStatus.COMPLETED,
        InvestigationStatus.FAILED,
        InvestigationStatus.CANCELLED,
    },
    InvestigationStatus.PAUSED: {InvestigationStatus.RUNNING, InvestigationStatus.CANCELLED},
    InvestigationStatus.NEEDS_HUMAN: {
        InvestigationStatus.RUNNING, InvestigationStatus.CANCELLED, InvestigationStatus.FAILED,
    },
    InvestigationStatus.COMPLETED: set(),
    InvestigationStatus.FAILED: set(),
    InvestigationStatus.CANCELLED: set(),
}

TASK_TRANSITIONS: dict[TaskStatus, set[TaskStatus]] = {
    TaskStatus.PENDING: {TaskStatus.READY, TaskStatus.SKIPPED, TaskStatus.CANCELLED},
    TaskStatus.READY: {TaskStatus.RUNNING, TaskStatus.SKIPPED, TaskStatus.CANCELLED},
    TaskStatus.RUNNING: {
        TaskStatus.SUCCEEDED, TaskStatus.FAILED, TaskStatus.READY,  # READY = retry
        TaskStatus.CANCELLED,
    },
    TaskStatus.FAILED: {TaskStatus.READY, TaskStatus.CANCELLED},
    TaskStatus.SUCCEEDED: set(),
    TaskStatus.SKIPPED: set(),
    TaskStatus.CANCELLED: set(),
}


class InvalidTransition(Exception):
    pass


@dataclass
class StateMachine:
    """Tracks current status plus full transition history (auditable)."""

    initial: InvestigationStatus = InvestigationStatus.DRAFT
    current: InvestigationStatus = InvestigationStatus.DRAFT
    history: list[tuple[str, str, str]] = field(default_factory=list)  # (from, to, reason)

    def transition(self, to: InvestigationStatus, reason: str = "") -> InvestigationStatus:
        if to not in INVESTIGATION_TRANSITIONS[self.current]:
            raise InvalidTransition(f"{self.current.value} -> {to.value} not allowed")
        self.history.append((self.current.value, to.value, reason))
        self.current = to
        return self.current

    def terminal(self) -> bool:
        return not INVESTIGATION_TRANSITIONS[self.current]


def task_transition(current: TaskStatus, to: TaskStatus) -> TaskStatus:
    if to not in TASK_TRANSITIONS[current]:
        raise InvalidTransition(f"task {current.value} -> {to.value} not allowed")
    return to

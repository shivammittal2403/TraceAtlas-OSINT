"""Per-task timeout enforcement using a monotonic deadline guard."""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass


class TaskTimeout(Exception):
    def __init__(self, task_id: str, seconds: float) -> None:
        super().__init__(f"task {task_id} exceeded {seconds:.1f}s timeout")
        self.task_id = task_id
        self.seconds = seconds


@dataclass
class Deadline:
    expires_at: float

    @classmethod
    def from_seconds(cls, seconds: float) -> "Deadline":
        if seconds <= 0:
            raise ValueError("timeout must be positive")
        return cls(expires_at=time.monotonic() + seconds)

    def remaining(self) -> float:
        return max(0.0, self.expires_at - time.monotonic())

    def expired(self) -> bool:
        return time.monotonic() >= self.expires_at

    def check(self, task_id: str = "") -> None:
        if self.expired():
            raise TaskTimeout(task_id or "unknown", self.expires_at)


class TimeoutGuard:
    """Watchdog that flags expiry cooperatively.

    Guarded work must call `check()` at safe points. Hard-killing arbitrary
    Python code is intentionally not attempted; cooperative cancellation is
    the only safe model.
    """

    def __init__(self, seconds: float, task_id: str = "") -> None:
        self.deadline = Deadline.from_seconds(seconds)
        self.task_id = task_id
        self._timer: threading.Timer | None = None
        self._expired = threading.Event()

    def start(self) -> "TimeoutGuard":
        self._timer = threading.Timer(self.deadline.remaining(), self._expired.set)
        self._timer.daemon = True
        self._timer.start()
        return self

    def cancel(self) -> None:
        if self._timer:
            self._timer.cancel()

    @property
    def expired(self) -> bool:
        return self._expired.is_set()

    def check(self) -> None:
        if self.expired:
            raise TaskTimeout(self.task_id, self.deadline.remaining())

    def __enter__(self) -> "TimeoutGuard":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.cancel()


@contextmanager
def time_limit(seconds: float, task_id: str = ""):
    guard = TimeoutGuard(seconds, task_id)
    guard.start()
    try:
        yield guard
    finally:
        guard.cancel()

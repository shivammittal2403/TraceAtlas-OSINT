"""Simple priority task queue used by the manager between waves."""

from __future__ import annotations

import heapq
import threading

from traceatlas.core.task import Task


class TaskQueue:
    def __init__(self) -> None:
        self._heap: list[tuple[float, int, Task]] = []
        self._counter = 0
        self._lock = threading.Lock()

    def push(self, task: Task, priority: float = 0.0) -> None:
        with self._lock:
            self._counter += 1
            heapq.heappush(self._heap, (-priority, self._counter, task))

    def pop(self) -> Task | None:
        with self._lock:
            if not self._heap:
                return None
            return heapq.heappop(self._heap)[2]

    def __len__(self) -> int:
        with self._lock:
            return len(self._heap)

    def empty(self) -> bool:
        return len(self) == 0

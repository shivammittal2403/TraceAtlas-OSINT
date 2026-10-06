"""Cooperative cancellation tokens shared by tasks, waves and employees."""

from __future__ import annotations

import threading


class CancelledError(Exception):
    def __init__(self, scope: str, reason: str = "") -> None:
        super().__init__(f"cancelled ({scope})" + (f": {reason}" if reason else ""))
        self.scope = scope
        self.reason = reason


class CancellationToken:
    """Thread-safe flag; children inherit parent cancellation."""

    def __init__(self, name: str = "task", parent: "CancellationToken | None" = None) -> None:
        self.name = name
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._children: list["CancellationToken"] = []
        self._parent = parent
        self.reason = ""
        if parent is not None:
            parent.register_child(self)

    def register_child(self, child: "CancellationToken") -> None:
        with self._lock:
            self._children.append(child)
        if self.cancelled:
            child.cancel(f"parent {self.name} cancelled")

    def cancel(self, reason: str = "") -> None:
        with self._lock:
            self.reason = reason
            kids = list(self._children)
        self._event.set()
        for kid in kids:
            kid.cancel(reason or f"parent {self.name} cancelled")

    @property
    def cancelled(self) -> bool:
        if self._event.is_set():
            return True
        return bool(self._parent and self._parent.cancelled)

    def check(self) -> None:
        if self.cancelled:
            reason = self.reason or (self._parent.reason if self._parent else "")
            raise CancelledError(self.name, reason)

    def child(self, name: str) -> "CancellationToken":
        return CancellationToken(name=name, parent=self)

    def wait(self, timeout: float | None = None) -> bool:
        return self._event.wait(timeout)

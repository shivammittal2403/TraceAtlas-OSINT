"""Enforced halt: a kill switch checked at every dispatch point.

Backed by an in-process flag AND an optional sentinel file so operators can
halt collection out-of-band (`touch .traceatlas_killswitch`). Once tripped,
the switch stays tripped until explicitly reset with a reason recorded.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field


@dataclass
class KillSwitch:
    sentinel_file: str = ".traceatlas_killswitch"
    check_file_each_dispatch: bool = True
    tripped_at: float | None = None
    reason: str = ""
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def trip(self, reason: str = "operator") -> None:
        with self._lock:
            if self.tripped_at is None:
                self.tripped_at = time.time()
                self.reason = reason
            try:
                with open(self.sentinel_file, "w") as fh:
                    fh.write(reason or "manual")
            except OSError:
                pass  # in-memory trip still holds

    def reset(self, reason: str = "operator") -> None:
        with self._lock:
            self.tripped_at = None
            self.reason = ""
            try:
                if os.path.exists(self.sentinel_file):
                    os.remove(self.sentinel_file)
            except OSError:
                pass

    @property
    def active(self) -> bool:
        """True when execution must halt now."""
        if self.tripped_at is not None:
            return True
        if self.check_file_each_dispatch and os.path.exists(self.sentinel_file):
            with self._lock:
                if self.tripped_at is None:
                    self.tripped_at = time.time()
                    self.reason = f"sentinel file {self.sentinel_file}"
            return True
        return False

    def check(self) -> None:
        from traceatlas.investigation.cancellation import CancelledError

        if self.active:
            raise CancelledError("kill_switch", self.reason)

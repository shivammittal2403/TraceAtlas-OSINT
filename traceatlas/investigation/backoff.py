"""Exponential backoff schedule with jitter for retryable failures."""

from __future__ import annotations

import random


class BackoffSchedule:
    """Computes sleep durations for successive attempts.

    delay(n) = min(base * factor**n, cap) then applies full jitter unless
    jitter is disabled. Deterministic when `rng` seed given (tests).
    """

    def __init__(self, base_seconds: float = 1.0, factor: float = 2.0,
                 cap_seconds: float = 60.0, jitter: bool = True,
                 rng: random.Random | None = None) -> None:
        if base_seconds <= 0 or factor < 1 or cap_seconds <= 0:
            raise ValueError("invalid backoff parameters")
        self.base = base_seconds
        self.factor = factor
        self.cap = cap_seconds
        self.jitter = jitter
        self._rng = rng or random.Random()

    def delay(self, attempt: int) -> float:
        if attempt < 0:
            raise ValueError("attempt must be >= 0")
        raw = min(self.base * (self.factor ** attempt), self.cap)
        return self._rng.uniform(0, raw) if self.jitter else raw

    def schedule(self, retries: int) -> list[float]:
        return [self.delay(i) for i in range(retries)]

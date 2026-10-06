"""Retry policy application: decide whether/how to re-attempt failed work."""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.investigation.backoff import BackoffSchedule

DEFAULT_RETRYABLE_MARKERS = (
    "timeout", "timed out", "429", "500", "502", "503", "504",
    "connection reset", "connection refused", "temporarily unavailable",
    "rate limit",
)


@dataclass
class RetryPolicy:
    max_attempts: int = 3
    backoff: BackoffSchedule = field(default_factory=BackoffSchedule)
    retryable_markers: tuple[str, ...] = DEFAULT_RETRYABLE_MARKERS

    def is_retryable(self, error: str) -> bool:
        lowered = (error or "").lower()
        return any(m in lowered for m in self.retryable_markers)

    def should_retry(self, attempts: int, error: str) -> bool:
        return attempts < self.max_attempts and self.is_retryable(error)

    def next_delay(self, attempts: int) -> float:
        return self.backoff.delay(max(attempts - 1, 0))

    def evaluate(self, attempts: int, error: str) -> tuple[bool, float]:
        """Return (retry?, sleep_seconds)."""
        if self.should_retry(attempts, error):
            return True, self.next_delay(attempts)
        return False, 0.0

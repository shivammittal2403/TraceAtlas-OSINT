"""Confidence representation with explicit uncertainty semantics."""

from __future__ import annotations

from dataclasses import dataclass

from traceatlas.core.enums import ConfidenceLevel


@dataclass(frozen=True)
class Confidence:
    """A numeric score paired with an honest qualitative level.

    Scores are *not* probabilities unless calibrated (see verification.calibration).
    """

    score: float
    level: ConfidenceLevel
    rationale: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("confidence score must be within [0, 1]")

    @classmethod
    def from_score(cls, score: float, rationale: str = "") -> "Confidence":
        if score < 0.2:
            level = ConfidenceLevel.UNKNOWN
        elif score < 0.5:
            level = ConfidenceLevel.LOW
        elif score < 0.75:
            level = ConfidenceLevel.MEDIUM
        elif score < 0.95:
            level = ConfidenceLevel.HIGH
        else:
            level = ConfidenceLevel.CONFIRMED
        return cls(score=score, level=level, rationale=rationale)

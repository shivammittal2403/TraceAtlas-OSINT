"""Promotional/marketing framing detector (overlaps self-interest deliberately)."""
from __future__ import annotations

from traceatlas.trust.model import BiasType, SourceRecord
from traceatlas.trust.source_bias.model import BiasFlags

_SUPERLATIVES = ("award", "leading", "best", "world-class", "innovative", "launches")


def detect(source: SourceRecord, flags: BiasFlags) -> BiasFlags:
    title = source.title.lower()
    if any(s in title for s in _SUPERLATIVES):
        flags.add(
            BiasType.PROMOTIONAL,
            incentive="promotional copy: superlative language signals marketing intent",
            limitation="tone suggests promotion rather than neutral reporting",
        )
    return flags

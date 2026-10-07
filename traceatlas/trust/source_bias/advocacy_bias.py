"""Advocacy organisation bias detector."""
from __future__ import annotations

from traceatlas.trust.model import BiasType, SourceRecord
from traceatlas.trust.source_bias.model import BiasFlags

_ADVOCACY_HINTS = ("watch", "rights", "campaign", "coalition", "alliance", "union")


def detect(source: SourceRecord, flags: BiasFlags) -> BiasFlags:
    text = f"{source.title} {source.publisher}".lower()
    if source.author_type == "advocacy" or any(h in text for h in _ADVOCACY_HINTS):
        flags.add(
            BiasType.ADVOCACY,
            incentive="outcome-prejudiced reporting: favours the cause the org advocates",
            limitation="selection toward cases supporting the mission",
        )
    return flags

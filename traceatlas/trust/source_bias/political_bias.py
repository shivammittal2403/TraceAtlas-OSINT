"""Political affiliation / state-position bias detector."""
from __future__ import annotations

from traceatlas.trust.model import BiasType, SourceRecord
from traceatlas.trust.source_bias.model import BiasFlags

_STATE_KEYWORDS = ("ministry", "government", "state news", "official gazette", "press office")


def detect(source: SourceRecord, flags: BiasFlags) -> BiasFlags:
    text = f"{source.title} {source.publisher} {source.url}".lower()
    if source.author_type == "government" or any(k in text for k in _STATE_KEYWORDS):
        flags.add(
            BiasType.POLITICAL,
            incentive="state-aligned messaging may favour official narratives",
            limitation="political framing possible; cross-check with non-state records",
        )
    return flags

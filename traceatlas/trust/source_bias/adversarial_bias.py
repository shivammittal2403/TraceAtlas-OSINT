"""Adversarial-source detector: anonymous/hostile channels spreading disinformation."""
from __future__ import annotations

from traceatlas.trust.model import BiasType, SourceRecord
from traceatlas.trust.source_bias.model import BiasFlags


def detect(source: SourceRecord, flags: BiasFlags) -> BiasFlags:
    text = f"{source.title} {source.publisher} {source.kind}".lower()
    anonymous = source.author_type == "anonymous"
    hostile_channel = source.kind == "social" and ("telegram" in source.url.lower() or "channel" in text)
    if anonymous:
        flags.add(
            BiasType.ADVERSARIAL,
            incentive="authorship unattributed: accountability absent; possible influence operation",
            limitation="anonymous provenance cannot be checked",
        )
    if hostile_channel and anonymous:
        flags.add(BiasType.ADVERSARIAL,
                  incentive="anonymous messaging-channel forward: amplification/propaganda risk",
                  limitation="forward chains hide the original author")
    return flags

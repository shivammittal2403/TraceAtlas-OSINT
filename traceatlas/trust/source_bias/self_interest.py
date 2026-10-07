"""Self-interest detector: does the source benefit from the claim being believed?"""
from __future__ import annotations

from traceatlas.trust.model import BiasType, SourceRecord
from traceatlas.trust.source_bias.model import BiasFlags


def detect(source: SourceRecord, flags: BiasFlags) -> BiasFlags:
    first_party = source.author_type == "first_party"
    promo = "about" in source.url.lower() or "newsroom" in source.url.lower()
    if first_party:
        flags.add(
            BiasType.SELF_INTEREST,
            incentive="first-party material: the subject benefits from favourable framing",
            limitation="self-described activity; independent corroboration preferred",
        )
    if promo:
        flags.add(BiasType.SELF_INTEREST,
                  incentive="promotional page of the subject itself",
                  limitation="curated self-presentation")
    return flags

"""Language-coverage bias detector."""
from __future__ import annotations

from traceatlas.trust.model import BiasType, SourceRecord
from traceatlas.trust.source_bias.model import BiasFlags


def detect(source: SourceRecord, flags: BiasFlags) -> BiasFlags:
    if source.language and source.language != "en":
        flags.add(
            BiasType.LINGUISTIC,
            incentive="",
            limitation=f"source is in '{source.language}': English-language searches will systematically miss it",
        )
    if source.language == "en":
        flags.add(
            BiasType.LINGUISTIC,
            incentive="",
            limitation="English-only corpus: non-English perspectives absent from this source",
        )
    return flags

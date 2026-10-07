"""Sampling/selection bias detector for datasets."""
from __future__ import annotations

from traceatlas.trust.model import BiasType, SourceRecord
from traceatlas.trust.source_bias.model import BiasFlags


def detect(source: SourceRecord, flags: BiasFlags) -> BiasFlags:
    if source.kind == "dataset":
        flags.add(
            BiasType.SAMPLING,
            incentive="",
            limitation="dataset reflects its collection method: coverage is bounded by how rows were sampled",
        )
    return flags

"""Institutional/organizational inertia bias detector."""
from __future__ import annotations

from traceatlas.trust.model import BiasType, SourceRecord
from traceatlas.trust.source_bias.model import BiasFlags


def detect(source: SourceRecord, flags: BiasFlags) -> BiasFlags:
    if source.kind == "registry":
        # registries are authoritative but reflect what filers stated, not ground truth
        flags.add(
            BiasType.INSTITUTIONAL,
            incentive="institution reproduces filed/self-reported data as-is",
            limitation="registry content is declaratory: accuracy depends on the filer",
        )
    return flags

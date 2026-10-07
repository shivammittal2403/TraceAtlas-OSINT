"""SourceBiasAnalyzer: runs every bias detector over a source and produces a
BiasAssessment (§10). Deterministic, explainable, annotation-only."""

from __future__ import annotations

from datetime import datetime

from traceatlas.trust.model import (
    BiasAssessment,
    IndependenceStatus,
    SourceRecord,
)
from traceatlas.trust.source_bias import (
    adversarial_bias,
    advocacy_bias,
    commercial_bias,
    geographic_bias,
    institutional_bias,
    linguistic_bias,
    political_bias,
    promotional_bias,
    publication_bias,
    sampling_bias,
    self_interest,
    source_position,
    survivorship_bias,
    temporal_bias,
)
from traceatlas.trust.source_bias.explanation import explain_bias
from traceatlas.trust.source_bias.limitations import collect_limitations
from traceatlas.trust.source_bias.model import BiasFlags
from traceatlas.trust.source_bias.scoring import risk_level_for

DETECTORS = (
    political_bias, commercial_bias, institutional_bias, advocacy_bias,
    self_interest, promotional_bias, adversarial_bias, sampling_bias,
    survivorship_bias, geographic_bias, linguistic_bias, temporal_bias,
    publication_bias,
)


class SourceBiasAnalyzer:
    """Assembles BiasAssessment objects. Never returns 'discard' — bias explains."""

    def __init__(self, now: datetime | None = None) -> None:
        self.now = now

    def assess(self, source: SourceRecord,
               independence: IndependenceStatus = IndependenceStatus.UNKNOWN) -> BiasAssessment:
        flags = BiasFlags(source_id=source.id)
        for det in DETECTORS:
            if det is temporal_bias:
                det.detect(source, flags, now=self.now)
            else:
                det.detect(source, flags)
        position = source_position.classify_position(source)
        assessment = BiasAssessment(
            source_id=source.id,
            bias_types=list(flags.types),
            possible_incentives=list(flags.incentives),
            known_limitations=collect_limitations(flags, source),
            primary_or_secondary=position,
            independence_status=independence,
            reliability_factors=["qualitative reliability assessed separately (§11)"],
            risk_level=risk_level_for(flags),
        )
        assessment.explanation = explain_bias(assessment)
        return assessment

"""Bias flag container shared by the per-bias detectors."""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.trust.model import BiasAssessment, BiasType, SourceRecord


@dataclass
class BiasFlags:
    """Accumulated detector output for one source."""

    source_id: str
    types: list[BiasType] = field(default_factory=list)
    incentives: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def add(self, btype: BiasType, incentive: str = "", limitation: str = "") -> None:
        if btype not in self.types:
            self.types.append(btype)
        if incentive and incentive not in self.incentives:
            self.incentives.append(incentive)
        if limitation and limitation not in self.limitations:
            self.limitations.append(limitation)


def bias_for_source(source: SourceRecord) -> BiasAssessment:
    """Convenience: run every detector over a source, return a BiasAssessment."""
    from traceatlas.trust.source_bias.analyzer import SourceBiasAnalyzer

    return SourceBiasAnalyzer().assess(source)

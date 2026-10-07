"""Source reliability assessment (§11) — kept SEPARATE from bias (§10).

A source may be biased but factually accurate; a source may look neutral but be
unreliable. Levels are qualitative (VERY_LOW..UNKNOWN); numeric scores are NOT
fabricated because they would be fake precision unless calibrated.
"""

from __future__ import annotations

from traceatlas.trust.model import (
    PrimaryOrSecondary,
    ReliabilityAssessment,
    ReliabilityLevel,
    SourceRecord,
)
from traceatlas.trust.source_bias.source_position import classify_position

_RANK = [ReliabilityLevel.VERY_LOW, ReliabilityLevel.LOW, ReliabilityLevel.MODERATE,
         ReliabilityLevel.HIGH, ReliabilityLevel.VERY_HIGH]

_AUTHOR_AUTHORITY = {
    "registry": 2, "government": 2, "researcher": 1, "first_party": 1,
    "media": 1, "commercial": 0, "advocacy": 0, "anonymous": -2, "unknown": -1,
}


def _level_from_signals(hits: int, penalties: int) -> ReliabilityLevel:
    score = hits - penalties
    if score >= 5:
        return ReliabilityLevel.VERY_HIGH
    if score >= 3:
        return ReliabilityLevel.HIGH
    if score >= 1:
        return ReliabilityLevel.MODERATE
    if score >= 0:
        return ReliabilityLevel.LOW
    return ReliabilityLevel.VERY_LOW


class SourceReliabilityAnalyzer:
    """Deterministic qualitative reliability from structural signals only."""

    def assess(self, source: SourceRecord, corroboration_clusters: int = 0,
               historical_accuracy_known: bool = False,
               methodology_transparent: bool = False,
               data_quality_ok: bool = True,
               complete: bool = True) -> ReliabilityAssessment:
        hits = 0
        notes: list[str] = []

        authority = _AUTHOR_AUTHORITY.get(source.author_type, 0)
        if source.kind == "registry":
            hits += 2
            notes.append("authoritative registry record")
        elif authority >= 2:
            hits += 2
            notes.append("high-authority producer")
        elif authority == 1:
            hits += 1
            notes.append("moderate authority")
        elif authority < 0:
            hits += authority  # anonymous ⇒ strong penalty
            notes.append("low/unattributed authority")

        position = classify_position(source)
        if position is PrimaryOrSecondary.PRIMARY:
            hits += 2
            notes.append("primary proximity to event")
        else:
            notes.append("secondary reporting: inherits upstream errors")

        if corroboration_clusters >= 2:
            hits += 2
            notes.append(f"corroborated by {corroboration_clusters} independent clusters")
        elif corroboration_clusters == 1:
            hits += 1
            notes.append("single-cluster support only")

        if historical_accuracy_known:
            hits += 1
            notes.append("measured historical accuracy available")
        if methodology_transparent:
            hits += 1
            notes.append("transparent methodology")
        if not data_quality_ok:
            hits -= 2
            notes.append("data quality problems observed")
        if not complete:
            hits -= 1
            notes.append("incomplete coverage")

        freshness = "recent" if source.event_time is None else (
            "dated" if source.event_time < source.captured_at else "contemporaneous")
        transparency = "declared provenance" if source.url or source.publisher else "opaque provenance"

        level = _level_from_signals(max(hits, 0), 0 if hits >= 0 else -hits)
        if source.author_type == "anonymous":
            level = min(level, ReliabilityLevel.LOW, key=_RANK.index)

        return ReliabilityAssessment(
            source_id=source.id,
            level=level,
            authority=source.author_type,
            proximity_to_event=position.value + "/" + freshness,
            primary_or_secondary=position,
            freshness=freshness,
            transparency=transparency,
            methodology="transparent" if methodology_transparent else "unknown",
            corroboration=f"{corroboration_clusters} independent cluster(s)",
            consistency="consistent" if data_quality_ok else "inconsistent",
            completeness="complete" if complete else "partial",
            explanation="; ".join(notes) or "no reliability signals",
        )


def merge_reliability(assessments: list[ReliabilityAssessment]) -> ReliabilityLevel:
    """Fact-level reliability = weakest link among material sources."""
    if not assessments:
        return ReliabilityLevel.UNKNOWN
    return min((a.level for a in assessments), key=lambda l: _RANK.index(l)
               if l in _RANK else -1)

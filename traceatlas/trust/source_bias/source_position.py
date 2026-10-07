"""Source position: primary vs secondary proximity to the event (§10 question set)."""
from __future__ import annotations

from traceatlas.trust.model import PrimaryOrSecondary, SourceRecord


def classify_position(source: SourceRecord) -> PrimaryOrSecondary:
    """Deterministic position classification from lineage + author type."""
    if source.derived_from_id or source.upstream_source_id:
        return PrimaryOrSecondary.SECONDARY
    if source.kind == "archive":
        return PrimaryOrSecondary.PRIMARY      # archived snapshot of the page itself
    if source.author_type in ("first_party", "government", "researcher"):
        return PrimaryOrSecondary.PRIMARY
    if source.author_type in ("media", "commercial", "unknown", "anonymous"):
        return PrimaryOrSecondary.SECONDARY
    return PrimaryOrSecondary.UNKNOWN

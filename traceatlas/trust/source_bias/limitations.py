"""Aggregate known-limitation strings for a source across detectors."""
from __future__ import annotations

from traceatlas.trust.model import SourceRecord
from traceatlas.trust.source_bias.model import BiasFlags


def collect_limitations(flags: BiasFlags, source: SourceRecord) -> list[str]:
    out = list(flags.limitations)
    if source.author_type == "anonymous":
        out.append("anonymous authorship")
    if source.kind == "feed":
        out.append("machine-generated feed: parsing errors possible")
    return sorted(set(out))

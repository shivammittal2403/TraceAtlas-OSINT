"""Corroboration counting with an explicit independence caveat."""

from __future__ import annotations


def count_sources(evidence_source_ids: list[str]) -> dict:
    uniq = sorted({s for s in evidence_source_ids if s})
    return {
        "distinct_source_count": len(uniq),
        "sources": uniq,
        "caveat": (
            "Source independence has NOT been verified "
            "(independence engine unimplemented)."
        ),
    }

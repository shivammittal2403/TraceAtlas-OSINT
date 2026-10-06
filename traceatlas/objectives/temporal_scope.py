"""Derive a temporal window from the objective text when stated."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class TemporalScope:
    start_year: int | None = None
    end_year: int | None = None
    raw: str = ""


_RANGE_RE = re.compile(r"\b(\d{4})\s*(?:-|to|through)\s*(\d{4})\b")
_SINCE_RE = re.compile(r"\bsince\s+(\d{4})\b", re.I)


def derive_temporal_scope(text: str) -> TemporalScope:
    if m := _RANGE_RE.search(text):
        return TemporalScope(int(m.group(1)), int(m.group(2)), m.group())
    if m := _SINCE_RE.search(text):
        return TemporalScope(int(m.group(1)), None, m.group())
    return TemporalScope()

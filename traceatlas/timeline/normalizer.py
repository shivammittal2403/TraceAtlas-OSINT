"""Timestamp normalization to UTC ISO-8601 with precision capture."""

from __future__ import annotations

import re
from datetime import datetime, timezone

_PATTERNS = [
    ("%Y-%m-%dT%H:%M:%S", "second"),
    ("%Y-%m-%d %H:%M:%S", "second"),
    ("%Y-%m-%d", "day"),
    ("%Y-%m", "month"),
    ("%Y", "year"),
]


def parse_timestamp(value: str) -> tuple[datetime | None, str]:
    """Return (dt_utc, precision); (None, 'unknown') when unparseable - never guessed."""
    v = value.strip()
    if not v:
        return None, "unknown"
    iso = re.sub(r"Z$", "+00:00", v)
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc), "second"
    except ValueError:
        pass
    for fmt, precision in _PATTERNS:
        try:
            dt = datetime.strptime(v, fmt)
            return dt.replace(tzinfo=timezone.utc), precision
        except ValueError:
            continue
    return None, "unknown"

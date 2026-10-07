"""Temporal sanity: event time vs retrieval time; staleness annotation."""

from __future__ import annotations

from datetime import datetime, timezone

from traceatlas.trust.case_memory import CaseMemory
from traceatlas.trust.fact_gate.candidate import FactCandidate

_STALE_DAYS = 730  # two years ⇒ annotate temporal limitation on the fact


def check_temporal(candidate: FactCandidate, memory: CaseMemory,
                   now: datetime | None = None) -> tuple[bool, list[str]]:
    problems: list[str] = []
    now = now or datetime.now(timezone.utc)
    if candidate.event_time:
        try:
            ev = datetime.fromisoformat(candidate.event_time)
        except ValueError:
            problems.append(f"unparseable event_time {candidate.event_time!r}")
            return False, problems
        if ev.tzinfo is None:
            ev = ev.replace(tzinfo=timezone.utc)
        if ev > now:
            problems.append("event_time is in the future — impossible; reject candidate")
            return False, problems
        if (now - ev).days >= _STALE_DAYS:
            problems.append("temporal: observation is stale; treat as historical/partial fact only")
    return True, problems

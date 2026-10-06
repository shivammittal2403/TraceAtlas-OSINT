"""Timeline model: events sorted with unknown-time handling."""

from __future__ import annotations

from traceatlas.core.event import Event


def sorted_events(events: list[Event]) -> list[Event]:
    """Events without event_time sort last (explicitly unknown, never guessed)."""
    return sorted(events, key=lambda e: (e.sort_key(), e.id))

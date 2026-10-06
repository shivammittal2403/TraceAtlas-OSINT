"""Resolve jurisdiction mentions ('India', 'EU', 'California') to records."""

from __future__ import annotations

from traceatlas.core.jurisdiction import Jurisdiction

_ALIASES = {
    "india": "in", "indiya": "in",
    "eu": "eu", "european union": "eu",
    "usa": "us", "united states": "us", "u.s.": "us",
    "uk": "gb", "united kingdom": "gb",
    "germany": "de", "france": "fr", "russia": "ru", "china": "cn",
}


def resolve_jurisdictions(text: str) -> list[Jurisdiction]:
    lowered = text.lower()
    found: list[Jurisdiction] = []
    seen: set[str] = set()
    for alias, iso in _ALIASES.items():
        if alias in lowered and iso not in seen:
            seen.add(iso)
            found.append(Jurisdiction(iso_country=iso))
    return found

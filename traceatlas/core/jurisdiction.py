"""Jurisdiction metadata used by policy checks."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Jurisdiction:
    iso_country: str          # ISO-3166 alpha-2
    subdivision: str = ""     # state/province
    notes: str = ""

    @classmethod
    def parse(cls, value: str) -> "Jurisdiction":
        parts = [p.strip() for p in value.split("-", 1)]
        return cls(iso_country=parts[0].lower(), subdivision=parts[1] if len(parts) > 1 else "")

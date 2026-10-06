"""Scope: explicit boundaries on what an investigation may touch."""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.serialization import to_jsonable


@dataclass
class Scope:
    allowed_domains: list[str] = field(default_factory=list)
    allowed_cidrs: list[str] = field(default_factory=list)
    allowed_entity_ids: list[str] = field(default_factory=list)
    prohibited_actions: list[str] = field(
        default_factory=lambda: [
            "authentication_bypass",
            "impersonation",
            "rate_abuse",
            "paywall_bypass",
            "active_scanning",
        ]
    )
    geographic_limits: list[str] = field(default_factory=list)
    temporal_start: str | None = None
    temporal_end: str | None = None

    def allows_domain(self, domain: str) -> bool:
        return not self.allowed_domains or domain.lower() in self.allowed_domains

    def to_dict(self) -> dict:
        return to_jsonable(self)

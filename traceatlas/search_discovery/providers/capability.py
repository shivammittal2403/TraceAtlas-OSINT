"""Search-provider capability model (§5, §26).

Every provider declares exactly which operators it supports. The compiler
consults this table and refuses to emit unsupported syntax — engine-specific
dorks are never blindly pasted across engines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Operator = Literal[
    "exact", "exclude", "site", "filetype", "intitle", "inurl", "inbody",
    "daterange", "language", "region", "safesearch", "pagination",
]

ALL_OPERATORS: tuple[str, ...] = (
    "exact", "exclude", "site", "filetype", "intitle", "inurl", "inbody",
    "daterange", "language", "region", "safesearch", "pagination",
)

Maturity = Literal["stable", "beta", "degraded", "untested"]


@dataclass(frozen=True)
class ProviderCapability:
    """Declared access surface of one search/research provider (§5)."""
    provider_id: str
    name: str
    supported_operators: frozenset[str]
    api_available: bool                     # official API / documented endpoint
    authentication_required: bool = False
    auth_env_var: str = ""                  # e.g. GITHUB_TOKEN (never stored inline)
    rate_limit_per_minute: float = 30.0
    quota_per_day: int | None = None
    supports_pagination: bool = True
    max_results_per_query: int = 50
    language_filters: bool = False
    date_filters: bool = False
    region_filters: bool = False
    safe_search: bool = False
    cost_per_query: float = 0.0             # arbitrary units for budget model (§8)
    terms_url: str = ""
    privacy_class: str = "cloud"            # queries leave the host
    source_type: str = "web"                # web|code|social|archive|news|academic
    maturity: Maturity = "stable"

    @property
    def unsupported_operators(self) -> tuple[str, ...]:
        return tuple(sorted(set(ALL_OPERATORS) - set(self.supported_operators)))

    def supports(self, op: str) -> bool:
        return op in self.supported_operators

    def to_dict(self) -> dict:
        return {
            "provider_id": self.provider_id, "name": self.name,
            "supported_operators": sorted(self.supported_operators),
            "unsupported_operators": list(self.unsupported_operators),
            "api_available": self.api_available,
            "authentication": self.authentication_required,
            "rate_limit": self.rate_limit_per_minute,
            "quota_per_day": self.quota_per_day,
            "pagination": self.supports_pagination,
            "max_results": self.max_results_per_query,
            "language_filters": self.language_filters,
            "date_filters": self.date_filters,
            "region_filters": self.region_filters,
            "safe_search": self.safe_search,
            "cost": self.cost_per_query,
            "terms": self.terms_url,
            "source_type": self.source_type,
            "privacy_class": self.privacy_class,
            "maturity": self.maturity,
        }

"""Connector SDK: base contract shared by all real collectors.

Qualification rule (truthful status): `enabled` stays False until a connector
passes LIVE_VERIFIED qualification (scripts/qualify_sources.py). Real network
connectors here are functional; whether they run in production is gated by
`enabled` + policy approval, never by fake status flags.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ConnectorRequest:
    url: str = ""
    params: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    query: str = ""            # logical search query, for replay context
    target: str = ""           # normalized investigation input (domain/ip/...)


@dataclass
class ConnectorResponse:
    ok: bool
    status_code: int = 0
    body: bytes = b""
    error: str = ""
    elapsed_ms: float = 0.0
    redirect_chain: list[str] = field(default_factory=list)
    headers: dict = field(default_factory=dict)


@dataclass
class ConnectorManifest:
    id: str
    name: str
    source_id: str
    capabilities: list[str]          # e.g. ["dns.a", "dns.txt"]
    input_types: list[str]           # domain | ip | asn | url | ...
    output_types: list[str]          # observation kinds produced
    rate_limit_rps: float = 1.0
    cost_per_query_usd: float = 0.0
    requires_credentials: bool = False
    robots_or_tos_constrained: bool = True


class BaseConnector(ABC):
    name: str = "base"
    enabled: bool = False  # must remain False until qualified + policy-approved

    def __init__(self, config: dict | None = None) -> None:
        self.config = config or {}
        self._calls = 0
        self._window_start = time.monotonic()

    # ---- lifecycle -------------------------------------------------------
    @abstractmethod
    def manifest(self) -> ConnectorManifest: ...

    def validate_config(self) -> list[str]:
        """Return human-readable config problems; empty list means valid."""
        return []

    def validate_input(self, request: ConnectorRequest) -> list[str]:
        """Return input problems before any network call; empty means valid."""
        return []

    def health(self) -> dict:
        m = self.manifest()
        return {
            "connector": m.id,
            "enabled": self.enabled,
            "requires_credentials": m.requires_credentials,
            "recent_calls": self._calls,
        }

    def estimate_cost(self, request: ConnectorRequest) -> float:
        return self.manifest().cost_per_query_usd

    def rate_limit_status(self) -> dict:
        m = self.manifest()
        elapsed = time.monotonic() - self._window_start
        used_per_s = self._calls / elapsed if elapsed > 0 else 0.0
        return {"rps_used": round(used_per_s, 3), "rps_limit": m.rate_limit_rps}

    # ---- collection ------------------------------------------------------
    @abstractmethod
    def fetch(self, request: ConnectorRequest) -> ConnectorResponse: ...

    def search(self, request: ConnectorRequest) -> list[ConnectorResponse]:
        """Default: single fetch. Streaming/paginated connectors override."""
        return [self.fetch(request)]

    # ---- post-processing hooks ------------------------------------------
    def normalize(self, response: ConnectorResponse) -> list[dict]:
        """Turn raw payload into zero or more normalized records (dicts)."""
        return []

    def extract_observations(self, response: ConnectorResponse) -> list[dict]:
        """Produce typed observation dicts: {predicate, subject, object, attributes}."""
        return []

    def _throttle(self) -> None:
        """Simple synchronous rate limiter honoring manifest rps."""
        m = self.manifest()
        if m.rate_limit_rps <= 0:
            return
        min_interval = 1.0 / m.rate_limit_rps
        now = time.monotonic()
        if now - self._window_start < 1.0:
            self._calls += 1
            expected = self._calls * min_interval
            sleep_for = expected - (now - self._window_start)
            if sleep_for > 0:
                time.sleep(sleep_for)
        else:
            self._window_start = now
            self._calls = 1

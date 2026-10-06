"""Connector base class.

IMPORTANT: no connector here performs live network collection yet. The
`enabled` flag on each connector manifest is False until it passes
qualification (see sources/qualification and scripts/qualify_sources.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ConnectorRequest:
    url: str = ""
    params: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)


@dataclass
class ConnectorResponse:
    ok: bool
    status_code: int = 0
    body: bytes = b""
    error: str = ""


class BaseConnector:
    name: str = "base"
    enabled: bool = False  # must remain False until qualified + policy-approved

    def fetch(self, request: ConnectorRequest) -> ConnectorResponse:
        raise NotImplementedError(
            f"{self.name}: live collection is not implemented/enabled in this build"
        )

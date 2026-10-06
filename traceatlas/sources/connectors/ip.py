"""IP intelligence connectors: ipinfo-style JSON endpoint (configurable base URL).

Returns ASN / organization / country context for an IP address. The base_url is
configuration, not a hardcoded credential; free tiers are rate-limited and the
connector throttles politely. `enabled` stays False until LIVE_VERIFIED.
"""

from __future__ import annotations

import json

from traceatlas.core.validation import is_valid_ipv4
from traceatlas.sources.connectors.base import (
    BaseConnector, ConnectorManifest, ConnectorRequest, ConnectorResponse,
)
from traceatlas.sources.connectors.http_client import HttpFetcher


class IpConnector(BaseConnector):
    name = "ip"

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        self.base_url = str(self.config.get("base_url", "https://ipinfo.io"))
        self.token = str(self.config.get("token", ""))
        self._http = HttpFetcher()

    def manifest(self) -> ConnectorManifest:
        return ConnectorManifest(
            id="connector.ip",
            name="IP geolocation/ASN (ipinfo-compatible)",
            source_id="source.ipinfo",
            capabilities=["ip.asn", "ip.geo", "ip.org"],
            input_types=["ip"],
            output_types=["ip.hosted_by", "ip.in_asn", "ip.located_in"],
            rate_limit_rps=1.0,
            requires_credentials=bool(self.token),
        )

    def validate_config(self) -> list[str]:
        problems = []
        if not self.base_url.startswith(("http://", "https://")):
            problems.append("base_url must be http(s)")
        return problems

    def validate_input(self, request: ConnectorRequest) -> list[str]:
        if not request.target or not is_valid_ipv4(request.target):
            return [f"invalid IPv4 target: {request.target!r}"]
        return []

    def fetch(self, request: ConnectorRequest) -> ConnectorResponse:
        problems = self.validate_input(request)
        if problems:
            return ConnectorResponse(ok=False, error="; ".join(problems))
        self._throttle()
        url = f"{self.base_url.rstrip('/')}/{request.target}/json"
        params = {"token": self.token} if self.token else {}
        try:
            resp = self._http.get(url, params=params)
            if resp.status_code != 200:
                return ConnectorResponse(ok=False, status_code=resp.status_code,
                                         error=f"ip provider http {resp.status_code}")
            return ConnectorResponse(ok=True, status_code=200, body=resp.content,
                                     headers=dict(resp.headers), elapsed_ms=resp.elapsed_ms,
                                     redirect_chain=resp.redirect_chain)
        except Exception as e:
            return ConnectorResponse(ok=False, error=f"ip lookup failed: {e}")

    def extract_observations(self, response: ConnectorResponse) -> list[dict]:
        if not response.ok:
            return []
        try:
            data = json.loads(response.body)
        except json.JSONDecodeError:
            return []
        ip = str(data.get("ip", ""))
        obs: list[dict] = []
        org = str(data.get("org", ""))
        if "/" in org:
            asn, _, name = org.partition("/")
            obs.append({"predicate": "ip.in_asn", "subject": ip, "obj": asn,
                        "attributes": {"provider": name}})
            obs.append({"predicate": "ip.hosted_by", "subject": ip, "obj": name, "attributes": {}})
        country = str(data.get("country", ""))
        if country:
            obs.append({"predicate": "ip.located_in", "subject": ip, "obj": country,
                        "attributes": {"loc": data.get("loc", "")}})
        return obs

    def normalize(self, response: ConnectorResponse) -> list[dict]:
        return self.extract_observations(response)

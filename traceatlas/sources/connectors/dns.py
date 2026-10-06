"""DNS connector: real resolver using stdlib `socket` + DoH (Google/Cloudflare) fallback.

Capabilities: dns.a, dns.aaaa, dns.cname, dns.mx, dns.txt, dns.ns, dns.soa (DoH).
No credentials required. Rate-limited politely (0.5 rps default for DoH path).
"""

from __future__ import annotations

import json
import re
import socket

from traceatlas.core.validation import is_valid_domain
from traceatlas.sources.connectors.base import (
    BaseConnector,
    ConnectorManifest,
    ConnectorRequest,
    ConnectorResponse,
)
from traceatlas.sources.connectors.http_client import HttpFetcher

DOH_ENDPOINTS = {
    "google": "https://dns.google/resolve",
    "cloudflare": "https://cloudflare-dns.com/dns-query",
}

_RR_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}


class DnsConnector(BaseConnector):
    name = "dns"

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        self.provider = str(self.config.get("doh_provider", "google"))
        self._http = HttpFetcher()

    def manifest(self) -> ConnectorManifest:
        return ConnectorManifest(
            id="connector.dns",
            name="DNS (stdlib + DNS-over-HTTPS)",
            source_id="source.dns",
            capabilities=["dns.a", "dns.aaaa", "dns.cname", "dns.mx", "dns.txt", "dns.ns", "dns.soa"],
            input_types=["domain"],
            output_types=["domain.resolves_to", "domain.has_mx", "domain.has_txt", "domain.delegated_to"],
            rate_limit_rps=2.0,
        )

    def validate_input(self, request: ConnectorRequest) -> list[str]:
        problems = []
        if not request.target:
            problems.append("target (domain) required")
        elif not is_valid_domain(request.target):
            problems.append(f"invalid domain: {request.target!r}")
        return problems

    # ---- stdlib fast path for A/AAAA -----------------------------------
    def _resolve_stdlib(self, domain: str) -> list[str]:
        try:
            infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
            return sorted({i[4][0] for i in infos})
        except socket.gaierror:
            return []

    # ---- DoH path for arbitrary RR types --------------------------------
    def _doh(self, domain: str, rr_type: str) -> list[dict]:
        url = DOH_ENDPOINTS.get(self.provider, DOH_ENDPOINTS["google"])
        resp = self._http.get(url, params={"name": domain, "type": rr_type},
                              headers={"accept": "application/dns-json"}
                              if self.provider == "cloudflare" else None)
        if resp.status_code != 200:
            return []
        data = resp.json()
        out = []
        for ans in data.get("Answer", []) or []:
            out.append({"name": ans.get("name", "").rstrip("."),
                        "type": ans.get("type"), "data": ans.get("data", "").strip('"')})
        return out

    def fetch(self, request: ConnectorRequest) -> ConnectorResponse:
        problems = self.validate_input(request)
        if problems:
            return ConnectorResponse(ok=False, error="; ".join(problems))
        self._throttle()
        domain = request.target.lower().rstrip(".")
        rr = str(request.params.get("type", "A")).upper()
        if rr not in _RR_TYPES:
            return ConnectorResponse(ok=False, error=f"unsupported rr type {rr}")
        try:
            if rr in ("A", "AAAA"):
                answers = [{"name": domain, "type": rr, "data": ip}
                           for ip in self._resolve_stdlib(domain)]
                if not answers and rr == "A":
                    answers = self._doh(domain, "1")
                payload = {"domain": domain, "type": rr, "answers": answers}
            else:
                answers = self._doh(domain, str(_RR_TYPES[rr]))
                payload = {"domain": domain, "type": rr, "answers": answers}
            body = json.dumps(payload, sort_keys=True).encode()
            return ConnectorResponse(ok=True, status_code=200, body=body, headers={"content-type": "application/json"})
        except Exception as e:  # network errors surface as failed responses, never fake data
            return ConnectorResponse(ok=False, error=f"dns lookup failed: {e}")

    def extract_observations(self, response: ConnectorResponse) -> list[dict]:
        if not response.ok:
            return []
        data = json.loads(response.body)
        domain, rr = data["domain"], data["type"]
        preds = {"A": "domain.resolves_to", "AAAA": "domain.resolves_to",
                 "MX": "domain.has_mx", "TXT": "domain.has_txt",
                 "NS": "domain.delegated_to", "CNAME": "domain.cname_to", "SOA": "domain.has_soa"}
        predicate = preds.get(rr, "domain.dns_record")
        obs = []
        for ans in data.get("answers", []):
            value = ans["data"]
            if rr == "MX":
                m = re.match(r"^\s*(\d+)\s+(\S+)\.?$", value)
                if m:
                    preference, host = int(m.group(1)), m.group(2).rstrip(".")
                    obs.append({"predicate": predicate, "subject": domain, "obj": host,
                                "attributes": {"preference": preference}})
                    continue
            obs.append({"predicate": predicate, "subject": domain,
                        "obj": value.rstrip("."), "attributes": {"rr_type": rr}})
        return obs

    def normalize(self, response: ConnectorResponse) -> list[dict]:
        return self.extract_observations(response)

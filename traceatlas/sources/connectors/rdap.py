"""RDAP connector: real domain registration data via IANA bootstrap.

Resolves the correct RDAP server from https://data.iana.org/rdap/dns.json and
fetches the domain record. No credentials. Produces registrar, nameserver,
status, and event (registration/expiration/last-changed) observations.
"""

from __future__ import annotations

import json
import time

from traceatlas.core.validation import is_valid_domain
from traceatlas.sources.connectors.base import (
    BaseConnector, ConnectorManifest, ConnectorRequest, ConnectorResponse,
)
from traceatlas.sources.connectors.http_client import HttpFetcher

_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_bootstrap_cache: dict[str, object] = {"services": None, "fetched_at": 0.0}


class RdapConnector(BaseConnector):
    name = "rdap"

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        self._http = HttpFetcher(timeout_s=float(self.config.get("timeout_s", 20)))

    def manifest(self) -> ConnectorManifest:
        return ConnectorManifest(
            id="connector.rdap",
            name="RDAP (IANA bootstrap)",
            source_id="source.rdap",
            capabilities=["rdap.domain"],
            input_types=["domain"],
            output_types=["domain.registered_with", "domain.has_event", "domain.delegated_to", "domain.has_status"],
            rate_limit_rps=1.0,
        )

    def validate_input(self, request: ConnectorRequest) -> list[str]:
        if not request.target or not is_valid_domain(request.target):
            return [f"invalid domain target: {request.target!r}"]
        return []

    def _bootstrap_services(self) -> list:
        now = time.time()
        if not _bootstrap_cache["services"] or now - float(_bootstrap_cache["fetched_at"]) > 86400:
            resp = self._http.get(_BOOTSTRAP_URL)
            if resp.status_code != 200:
                raise RuntimeError(f"rdap bootstrap fetch failed: HTTP {resp.status_code}")
            _bootstrap_cache["services"] = resp.json().get("services", [])
            _bootstrap_cache["fetched_at"] = now
        return _bootstrap_cache["services"]  # type: ignore[return-value]

    def _server_for(self, domain: str) -> str:
        labels = domain.split(".")
        for services in self._bootstrap_services():
            tlds, base_url = services[0], services[1]
            for tld in tlds:
                if labels[-1].lower() == tld.lower():
                    return base_url
        raise RuntimeError(f"no rdap server known for TLD .{labels[-1]}")

    def fetch(self, request: ConnectorRequest) -> ConnectorResponse:
        problems = self.validate_input(request)
        if problems:
            return ConnectorResponse(ok=False, error="; ".join(problems))
        self._throttle()
        domain = request.target.lower().rstrip(".")
        try:
            server = self._server_for(domain)
            url = f"{server.rstrip('/')}/domain/{domain}"
            resp = self._http.get(url, headers={"accept": "application/rdap+json"})
            if resp.status_code == 404:
                return ConnectorResponse(ok=False, status_code=404, error=f"not found in RDAP: {domain}")
            if resp.status_code != 200:
                return ConnectorResponse(ok=False, status_code=resp.status_code,
                                         error=f"rdap http {resp.status_code}")
            return ConnectorResponse(ok=True, status_code=200, body=resp.content,
                                     headers=dict(resp.headers), elapsed_ms=resp.elapsed_ms,
                                     redirect_chain=resp.redirect_chain)
        except Exception as e:
            return ConnectorResponse(ok=False, error=f"rdap lookup failed: {e}")

    @staticmethod
    def _event_map(rdap: dict) -> dict[str, str]:
        out: dict[str, str] = {}
        for ev in rdap.get("events", []) or []:
            out[str(ev.get("eventAction", "")).lower()] = str(ev.get("eventDate", ""))
        return out

    def extract_observations(self, response: ConnectorResponse) -> list[dict]:
        if not response.ok:
            return []
        try:
            data = json.loads(response.body)
        except json.JSONDecodeError:
            return []
        domain = str(data.get("ldhName", "")).lower()
        obs: list[dict] = []
        for ent in data.get("entities", []) or []:
            roles = [r.lower() for r in ent.get("roles", [])]
            name = ""
            for v in ent.get("vcardArray", [None, []])[1] if isinstance(ent.get("vcardArray"), list) else []:
                if len(v) >= 2 and v[0] == "fn":
                    name = str(v[3])
            if "registrar" in roles and name:
                obs.append({"predicate": "domain.registered_with", "subject": domain,
                            "obj": name, "attributes": {"role": "registrar"}})
        for ns in data.get("nameservers", []) or []:
            nsh = str(ns.get("ldhName", "")).lower().rstrip(".")
            if nsh:
                obs.append({"predicate": "domain.delegated_to", "subject": domain,
                            "obj": nsh, "attributes": {}})
        events = self._event_map(data)
        for action, date in events.items():
            if date:
                obs.append({"predicate": "domain.has_event", "subject": domain,
                            "obj": action, "attributes": {"date": date}})
        for st in data.get("status", []) or []:
            obs.append({"predicate": "domain.has_status", "subject": domain,
                        "obj": str(st), "attributes": {}})
        return obs

    def normalize(self, response: ConnectorResponse) -> list[dict]:
        return self.extract_observations(response)

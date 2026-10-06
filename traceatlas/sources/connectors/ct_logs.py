"""Certificate Transparency log connector (crt.sh, no credentials).

Domain -> issued certificates. Produces certificate.subject_alt_name and
certificate.issued_to observations used by the CT transform family.
"""

from __future__ import annotations

import json
import re

from traceatlas.core.validation import is_valid_domain
from traceatlas.sources.connectors.base import (
    BaseConnector, ConnectorManifest, ConnectorRequest, ConnectorResponse,
)
from traceatlas.sources.connectors.http_client import HttpFetcher

_CRTSH = "https://crt.sh"


class CertificateTransparencyConnector(BaseConnector):
    name = "ct_sh"

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        self._http = HttpFetcher(timeout_s=float(self.config.get("timeout_s", 30)))

    def manifest(self) -> ConnectorManifest:
        return ConnectorManifest(
            id="connector.ct.crtsh",
            name="Certificate Transparency (crt.sh)",
            source_id="source.crtsh",
            capabilities=["ct.search_domain"],
            input_types=["domain"],
            output_types=["certificate.issued_to", "domain.has_certificate"],
            rate_limit_rps=0.2,
        )

    def validate_input(self, request: ConnectorRequest) -> list[str]:
        t = request.target
        if not t or not (is_valid_domain(t) or (t.startswith(".") and is_valid_domain(t[1:]))):
            return [f"invalid domain target: {t!r}"]
        return []

    def fetch(self, request: ConnectorRequest) -> ConnectorResponse:
        problems = self.validate_input(request)
        if problems:
            return ConnectorResponse(ok=False, error="; ".join(problems))
        self._throttle()
        domain = request.target.lower().lstrip(".")
        try:
            resp = self._http.get(f"{_CRTSH}/json", params={"q": f"%.{domain}", "output": "json"})
            if resp.status_code != 200:
                return ConnectorResponse(ok=False, status_code=resp.status_code,
                                         error=f"crt.sh http {resp.status_code}")
            return ConnectorResponse(ok=True, status_code=200, body=resp.content,
                                     headers=dict(resp.headers), elapsed_ms=resp.elapsed_ms)
        except Exception as e:
            return ConnectorResponse(ok=False, error=f"ct lookup failed: {e}")

    @staticmethod
    def _sans(cert: dict) -> list[str]:
        raw = str(cert.get("name_value", "") or cert.get("common_name", ""))
        names = [n.strip().lower() for n in re.split(r"[,\n]", raw) if n.strip()]
        return sorted(set(names))

    def normalize(self, response: ConnectorResponse) -> list[dict]:
        if not response.ok:
            return []
        try:
            data = json.loads(response.body)
        except json.JSONDecodeError:
            return []
        if not isinstance(data, list):
            return []
        out = []
        for cert in data:
            if not isinstance(cert, dict):
                continue
            out.append({
                "id": str(cert.get("id", "")),
                "issuer": str(cert.get("issuer_name", "")),
                "not_before": str(cert.get("not_before", "")),
                "not_after": str(cert.get("not_after", "")),
                "sans": self._sans(cert),
            })
        return out

    def extract_observations(self, response: ConnectorResponse) -> list[dict]:
        obs: list[dict] = []
        for rec in self.normalize(response):
            for san in rec["sans"]:
                obs.append({"predicate": "certificate.issued_to", "subject": rec["id"] or san,
                            "obj": san, "attributes": {"issuer": rec["issuer"],
                                                       "not_before": rec["not_before"],
                                                       "not_after": rec["not_after"]}})
        return obs

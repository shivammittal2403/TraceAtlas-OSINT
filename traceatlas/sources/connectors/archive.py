"""Internet Archive connectors: CDX availability + Wayback snapshot listing.

Real public APIs, no credentials. Provides historical-URL evidence for temporal
graph edges (valid_from/valid_to inference).
"""

from __future__ import annotations

import json

from traceatlas.core.validation import is_http_url
from traceatlas.sources.connectors.base import (
    BaseConnector, ConnectorManifest, ConnectorRequest, ConnectorResponse,
)
from traceatlas.sources.connectors.http_client import HttpFetcher


class ArchiveConnector(BaseConnector):
    name = "wayback"

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        self._http = HttpFetcher(timeout_s=20)

    def manifest(self) -> ConnectorManifest:
        return ConnectorManifest(
            id="connector.archive.wayback",
            name="Internet Archive CDX/Wayback",
            source_id="source.archive_org",
            capabilities=["archive.cdx", "archive.availability"],
            input_types=["url", "domain"],
            output_types=["url.archived_at", "url.first_seen"],
            rate_limit_rps=0.5,
        )

    def validate_input(self, request: ConnectorRequest) -> list[str]:
        target = request.target or request.url
        if not target:
            return ["target required"]
        return []

    def fetch(self, request: ConnectorRequest) -> ConnectorResponse:
        problems = self.validate_input(request)
        if problems:
            return ConnectorResponse(ok=False, error="; ".join(problems))
        self._throttle()
        target = request.target or request.url
        mode = str(request.params.get("mode", "cdx"))
        try:
            if mode == "availability":
                resp = self._http.get("https://archive.org/wayback/available",
                                      params={"url": target})
                return ConnectorResponse(ok=resp.status_code == 200, status_code=resp.status_code,
                                         body=resp.content, headers=dict(resp.headers),
                                         error="" if resp.status_code == 200 else f"http {resp.status_code}")
            cdx_url = f"http://web.archive.org/web/timemap/link/{target}" if False else "https://web.archive.org/cdx/search/cdx"
            resp = self._http.get(cdx_url, params={
                "url": target, "output": "json", "limit": int(self.config.get("limit", 50)),
                "collapse": "timestamp", "fl": "original,timestamp,statuscode,mimetype"})
            if resp.status_code != 200:
                return ConnectorResponse(ok=False, status_code=resp.status_code,
                                         error=f"cdx http {resp.status_code}")
            return ConnectorResponse(ok=True, status_code=200, body=resp.content,
                                     headers=dict(resp.headers), elapsed_ms=resp.elapsed_ms)
        except Exception as e:
            return ConnectorResponse(ok=False, error=f"archive lookup failed: {e}")

    def normalize(self, response: ConnectorResponse) -> list[dict]:
        if not response.ok:
            return []
        try:
            data = json.loads(response.body)
        except json.JSONDecodeError:
            return []
        # availability shape: {"archived_snapshots": {...}}
        if isinstance(data, dict):
            snaps = data.get("archived_snapshots", {})
            closest = snaps.get("closest") if isinstance(snaps, dict) else None
            if closest:
                return [{"url": closest.get("url", ""), "timestamp": closest.get("timestamp", ""),
                         "status": closest.get("status", "")}]
            return []
        # cdx shape: [[header...], [row...], ...]
        if isinstance(data, list) and data:
            header = data[0]
            return [dict(zip([str(h) for h in header], [str(c) for c in row]))
                    for row in data[1:] if isinstance(row, list)]
        return []

    def extract_observations(self, response: ConnectorResponse) -> list[dict]:
        obs: list[dict] = []
        rows = self.normalize(response)
        for row in rows:
            ts = row.get("timestamp", "")
            url = row.get("original") or row.get("url", "")
            if ts and url:
                obs.append({"predicate": "url.archived_at", "subject": url, "obj": ts,
                            "attributes": {"statuscode": row.get("statuscode", ""),
                                           "mimetype": row.get("mimetype", "")}})
        if rows:
            first = rows[0].get("timestamp", "")
            subj = rows[0].get("original") or rows[0].get("url", "")
            if first and subj:
                obs.append({"predicate": "url.first_seen", "subject": subj, "obj": first,
                            "attributes": {}})
        return obs

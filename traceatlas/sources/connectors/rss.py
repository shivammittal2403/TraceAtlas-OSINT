"""RSS/Atom feed connector using feedparser (real, dependency-declared).

News/blog monitoring sources plug in via base_url configuration.
"""

from __future__ import annotations

import json

import feedparser

from traceatlas.core.validation import is_http_url
from traceatlas.sources.connectors.base import (
    BaseConnector, ConnectorManifest, ConnectorRequest, ConnectorResponse,
)
from traceatlas.sources.connectors.http_client import HttpFetcher


class RssConnector(BaseConnector):
    name = "rss"

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        self.base_url = str(self.config.get("feed_url", ""))
        self._http = HttpFetcher()

    def manifest(self) -> ConnectorManifest:
        return ConnectorManifest(
            id=str(self.config.get("manifest_id", "connector.rss")),
            name=str(self.config.get("manifest_name", "RSS/Atom feed")),
            source_id=str(self.config.get("source_id", "source.rss")),
            capabilities=["rss.read"],
            input_types=["url"],
            output_types=["feed.entry_published"],
            rate_limit_rps=float(self.config.get("rate_limit_rps", 0.5)),
        )

    def validate_config(self) -> list[str]:
        return [] if is_http_url(self.base_url) else ["feed_url must be a valid http(s) URL"]

    def validate_input(self, request: ConnectorRequest) -> list[str]:
        url = request.url or self.base_url
        if not is_http_url(url):
            return [f"invalid feed url: {url!r}"]
        return []

    def fetch(self, request: ConnectorRequest) -> ConnectorResponse:
        problems = self.validate_config() + self.validate_input(request)
        if problems:
            return ConnectorResponse(ok=False, error="; ".join(problems))
        self._throttle()
        try:
            resp = self._http.get(request.url or self.base_url)
            ok = resp.status_code == 200
            return ConnectorResponse(ok=ok, status_code=resp.status_code, body=resp.content,
                                     headers=dict(resp.headers), elapsed_ms=resp.elapsed_ms,
                                     error="" if ok else f"http {resp.status_code}")
        except Exception as e:
            return ConnectorResponse(ok=False, error=f"feed fetch failed: {e}")

    def normalize(self, response: ConnectorResponse) -> list[dict]:
        if not response.ok:
            return []
        parsed = feedparser.parse(response.body)
        entries = []
        for e in parsed.entries[:200]:
            entries.append({
                "title": str(e.get("title", "")),
                "link": str(e.get("link", "")),
                "published": str(e.get("published", "")),
                "id": str(e.get("id", e.get("link", ""))),
            })
        return entries

    def extract_observations(self, response: ConnectorResponse) -> list[dict]:
        obs: list[dict] = []
        for entry in self.normalize(response):
            if entry["link"]:
                obs.append({"predicate": "feed.entry_published", "subject": self.manifest().id,
                            "obj": entry["link"],
                            "attributes": {"title": entry["title"], "published": entry["published"]}})
        return obs

"""DuckDuckGo HTML search connector (no API key, bot-friendly endpoint).

Returns result titles/urls/snippets. Robots/TOS-constrained: low rate, capped
results. This is a real collector; qualification gates production enablement.
"""

from __future__ import annotations

import re

from traceatlas.sources.connectors.base import (
    BaseConnector, ConnectorManifest, ConnectorRequest, ConnectorResponse,
)
from traceatlas.sources.connectors.http_client import HttpFetcher

_RESULT_RE = re.compile(
    r'<a rel="nofollow" class="result__a" href="(?P<href>[^"]+)">(?P<title>.*?)</a>'
    r'.*?<a class="result__snippet"[^>]*>(?P<snippet>.*?)</a>',
    re.S,
)


def _ddg_unwrap(href: str) -> str:
    m = re.search(r"uddg=([^&]+)", href)
    if not m:
        return href
    from urllib.parse import unquote
    return unquote(m.group(1))


class SearchConnector(BaseConnector):
    name = "ddg_search"

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        self._http = HttpFetcher()

    def manifest(self) -> ConnectorManifest:
        return ConnectorManifest(
            id="connector.search.ddg",
            name="DuckDuckGo HTML search",
            source_id="source.duckduckgo",
            capabilities=["search.web"],
            input_types=["query"],
            output_types=["search.result_found"],
            rate_limit_rps=0.25,
        )

    def validate_input(self, request: ConnectorRequest) -> list[str]:
        if not (request.query or request.target):
            return ["query required"]
        return []

    def fetch(self, request: ConnectorRequest) -> ConnectorResponse:
        problems = self.validate_input(request)
        if problems:
            return ConnectorResponse(ok=False, error="; ".join(problems))
        self._throttle()
        q = request.query or request.target
        try:
            resp = self._http.get("https://html.duckduckgo.com/html/", params={"q": q})
            if resp.status_code != 200:
                return ConnectorResponse(ok=False, status_code=resp.status_code,
                                         error=f"ddg http {resp.status_code}")
            return ConnectorResponse(ok=True, status_code=200, body=resp.content,
                                     headers=dict(resp.headers), elapsed_ms=resp.elapsed_ms)
        except Exception as e:
            return ConnectorResponse(ok=False, error=f"search failed: {e}")

    def normalize(self, response: ConnectorResponse) -> list[dict]:
        if not response.ok:
            return []
        out = []
        for m in _RESULT_RE.finditer(response.text):
            href = _ddg_unwrap(m.group("href"))
            title = re.sub(r"<[^>]+>", "", m.group("title")).strip()
            snippet = re.sub(r"<[^>]+>", "", m.group("snippet")).strip()
            if href.startswith("http"):
                out.append({"url": href, "title": title, "snippet": snippet})
        return out[:25]

    def extract_observations(self, response: ConnectorResponse) -> list[dict]:
        q = ""
        obs: list[dict] = []
        for rec in self.normalize(response):
            obs.append({"predicate": "search.result_found", "subject": q or "query",
                        "obj": rec["url"],
                        "attributes": {"title": rec["title"], "snippet": rec["snippet"][:400]}})
        return obs

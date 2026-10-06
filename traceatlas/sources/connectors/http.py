"""Generic HTTP page connector: fetch any allowlisted public URL as evidence.

This is the workhorse for webint: fetch a page, capture raw bytes, extract
title/links/metadata deterministically (no LLM). Policy-guarded via HttpFetcher.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin

from traceatlas.core.validation import is_http_url
from traceatlas.sources.connectors.base import (
    BaseConnector, ConnectorManifest, ConnectorRequest, ConnectorResponse,
)
from traceatlas.sources.connectors.http_client import HttpFetcher


class _LinkTitleParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title_parts: list[str] = []
        self._in_title = False
        self.links: list[str] = []
        self.meta: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "title":
            self._in_title = True
        elif tag == "a" and a.get("href"):
            href = a["href"].strip()
            if href.startswith(("http://", "https://")):
                self.links.append(href)
            elif not href.startswith(("#", "mailto:", "javascript:")):
                self.links.append(urljoin(self.base_url, href))
        elif tag == "meta":
            key = a.get("property") or a.get("name")
            if key and a.get("content"):
                self.meta[str(key)] = str(a["content"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)

    @property
    def title(self) -> str:
        return re.sub(r"\s+", " ", "".join(self.title_parts)).strip()


def parse_html_page(base_url: str, html_text: str) -> dict:
    p = _LinkTitleParser(base_url)
    p.feed(html_text)
    return {
        "title": p.title,
        "links": sorted(set(p.links)),
        "meta": p.meta,
        "text_preview": re.sub(r"<[^>]+>", " ", html_text)[:2000],
    }


class HttpConnector(BaseConnector):
    name = "http_page"

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        self._http = HttpFetcher(max_bytes=int(self.config.get("max_bytes", 4 * 1024 * 1024)))

    def manifest(self) -> ConnectorManifest:
        return ConnectorManifest(
            id="connector.http",
            name="HTTP page fetcher",
            source_id="source.web",
            capabilities=["http.get"],
            input_types=["url"],
            output_types=["page.fetched", "page.links_to", "page.has_title"],
            rate_limit_rps=1.0,
        )

    def validate_input(self, request: ConnectorRequest) -> list[str]:
        url = request.url or request.target
        if not is_http_url(url):
            return [f"not an http(s) url: {url!r}"]
        return []

    def fetch(self, request: ConnectorRequest) -> ConnectorResponse:
        problems = self.validate_input(request)
        if problems:
            return ConnectorResponse(ok=False, error="; ".join(problems))
        self._throttle()
        try:
            resp = self._http.get(request.url or request.target, headers=request.headers or None,
                                  params=request.params or None)
            ok = 200 <= resp.status_code < 300
            return ConnectorResponse(ok=ok, status_code=resp.status_code, body=resp.content,
                                     headers=dict(resp.headers), elapsed_ms=resp.elapsed_ms,
                                     redirect_chain=resp.redirect_chain,
                                     error="" if ok else f"http {resp.status_code}")
        except Exception as e:
            return ConnectorResponse(ok=False, error=f"fetch failed: {e}")

    def normalize(self, response: ConnectorResponse) -> list[dict]:
        if not response.ok:
            return []
        ctype = response.headers.get("content-type", "")
        if "html" in ctype or response.body.lstrip()[:1] == b"<":
            parsed = parse_html_page(response.redirect_chain[-1] if response.redirect_chain else "",
                                     response.text)
            return [{"kind": "page", "url": response.redirect_chain[-1] if response.redirect_chain else "",
                     **parsed}]
        return [{"kind": "bytes", "size": len(response.body), "content_type": ctype}]

    def extract_observations(self, response: ConnectorResponse) -> list[dict]:
        obs: list[dict] = []
        for rec in self.normalize(response):
            if rec.get("kind") != "page":
                continue
            url = rec["url"]
            if rec.get("title"):
                obs.append({"predicate": "page.has_title", "subject": url,
                            "obj": rec["title"], "attributes": {}})
            for link in rec.get("links", [])[:500]:
                obs.append({"predicate": "page.links_to", "subject": url,
                            "obj": link, "attributes": {}})
        return obs

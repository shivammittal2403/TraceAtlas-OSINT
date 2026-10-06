"""DuckDuckGo provider — html.duckduckgo.com documented lite endpoint.

Verified live in this environment (HTTP 200, parseable result blocks). No API
key required; we keep a conservative rate limit and treat the endpoint as a
beta-quality public search surface (§5 maturity honesty: never claim more).
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, unquote, urlparse

import httpx

from traceatlas.search_discovery.errors import ProviderUnavailableError
from traceatlas.search_discovery.providers.base import (BaseSearchProvider,
                                                         ProviderResponse, RawHit)
from traceatlas.search_discovery.providers.capability import ProviderCapability
from traceatlas.search_discovery.query import CompiledQuery

_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) TraceAtlasResearch/1.0")

_RESULT_RE = re.compile(
    r'<a rel="nofollow" class="result__a" href="(?P<href>[^"]+)">(?P<title>.*?)</a>'
    r'.*?(?:<a class="result__snippet"[^>]*>(?P<snippet>.*?)</a>)?',
    re.S)


def _strip_tags(html: str) -> str:
    return re.sub(r"<[^>]+>", "", html).replace("&amp;", "&").replace(
        "&quot;", '"').strip()


def _decode_href(href: str) -> str:
    """DDG sometimes wraps results in //duckduckgo.com/l/?uddg=<encoded>."""
    if href.startswith("//"):
        href = "https:" + href
    q = urlparse(href)
    if "duckduckgo.com" in q.netloc and "/l/" in q.path:
        target = parse_qs(q.query).get("uddg", [""])
        if target:
            return unquote(target[0])
    return href


class DuckDuckGoProvider(BaseSearchProvider):
    capability = ProviderCapability(
        provider_id="duckduckgo",
        name="DuckDuckGo (html endpoint)",
        supported_operators=frozenset(
            {"exact", "exclude", "site", "filetype", "daterange",
             "intitle", "inurl", "language", "pagination"}),
        api_available=False,               # documented HTML endpoint, not REST API
        rate_limit_per_minute=10.0,
        supports_pagination=True,
        max_results_per_query=30,
        language_filters=True,
        date_filters=True,
        cost_per_query=0.0,
        terms_url="https://duckduckgo.com/traffic.html",
        source_type="web",
        maturity="beta",
    )

    def _http_search(self, compiled: CompiledQuery, *, page: int,
                     max_results: int) -> ProviderResponse:
        data = {"q": compiled.query_string, "kl": compiled.params.get(
            "region", "us-en")}
        if page > 1:
            data["s"] = str((page - 1) * 20)
            data["dc"] = str((page - 1) * 20 + 1)
            data["o"] = "json"
        r = self._client.post("https://html.duckduckgo.com/html/", data=data,
                              headers={"User-Agent": _UA}, timeout=15.0,
                              follow_redirects=True)
        if r.status_code == 403 or "anomaly" in r.text[:400].lower():
            raise ProviderUnavailableError(
                self.provider_id, "DDG anomaly/403 — back off, do not bypass (§45)")
        r.raise_for_status()
        hits: list[RawHit] = []
        for m in _RESULT_RE.finditer(r.text):
            url = _decode_href(m.group("href"))
            if not url.startswith("http"):
                continue
            hits.append(RawHit(url=url,
                               title=_strip_tags(m.group("title")),
                               snippet=_strip_tags(m.group("snippet") or ""),
                               display_url=url))
            if len(hits) >= max_results:
                break
        return ProviderResponse(hits=hits, total_estimated=len(hits),
                                page=page, has_more=len(hits) == max_results,
                                raw_status=r.status_code)

    def _check_health(self) -> bool:
        try:
            r = self._client.get("https://html.duckduckgo.com/html/",
                                 headers={"User-Agent": _UA}, timeout=8.0)
            return r.status_code < 500
        except httpx.HTTPError:
            return False

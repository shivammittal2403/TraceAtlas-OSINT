"""GitHub provider — official REST search APIs (§12).

Endpoints (documented, lawful): /search/repositories, /search/code,
/search/users. Anonymous use is limited; a GITHUB_TOKEN raises limits.
Search API pagination is capped at 1000 results by GitHub itself.

Credential policy (§12/§45): if code search surfaces token-like strings we
REDACT them and record a defensive exposure finding; we never validate or use
secrets.
"""

from __future__ import annotations

import os
from urllib.parse import quote

import httpx

from traceatlas.search_discovery.errors import (ProviderUnavailableError,
                                                 RateLimitedError)
from traceatlas.search_discovery.providers.base import (BaseSearchProvider,
                                                         ProviderResponse, RawHit,
                                                         redact_secrets)
from traceatlas.search_discovery.providers.capability import ProviderCapability
from traceatlas.search_discovery.query import CompiledQuery

_API = "https://api.github.com"


class GitHubSearchProvider(BaseSearchProvider):
    capability = ProviderCapability(
        provider_id="github",
        name="GitHub Search API",
        supported_operators=frozenset(
            {"exact", "exclude", "site", "filetype", "inurl", "pagination"}),
        api_available=True,
        authentication_required=False,      # works anonymously at low rate
        auth_env_var="GITHUB_TOKEN",
        rate_limit_per_minute=5.0,          # anonymous: 10/min search; be polite
        quota_per_day=60,                   # anonymous search cap ballpark
        supports_pagination=True,
        max_results_per_query=30,
        cost_per_query=0.0,
        terms_url="https://docs.github.com/en/rest/search",
        source_type="code",
        maturity="stable",
    )

    def __init__(self, *, token_env: str = "GITHUB_TOKEN", **kw):
        super().__init__(**kw)
        self._token_env = token_env
        self.exposure_findings: list[dict] = []   # §12 defensive flagging

    def token(self) -> str:
        return os.environ.get(self._token_env, "")

    def _headers(self) -> dict:
        h = {"Accept": "application/vnd.github+json",
             "X-GitHub-Api-Version": "2022-11-28",
             "User-Agent": "TraceAtlas-Research/1.0"}
        tok = self.token()
        if tok:
            h["Authorization"] = f"Bearer {tok}"
            self.capability  # rate limit effectively raised with auth
        return h

    def _http_search(self, compiled: CompiledQuery, *, page: int,
                     max_results: int) -> ProviderResponse:
        kind = compiled.params.get("gh_kind", "repositories")
        per = min(max_results, 100 if kind == "repositories" else 30)
        url = f"{_API}/search/{kind}"
        params = {"q": compiled.query_string, "per_page": per, "page": page}
        try:
            r = self._client.get(url, params=params, headers=self._headers(),
                                 timeout=15.0)
        except httpx.HTTPError as exc:
            raise ProviderUnavailableError(self.provider_id, str(exc)) from exc
        if r.status_code == 403 and r.headers.get("X-RateLimit-Remaining") == "0":
            raise RateLimitedError(self.provider_id, "GitHub rate limit",
                                   retry_after=max(
                                       60 - (r.elapsed.total_seconds() % 60), 5))
        if r.status_code in (401, 422, 451):
            raise ProviderUnavailableError(
                self.provider_id, f"GitHub rejected request ({r.status_code})")
        r.raise_for_status()
        data = r.json()
        hits: list[RawHit] = []
        for item in data.get("items", [])[:max_results]:
            hit = self._map_item(kind, item)
            if hit:
                hits.append(hit)
        return ProviderResponse(hits=hits,
                                total_estimated=int(data.get("total_count", len(hits))),
                                page=page,
                                has_more=page * max_results < int(
                                    data.get("total_count", 0)),
                                raw_status=r.status_code)

    def _map_item(self, kind: str, item: dict) -> RawHit | None:
        if kind == "repositories":
            desc = (item.get("description") or "")[:500]
            desc, n = redact_secrets(desc)
            if n:
                self.exposure_findings.append({
                    "where": item.get("html_url"), "kind": "secret_in_description"})
            snippet = (f"stars={item.get('stargazers_count')} "
                       f"lang={item.get('language')} updated={item.get('pushed_at')}"
                       f" :: {desc}")
            return RawHit(url=item["html_url"], title=item.get("full_name", ""),
                          snippet=snippet, published_at=item.get("created_at", ""),
                          content_type_hint="code")
        if kind == "users":
            return RawHit(url=item["html_url"], title=item.get("login", ""),
                          snippet=(item.get("bio") or "")[:400],
                          published_at=item.get("created_at", ""),
                          content_type_hint="social")
        if kind == "code":
            frag = item.get("repository", {}).get("html_url", "")
            path = item.get("path", "")
            text, n = redact_secrets(item.get("name", ""))
            if n:
                self.exposure_findings.append({"where": f"{frag}/{path}",
                                               "kind": "secret_candidate_in_path"})
            return RawHit(url=f"{frag}/blob/HEAD/{quote(path)}" if frag else path,
                          title=f"{text}",
                          snippet=f"code match in {frag} :: {path}",
                          content_type_hint="code")
        return None

    def _check_health(self) -> bool:
        try:
            r = self._client.get(f"{_API}/zen", headers=self._headers(), timeout=8.0)
            return r.status_code == 200
        except httpx.HTTPError:
            return False

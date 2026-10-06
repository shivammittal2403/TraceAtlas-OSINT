"""Base search provider: capability-declared, lawful-access-only (§5, §14, §45).

Concrete providers implement `_http_search` against the provider's documented
API/endpoint. The base class provides:
- compile(): generic QuerySpec -> engine-specific syntax honoring capabilities
- search():  rate limiting, pagination, normalization, error recording
- health():  cheap liveness probe (cached)

Security policy (§45): this layer NEVER fetches authenticated pages, bypasses
paywalls/CAPTCHAs, or harvests credentials. Incidental secrets in snippets are
redacted before storage.
"""

from __future__ import annotations

import os
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import date

import httpx

from traceatlas.search_discovery.errors import (PaginationError,
                                                  ProviderError,
                                                  ProviderUnavailableError,
                                                  RateLimitedError)
from traceatlas.search_discovery.providers.capability import ProviderCapability
from traceatlas.search_discovery.query import CompiledQuery, QuerySpec, DateRange
from traceatlas.search_discovery.result import SearchResult

# Redaction of incidental secret material (§12, §45): we keep the *fact* of an
# exposure but never the value.
_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(?:AKIA[0-9A-Z]{16})\b"),
    re.compile(r"(?i)\bBEGIN [A-Z ]*PRIVATE KEY\b.*"),
    re.compile(r"(?i)\bghp_[0-9A-Za-z]{36}\b"),
    re.compile(r"(?i)\bxox[bpors]-[0-9A-Za-z-]{10,}\b"),
    re.compile(r"(?i)(?:password|passwd|secret)\s*[=:]\s*\S+"),
    re.compile(r"(?i)\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
]


def redact_secrets(text: str) -> tuple[str, int]:
    """Replace secret-looking spans with [REDACTED:<kind>]; return (text, count)."""
    n = 0
    for pat in _SECRET_PATTERNS:
        text, k = pat.subn("[REDACTED]", text)
        n += k
    return text, n


_JULIAN_MIN = date(1970, 1, 1).toordinal()


def _to_julian(iso: str) -> int | None:
    try:
        y, m, d = (int(x) for x in iso.split("-")[:3])
        return date(y, m, d).toordinal() + _JULIAN_MIN - 1
    except (ValueError, IndexError):
        return None


@dataclass
class RawHit:
    """Provider-native result row before normalization."""
    url: str
    title: str = ""
    snippet: str = ""
    display_url: str = ""
    published_at: str = ""
    language: str = ""
    content_type_hint: str = "web"


@dataclass
class ProviderResponse:
    hits: list[RawHit] = field(default_factory=list)
    total_estimated: int = 0
    page: int = 1
    has_more: bool = False
    raw_status: int = 200
    latency_ms: float = 0.0
    error: str = ""


class BaseSearchProvider(ABC):
    capability: ProviderCapability

    def __init__(self, *, client: httpx.Client | None = None,
                 clock=time.monotonic):
        self._client = client or httpx.Client(timeout=httpx.Timeout(15.0))
        self._clock = clock
        self._next_allowed = 0.0
        self._health_cache: tuple[bool, float] | None = None
        self.calls: list[dict] = []          # audit log (§9 cost/latency)

    # ------------------------------------------------------------ identity
    @property
    def provider_id(self) -> str:
        return self.capability.provider_id

    def token(self) -> str:
        return os.environ.get(self.capability.auth_env_var, "") if \
            self.capability.auth_env_var else ""

    # ------------------------------------------------------------ compiling
    def compile(self, spec: QuerySpec) -> CompiledQuery:
        """Translate generic intent into engine syntax; drop unsupported ops (§5)."""
        cap = self.capability
        parts: list[str] = []
        supported: list[str] = []
        dropped: list[str] = []
        params: dict = {}

        for t in spec.exact_terms:
            if cap.supports("exact"):
                parts.append(f'"{t}"'); supported.append("exact")
            else:
                parts.append(t)

        for t in spec.terms:
            parts.append(_quote_if_needed(t))

        for t in spec.excluded_terms:
            if cap.supports("exclude"):
                parts.append(f"-{t}"); supported.append("exclude")
            else:
                dropped.append(f"exclude:{t}")

        if spec.site:
            if cap.supports("site"):
                parts.append(f"site:{spec.site}"); supported.append("site")
            else:
                dropped.append(f"site:{spec.site}")

        for ft in spec.filetypes:
            ft = ft.lower().lstrip(".")
            if cap.supports("filetype"):
                parts.append(f"filetype:{ft}"); supported.append("filetype")
            else:
                dropped.append(f"filetype:{ft}")

        for t in spec.title_terms:
            if cap.supports("intitle"):
                parts.append(f"intitle:{_quote_if_needed(t)}")
                supported.append("intitle")
            else:
                dropped.append(f"intitle:{t}")

        for t in spec.url_terms:
            if cap.supports("inurl"):
                parts.append(f"inurl:{_quote_if_needed(t)}")
                supported.append("inurl")
            else:
                dropped.append(f"inurl:{t}")

        for t in spec.body_terms:
            if cap.supports("inbody"):
                parts.append(f"inbody:{_quote_if_needed(t)}")
                supported.append("inbody")
            else:
                dropped.append(f"inbody:{t}")

        if spec.date_range:
            if cap.supports("daterange"):
                j1 = _to_julian(spec.date_range.after)
                j2 = _to_julian(spec.date_range.before)
                if j1 and j2:
                    parts.append(f"daterange:{j1}-{j2}")
                    supported.append("daterange")
                else:
                    dropped.append("daterange:bad-date")
            else:
                dropped.append("daterange")

        if spec.language:
            if cap.language_filters:
                params["language"] = spec.language
                supported.append("language")
            else:
                dropped.append(f"language:{spec.language}")

        if spec.region:
            if cap.region_filters:
                params["region"] = spec.region
                supported.append("region")
            else:
                dropped.append(f"region:{spec.region}")

        qs = " ".join(parts).strip()
        valid = bool(qs or params)
        reason = "" if valid else "empty compiled query"
        return CompiledQuery(provider_id=cap.provider_id, query_string=qs,
                             supported_ops=sorted(set(supported)),
                             dropped_ops=dropped, params=params,
                             valid=valid, invalid_reason=reason)

    # ------------------------------------------------------------ execution
    def search(self, compiled: CompiledQuery, *, page: int = 1,
               max_results: int | None = None) -> ProviderResponse:
        if not compiled.valid:
            raise ProviderError(self.provider_id,
                                f"refused invalid compiled query: {compiled.invalid_reason}")
        if page < 1:
            raise PaginationError(self.provider_id, f"page must be >=1, got {page}")
        if not self.capability.supports_pagination and page > 1:
            raise PaginationError(self.provider_id, "provider does not paginate")
        self._wait_for_slot()
        t0 = self._clock()
        try:
            resp = self._http_search(compiled, page=page,
                                     max_results=min(max_results or 10,
                                                     self.capability.max_results_per_query))
        except RateLimitedError:
            self._backoff()
            raise
        except ProviderUnavailableError:
            raise
        except httpx.HTTPStatusError as exc:      # pragma: no cover - network path
            status = exc.response.status_code
            if status == 429:
                ra = float(exc.response.headers.get("Retry-After", "5"))
                self._backoff(retry_after=ra)
                raise RateLimitedError(self.provider_id, "HTTP 429", ra) from exc
            raise ProviderUnavailableError(self.provider_id,
                                           f"HTTP {status}") from exc
        except httpx.HTTPError as exc:            # pragma: no cover - network path
            raise ProviderUnavailableError(self.provider_id, str(exc)) from exc
        latency = (self._clock() - t0) * 1000.0
        resp.latency_ms = latency
        # normalize + redact (§11, §45) — snippets preserved but sanitized
        for h in resp.hits:
            h.snippet, n = redact_secrets(h.snippet)
            h.title, _ = redact_secrets(h.title)
            if n:
                h.content_type_hint = h.content_type_hint or "web"
        self.calls.append({"query": compiled.query_string, "page": page,
                           "hits": len(resp.hits), "latency_ms": round(latency, 1),
                           "at": time.time()})
        return resp

    @abstractmethod
    def _http_search(self, compiled: CompiledQuery, *, page: int,
                     max_results: int) -> ProviderResponse:
        """Provider-specific HTTP call. Must map native errors to taxonomy."""

    def to_result(self, hit: RawHit, rank: int, query_id: str) -> SearchResult:
        return SearchResult(result_id=f"res_{self.provider_id}_{abs(hash((hit.url, query_id))) % 10**12}",
                            query_id=query_id, provider=self.provider_id,
                            rank=rank, title=hit.title, url=hit.url,
                            display_url=hit.display_url or hit.url,
                            snippet=hit.snippet, published_at=hit.published_at,
                            language=hit.language,
                            content_type=hit.content_type_hint)

    # ------------------------------------------------------------ ops
    def _wait_for_slot(self) -> None:
        interval = 60.0 / max(self.capability.rate_limit_per_minute, 0.001)
        now = self._clock()
        wait = self._next_allowed - now
        if wait > 0:
            time.sleep(wait)
            now = self._clock()
        self._next_allowed = max(now, self._next_allowed) + interval

    def _backoff(self, retry_after: float = 2.0) -> None:
        self._next_allowed = self._clock() + retry_after

    def health(self) -> bool:
        if self._health_cache and time.time() - self._health_cache[1] < 30:
            return self._health_cache[0]
        try:
            ok = self._check_health()
        except Exception:
            ok = False
        self._health_cache = (ok, time.time())
        return ok

    def _check_health(self) -> bool:
        try:
            r = self._client.get(self.capability.terms_url or "https://example.com",
                                 timeout=5.0)
            return r.status_code < 500
        except httpx.HTTPError:
            return False

    def capabilities(self) -> dict:
        return self.capability.to_dict()


def _quote_if_needed(term: str) -> str:
    term = term.strip()
    if re.search(r"\s", term) and not (term.startswith('"') and term.endswith('"')):
        return f'"{term}"'
    return term

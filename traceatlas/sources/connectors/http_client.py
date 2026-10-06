"""Shared, policy-guarded HTTP client used by all real connectors.

Security properties:
  - every URL passes UrlPolicy (scheme/allow/deny) before DNS resolution
  - DNS answers are validated against private/loopback/link-local ranges (SSRF)
  - redirects are re-validated hop-by-hop (no redirect-to-169.254.169.254)
  - response bodies are size-capped (archive-bomb / memory safety)
  - retries with exponential backoff + jitter for transient failures
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field

import httpx

from traceatlas.exceptions import SourceError
from traceatlas.security.url_policy import DEFAULT_POLICY, UrlPolicy, UrlPolicyError

DEFAULT_TIMEOUT_S = 15.0
DEFAULT_MAX_BYTES = 8 * 1024 * 1024  # 8 MiB per response body


@dataclass
class HttpResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    content: bytes
    elapsed_ms: float
    redirect_chain: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> object:
        import json

        return json.loads(self.text)


class HttpFetcher:
    """Small hardened wrapper over httpx with policy checks and bounded retries."""

    def __init__(
        self,
        policy: UrlPolicy | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_bytes: int = DEFAULT_MAX_BYTES,
        max_retries: int = 2,
        backoff_base_s: float = 0.5,
        user_agent: str = "TraceAtlasBot/0.1 (+https://github.com/shivammittal2403/TraceAtlas-OSINT)",
    ) -> None:
        self.policy = policy or DEFAULT_POLICY
        self.timeout_s = timeout_s
        self.max_bytes = max_bytes
        self.max_retries = max_retries
        self.backoff_base_s = backoff_base_s
        self.user_agent = user_agent

    def get(self, url: str, headers: dict | None = None, params: dict | None = None) -> HttpResponse:
        last_err: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                return self._get_once(url, headers, params)
            except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as e:
                last_err = e
                if attempt < self.max_retries:
                    delay = self.backoff_base_s * (2 ** attempt) + random.uniform(0, 0.25)
                    time.sleep(delay)
        raise SourceError(f"fetch failed after retries: {url}: {last_err}") from last_err

    def _get_once(self, url: str, headers: dict | None, params: dict | None) -> HttpResponse:
        # Build full URL including params so the policy sees the final destination.
        base = httpx.URL(url, params=params or {})
        # Validate + resolve up front (fail closed). We then let httpx perform the
        # actual request; a TOCTOU window remains only for rebinding within one TTL,
        # which is documented and mitigated by short-lived evidence + re-check on redirect.
        try:
            self.policy.safe_resolve(str(base))
        except UrlPolicyError:
            raise
        merged_headers = {"User-Agent": self.user_agent}
        if headers:
            merged_headers.update(headers)
        start = time.monotonic()
        chain: list[str] = []
        current = str(base)
        with httpx.Client(timeout=self.timeout_s, follow_redirects=False) as client:
            for _hop in range(6):  # bounded redirect following, re-validated per hop
                resp = client.get(current, headers=merged_headers)
                chain.append(current)
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location")
                    if not location:
                        break
                    nxt = httpx.URL(current).join(location)
                    # SECURITY: re-validate the redirect target (SSRF via redirect).
                    self.policy.safe_resolve(str(nxt))
                    current = str(nxt)
                    continue
                break
        content = resp.content[: self.max_bytes]
        if len(resp.content) > self.max_bytes:
            raise SourceError(f"response exceeds size cap ({self.max_bytes} bytes): {current}")
        return HttpResponse(
            url=current,
            status_code=resp.status_code,
            headers={k.lower(): v for k, v in resp.headers.items()},
            content=content,
            elapsed_ms=(time.monotonic() - start) * 1000,
            redirect_chain=chain,
        )

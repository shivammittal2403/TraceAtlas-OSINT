"""SSRF protection: refuse non-HTTP schemes and private destinations by default."""

from __future__ import annotations

from traceatlas.core.validation import is_http_url
from traceatlas.exceptions import PolicyViolation
from traceatlas.security.url_policy import is_private_host


def assert_egress_allowed(url: str, *, allow_private: bool = False) -> None:
    if not is_http_url(url):
        raise PolicyViolation(f"non-http(s) URL refused: {url!r}")
    if not allow_private and is_private_host(url):
        raise PolicyViolation(f"private/internal destination refused (SSRF guard): {url!r}")

"""URL policy: classify destination as safe/unsafe for egress (SSRF guard input)."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from traceatlas.core.validation import is_http_url


def parse_host(url: str) -> str:
    return urlparse(url).hostname or ""


def is_private_host(url: str) -> bool:
    """True if host is a private/loopback/link-local literal. DNS-rebinding checks
    at connect-time are NOT yet implemented (documented gap)."""
    host = parse_host(url)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host in ("localhost", "metadata.google.internal") or host.endswith(".internal")
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved

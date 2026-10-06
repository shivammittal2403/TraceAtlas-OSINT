"""URL safety policy: SSRF protection and allow/deny rules for all outbound fetches.

Every network-capable connector MUST route requests through `UrlPolicy.check` /
`assert_url_safe` before touching the socket. This blocks:
  - non-http(s) schemes (file:, gopher:, dict:, data:)
  - loopback / private / link-local / multicast / reserved addresses (SSRF)
  - cloud metadata endpoints (169.254.169.254)
  - optional host allowlist enforcement
DNS-rebinding mitigation: resolve the hostname once, validate ALL returned
addresses, and hand pinned IPs to the connector (see connectors/http_client.py).
"""

from __future__ import annotations

import fnmatch
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

from traceatlas.exceptions import PolicyViolation

_BLOCKED_SCHEMES = {"file", "gopher", "dict", "data", "ftp", "ftps", "ssh", "telnet"}


class UrlPolicyError(PolicyViolation):
    """Raised when a URL fails the security policy."""


def is_blocked_ip(ip_str: str) -> bool:
    """True if an IP literal must never be contacted by collectors (fail closed)."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def parse_host(url: str) -> str:
    return urlparse(url).hostname or ""


def is_private_host(url: str) -> bool:
    """True if host is a private/loopback/link-local/metadata address or internal name."""
    host = parse_host(url)
    if not host:
        return True
    if host == "localhost" or host.endswith(".internal") or host.endswith(".local"):
        return True
    try:
        return is_blocked_ip(host)
    except Exception:
        return False


@dataclass
class UrlPolicy:
    allowlist: list[str] = field(default_factory=list)   # glob host patterns; empty = any public host
    denylist: list[str] = field(default_factory=list)
    allowed_schemes: tuple[str, ...] = ("http", "https")
    block_private_networks: bool = True

    def _host_match(self, host: str, patterns: list[str]) -> bool:
        return any(fnmatch.fnmatchcase(host, p) or host == p.lstrip(".") for p in patterns)

    def check(self, url: str) -> str:
        """Validate scheme/port/host policy. Returns normalized host or raises."""
        parsed = urlparse(url)
        if parsed.scheme not in self.allowed_schemes:
            raise UrlPolicyError(f"scheme blocked: {parsed.scheme!r}")
        host = parsed.hostname
        if not host:
            raise UrlPolicyError("missing host")
        if parsed.port is not None and not (0 < parsed.port <= 65535):
            raise UrlPolicyError(f"invalid port: {parsed.port}")
        if self._host_match(host.lower(), self.denylist):
            raise UrlPolicyError(f"host denied: {host}")
        if self.allowlist and not self._host_match(host.lower(), self.allowlist):
            raise UrlPolicyError(f"host not in allowlist: {host}")
        return host.lower()

    def safe_resolve(self, url: str) -> tuple[str, list[str]]:
        """Check policy + resolve DNS, validating every answer (anti DNS-rebinding).

        Returns (host, [validated ips]). Connectors should pin connections to these IPs.
        """
        host = self.check(url)
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as e:
            raise UrlPolicyError(f"dns resolution failed for {host}: {e}") from e
        ips = sorted({i[4][0] for i in infos})
        if not ips:
            raise UrlPolicyError(f"no dns answers for {host}")
        if self.block_private_networks:
            for ip in ips:
                if is_blocked_ip(ip):
                    raise UrlPolicyError(
                        f"blocked address {ip} for host {host} (SSRF guard)")
        return host, ips


DEFAULT_POLICY = UrlPolicy()


def assert_url_safe(url: str, policy: UrlPolicy | None = None) -> tuple[str, list[str]]:
    """One-call guard used by every real connector before any network I/O."""
    return (policy or DEFAULT_POLICY).safe_resolve(url)

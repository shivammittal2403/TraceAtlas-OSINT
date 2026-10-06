"""Shared validation helpers."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import urlparse

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def is_valid_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value.lower().rstrip(".")))


def is_valid_ipv4(value: str) -> bool:
    if not _IPV4_RE.match(value):
        return False
    return all(0 <= int(part) <= 255 for part in value.split("."))


def is_http_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def require(condition: bool, message: str) -> None:
    if not condition:
        from traceatlas.exceptions import ValidationError

        raise ValidationError(message)

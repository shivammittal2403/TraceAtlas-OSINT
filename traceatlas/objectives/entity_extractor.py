"""Extract candidate target entities from objective text using patterns."""

from __future__ import annotations

import re

from traceatlas.core.enums import EntityType
from traceatlas.core.validation import is_valid_domain, is_valid_ipv4

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|in|co|de|ru|cn|uk|info|xyz)\b", re.I)
_ASN_RE = re.compile(r"\bAS\s?\d{1,6}\b", re.I)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_USERNAME_RE = re.compile(r"(?:username|handle|alias)\s+[\"']?([A-Za-z0-9_.-]{3,32})[\"']?", re.I)


def extract_entities(text: str) -> list[dict]:
    found: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(etype: EntityType, value: str) -> None:
        key = (etype.value, value.lower())
        if key not in seen:
            seen.add(key)
            found.append({"type": etype.value, "value": value})

    for m in _IPV4_RE.finditer(text):
        if is_valid_ipv4(m.group()):
            add(EntityType.IP_ADDRESS, m.group())
    for m in _DOMAIN_RE.finditer(text):
        d = m.group().lower()
        if is_valid_domain(d):
            add(EntityType.DOMAIN, d)
    for m in _ASN_RE.finditer(text):
        add(EntityType.ASN, m.group().upper().replace(" ", ""))
    for m in _EMAIL_RE.finditer(text):
        add(EntityType.EMAIL, m.group().lower())
    for m in _USERNAME_RE.finditer(text):
        add(EntityType.USERNAME, m.group(1))
    return found

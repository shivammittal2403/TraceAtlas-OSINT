"""Value normalization used before matching (deterministic, testable)."""

from __future__ import annotations

import re
import unicodedata


def _nfkc(value: str) -> str:
    return unicodedata.normalize("NFKC", value)


def normalize_domain(value: str) -> str:
    return _nfkc(value.strip().lower()).rstrip(".")


def normalize_ip(value: str) -> str:
    return _nfkc(value.strip())


def normalize_email(value: str) -> str:
    v = _nfkc(value.strip().lower())
    # NOTE: we do NOT apply provider-specific dot stripping; that is a policy choice
    # documented as unimplemented.
    return v


def normalize_username(value: str) -> str:
    return _nfkc(value.strip().lower()).lstrip("@")


def normalize_asn(value: str) -> str:
    m = re.search(r"(\d{1,6})", _nfkc(value.upper()))
    return f"AS{m.group(1)}" if m else _nfkc(value).upper()


def normalize_person_name(value: str) -> str:
    v = _nfkc(value.lower())
    v = re.sub(r"[^\p{L}\s]" if False else r"[^a-z\s'.-]", "", v)
    return re.sub(r"\s+", " ", v).strip()


def normalize_hash(value: str) -> str:
    return _nfkc(value.strip().lower())


NORMALIZERS = {
    "domain": normalize_domain,
    "ip": normalize_ip,
    "email": normalize_email,
    "username": normalize_username,
    "asn": normalize_asn,
    "person_name": normalize_person_name,
    "hash_lower": normalize_hash,
}

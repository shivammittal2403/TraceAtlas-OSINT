"""DETERMINISTIC VALIDATION GATE — runs BEFORE any AI pass (§8).

Validates raw connector results: HTTP status, required fields, syntax of
IDs/URLs/IPs/domains/emails/CVEs/wallets/coordinates, impossible dates,
duplicates, parser/normalizer status. On failure the result is marked
INVALID/MALFORMED/PARTIAL/SCHEMA_DRIFT/STALE/UNKNOWN and AI passes are NOT
allowed to silently repair evidence — they may only report on the mark.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from traceatlas.core.validation import is_http_url, is_valid_domain

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_WALLET_RE = re.compile(r"^(0x[0-9a-fA-F]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{27,62}|[45][1-9A-HJ-NP-Za-km-z]{33})$")
_SHA_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_FUTURE_SKEW_SECONDS = 300   # tolerate small clock skew

ValidationStatus = str  # VALID | INVALID | MALFORMED | PARTIAL | SCHEMA_DRIFT | STALE | UNKNOWN


@dataclass
class ValidationResult:
    status: ValidationStatus = "UNKNOWN"
    issues: list[str] = field(default_factory=list)
    checked_fields: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == "VALID"


def _parse_ts(value) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def validate_connector_result(payload: dict, *, http_status: int = 200,
                              required_fields: list[str] | None = None,
                              now: datetime | None = None,
                              max_age_seconds: float | None = None) -> ValidationResult:
    """Deterministically validate one raw API/source result (§8)."""
    now = now or datetime.now(timezone.utc)
    res = ValidationResult()
    if not isinstance(payload, dict):
        res.status = "MALFORMED"
        res.issues.append("payload is not a JSON object")
        return res

    if http_status < 200 or http_status >= 300:
        res.issues.append(f"http_status={http_status} non-2xx")
        res.status = "INVALID"
        return res

    for f in required_fields or []:
        if f not in payload or payload[f] in (None, ""):
            res.issues.append(f"missing required field: {f}")
    if res.issues:
        res.status = "SCHEMA_DRIFT" if required_fields else "PARTIAL"

    checks = {
        "ip": lambda v: _ip_ok(str(v)),
        "ipv4": lambda v: _ip_ok(str(v)),
        "domain": lambda v: is_valid_domain(str(v)),
        "email": lambda v: bool(_EMAIL_RE.match(str(v))),
        "cve": lambda v: bool(_CVE_RE.match(str(v))),
        "wallet": lambda v: bool(_WALLET_RE.match(str(v))),
        "url": lambda v: is_http_url(str(v)),
        "hash": lambda v: bool(_SHA_RE.match(str(v))),
        "sha256": lambda v: bool(_SHA_RE.match(str(v))),
        "latitude": lambda v: -90 <= float(v) <= 90,
        "longitude": lambda v: -180 <= float(v) <= 180,
        "lat": lambda v: -90 <= float(v) <= 90,
        "lon": lambda v: -180 <= float(v) <= 180,
    }
    for key, value in payload.items():
        checker = checks.get(key.lower())
        if checker is None or value in (None, ""):
            continue
        res.checked_fields.append(key)
        try:
            if not checker(value):
                res.issues.append(f"syntax invalid for {key}: {value!r}")
                res.status = "MALFORMED" if res.status in ("UNKNOWN", "VALID") else res.status
        except (TypeError, ValueError):
            res.issues.append(f"type invalid for {key}: {value!r}")
            res.status = "MALFORMED"

    # timestamps: impossible/future dates + staleness
    for key in ("last_seen", "first_seen", "observed_at", "captured_at",
                "event_time", "retrieved_at", "updated_at"):
        if key in payload and payload[key] not in (None, ""):
            ts = _parse_ts(payload[key])
            if ts is None:
                res.issues.append(f"unparseable timestamp in {key}: {payload[key]!r}")
                res.status = "MALFORMED" if res.status in ("UNKNOWN", "VALID") else res.status
                continue
            res.checked_fields.append(key)
            if ts > now + __import__("datetime").timedelta(seconds=_FUTURE_SKEW_SECONDS):
                res.issues.append(f"impossible future date in {key}: {ts.isoformat()}")
                res.status = "INVALID"
            elif max_age_seconds is not None and (now - ts).total_seconds() > max_age_seconds:
                res.issues.append(f"stale {key}: age {(now - ts).total_seconds():.0f}s "
                                  f"> {max_age_seconds:.0f}s")
                if res.status in ("UNKNOWN", "VALID"):
                    res.status = "STALE"

    # duplicate marker
    if payload.get("__duplicate__"):
        res.issues.append("duplicate record detected by ingestion fabric")
        if res.status in ("UNKNOWN", "VALID"):
            res.status = "PARTIAL"

    if not res.issues:
        res.status = "VALID"
    elif res.status == "UNKNOWN":
        res.status = "PARTIAL"
    return res


def _ip_ok(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

#!/usr/bin/env python3
"""
TRACEATLAS BEHAVINT — Safe Python Starter Implementation

Purpose:
  Evidence-first observable behavioural intelligence pipeline.

Hard boundaries enforced in code:
  - Does NOT stalk or track private persons in real time.
  - Does NOT perform biometric identification.
  - Does NOT infer religion, ethnicity, race, political belief, sexual orientation,
    health, mental health, disability, or private intimate behaviour.
  - Does NOT perform psychological profiling, personality scoring, or lie detection.
  - Does NOT generate dangerousness, criminality, loyalty, or predictive-policing scores.
  - Does NOT optimize manipulation, coercion, or persuasion against individuals.
  - Does NOT make autonomous consequential employment, credit, insurance, or law-enforcement decisions.
  - Treats account/device/session activity as account-level evidence, not automatic person attribution.
  - Treats anomaly as deviation, not malice.
  - Treats coordination signal as candidate, not confirmed common controller.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

VERSION = "0.1.0-behavint-safe-starter"
FAR_FUTURE = datetime(9999, 12, 31, tzinfo=timezone.utc)

try:
    from zoneinfo import ZoneInfo  # type: ignore
    HAS_ZONEINFO = True
except Exception:
    HAS_ZONEINFO = False


# --------------------------------------------------------------------
# Policy / privacy constants
# --------------------------------------------------------------------

ALLOWED_SCOPES = {
    "public_and_authorized_records",
    "authorized_case_evidence",
    "authorized_enterprise_telemetry",
    "authorized_security_operations",
    "provided_records_only",
}

SENSITIVE_KEYS = {
    "race",
    "ethnicity",
    "religion",
    "faith",
    "sexual_orientation",
    "sex_life",
    "health",
    "medical_condition",
    "disability",
    "mental_health",
    "psychological_profile",
    "personality",
    "political_belief",
    "political_affiliation",
    "union_membership",
    "biometric",
    "face",
    "facial",
    "voiceprint",
    "gait",
    "fingerprint",
    "iris",
    "dna",
    "lie_detector",
    "deception",
    "dangerousness",
    "criminality",
    "criminal_propensity",
    "loyalty",
    "extremism",
    "terrorism_probability",
    "fraudster_score",
}

CONTENT_KEYS = {
    "message_body",
    "email_body",
    "chat_log",
    "content",
    "transcript",
    "recording",
    "private_message",
    "dm",
}

EXACT_LOCATION_KEYS = {
    "latitude",
    "longitude",
    "lat",
    "lon",
    "gps",
    "home_address",
    "private_address",
    "street_address",
    "exact_location",
}

VOLUME_KEYS = {
    "volume",
    "amount",
    "bytes",
    "record_count",
    "rows",
    "size_mb",
    "quantity",
    "value",
}

PERSON_ENTITY_PATTERN = re.compile(r"(?i)^(person|individual|human|employee|candidate)[:_-]")

PROHIBITED_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"(?i)\b(stalk|real[- ]time track|live track|surveil)\s+(person|individual|employee|target|someone)"),
        "PRIVATE_STALKING_OR_REAL_TIME_TRACKING",
    ),
    (
        re.compile(r"(?i)\b(face recognition|voiceprint|biometric identif|gait recognition|typing cadence.*identify)"),
        "BIOMETRIC_IDENTIFICATION_REQUEST",
    ),
    (
        re.compile(r"(?i)\b(psycholog.*(diagnos|profile)|personality (score|disorder)|mental health (diagnos|assess)|lie detect|deception detect)"),
        "PSYCHOLOGICAL_PROFILING_OR_LIE_DETECTION",
    ),
    (
        re.compile(r"(?i)\b(infer|determine|classify|score)\s+(religion|ethnicity|race|political belief|sexual orientation|medical condition|mental health|criminality|dangerousness|loyalty)"),
        "SENSITIVE_TRAIT_OR_RISK_PROFILING",
    ),
    (
        re.compile(r"(?i)\b(predictive policing|crime prediction|criminal propensity|terrorist probability|dangerousness score)"),
        "PREDICTIVE_POLICING_OR_DANGEROUSNESS_SCORE",
    ),
    (
        re.compile(r"(?i)\b(manipulat|coerc|persua|influence).*\b(target|person|individual|employee)"),
        "MANIPULATION_OR_PERSUASION_REQUEST",
    ),
    (
        re.compile(r"(?i)\b(autonomous|automatic).*(hire|fire|terminate|credit decision|insurance decision|law.enforcement action|arrest)"),
        "AUTONOMOUS_CONSEQUENTIAL_DECISION",
    ),
]

SOURCE_RELIABILITY: Dict[str, float] = {
    "signed_system_log": 0.92,
    "identity_log": 0.88,
    "application_log": 0.82,
    "endpoint_telemetry": 0.82,
    "network_telemetry": 0.78,
    "cloud_audit_log": 0.84,
    "siem_event": 0.80,
    "authorized_workflow": 0.82,
    "authorized_ticketing": 0.78,
    "transaction_record": 0.88,
    "payment_metadata": 0.86,
    "fraud_telemetry": 0.72,
    "public_repository": 0.58,
    "public_website": 0.55,
    "public_social_post": 0.45,
    "self_reported": 0.35,
    "third_party_report": 0.40,
    "unknown": 0.30,
}

HIGH_AUTHORITY_SOURCE_TYPES = {
    "signed_system_log",
    "identity_log",
    "application_log",
    "endpoint_telemetry",
    "network_telemetry",
    "cloud_audit_log",
    "siem_event",
    "authorized_workflow",
    "transaction_record",
    "payment_metadata",
}

TIMESTAMP_TYPE_PRIORITY = {
    "EVENT_TIME": 0,
    "OBSERVED_TIME": 1,
    "RECORDED_TIME": 2,
    "PROCESSED_TIME": 3,
    "REPORTED_TIME": 4,
    "PUBLISHED_TIME": 5,
    "INGESTION_TIME": 6,
    "DISCOVERY_TIME": 7,
    "KNOWLEDGE_TIME": 8,
    "UNKNOWN": 99,
}

BENIGN_CONTEXT_TYPES = {
    "role_change",
    "system_migration",
    "maintenance",
    "project",
    "automation",
    "scheduled_process",
    "policy_change",
    "business_event",
    "holiday",
    "deployment",
    "incident_response",
}

CONTAMINATING_CONTEXT_TYPES = {
    "incident",
    "abuse",
    "migration",
    "special_project",
    "holiday",
    "outage",
    "data_backfill",
}

AUTOMATION_EVENT_HINTS = {
    "CRON",
    "SCHEDULED_JOB",
    "AUTOMATION",
    "SERVICE_ACCOUNT",
    "BOT",
    "BATCH",
    "PIPELINE",
}


# --------------------------------------------------------------------
# Generic helpers
# --------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_id(prefix: str, *parts: Any) -> str:
    raw = "|".join(str(json_safe(p)) for p in parts)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{digest}"


def json_safe(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [json_safe(x) for x in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, timedelta):
        return obj.total_seconds()
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    return str(obj)


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    s = unicodedata.normalize("NFKC", str(value))
    s = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", s)
    return s.strip()


def collapse_ws(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if isinstance(dt, datetime) else None


def clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def unique_preserve(items: Iterable[Any]) -> List[Any]:
    seen = set()
    out = []
    for item in items:
        key = json_safe(item)
        if isinstance(key, (dict, list)):
            key = json.dumps(key, sort_keys=True, ensure_ascii=False)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def safe_mean(xs: Iterable[float]) -> float:
    vals = [float(x) for x in xs]
    return sum(vals) / len(vals) if vals else 0.0


def safe_stdev(xs: Iterable[float]) -> float:
    vals = [float(x) for x in xs]
    if len(vals) < 2:
        return 0.0
    m = safe_mean(vals)
    return math.sqrt(sum((x - m) ** 2 for x in vals) / (len(vals) - 1))


def safe_median(xs: Iterable[float]) -> float:
    vals = sorted(float(x) for x in xs)
    if not vals:
        return 0.0
    mid = len(vals) // 2
    if len(vals) % 2:
        return vals[mid]
    return (vals[mid - 1] + vals[mid]) / 2.0


def safe_z(x: float, mean: float, std: float) -> float:
    if std <= 1e-9:
        return 0.0 if abs(float(x) - mean) <= 1e-9 else 5.0
    return (float(x) - mean) / std


def counter_probs(counter: Counter) -> Dict[Any, float]:
    total = sum(counter.values())
    if total <= 0:
        return {}
    return {k: v / total for k, v in counter.items()}


def tv_distance(p: Dict[Any, float], q: Dict[Any, float]) -> float:
    keys = set(p) | set(q)
    return 0.5 * sum(abs(p.get(k, 0.0) - q.get(k, 0.0)) for k in keys)


def mask_value(value: Any, keep_prefix: int = 3, keep_suffix: int = 2) -> str:
    s = normalize_text(value)
    if not s:
        return ""
    if len(s) <= keep_prefix + keep_suffix:
        return "*" * len(s)
    return s[:keep_prefix] + "*" * (len(s) - keep_prefix - keep_suffix) + s[-keep_suffix:]


def mask_entity(entity_id: Any, enabled: bool = True) -> str:
    if not enabled:
        return normalize_text(entity_id)
    return mask_value(entity_id, keep_prefix=4, keep_suffix=2)


def parse_time(value: Any) -> Optional[datetime]:
    if not value:
        return None
    s = normalize_text(value)
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d/%m/%Y",
        "%m/%d/%Y",
        "%Y-%m",
        "%Y",
    ):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            continue
    return None


def time_overlap(
    s1: Optional[datetime],
    e1: Optional[datetime],
    s2: Optional[datetime],
    e2: Optional[datetime],
) -> bool:
    if s1 is None and e1 is None:
        return True
    if s2 is None and e2 is None:
        return True
    if e1 and s2 and e1 < s2:
        return False
    if e2 and s1 and e2 < s1:
        return False
    return True


# --------------------------------------------------------------------
# Policy / authorization
# --------------------------------------------------------------------

def collect_user_intent_text(manifest: Dict[str, Any]) -> str:
    parts = [
        normalize_text(manifest.get("objective", "")),
        " ".join(normalize_text(q) for q in manifest.get("questions", []) or []),
    ]
    return " ".join(parts)


def policy_screen(manifest: Dict[str, Any]) -> List[str]:
    blob = collect_user_intent_text(manifest)
    blocked = []
    for pat, label in PROHIBITED_PATTERNS:
        if pat.search(blob):
            blocked.append(label)
    return list(dict.fromkeys(blocked))


def privacy_config(manifest: Dict[str, Any]) -> Dict[str, Any]:
    auth = manifest.get("authorization", {}) or {}
    pc = dict(auth.get("privacy", {}) or manifest.get("privacy", {}) or {})
    pc.setdefault("minimize_personal_data", True)
    pc.setdefault("hash_entities", False)
    pc.setdefault("mask_entity_display", True)
    return pc


def has_person_level_entities(manifest: Dict[str, Any]) -> bool:
    for ev in manifest.get("events", []) or []:
        entity = normalize_text(ev.get("entity_id") or ev.get("account_id") or "")
        etype = normalize_text(ev.get("entity_type") or "").upper()
        if PERSON_ENTITY_PATTERN.match(entity) or etype in {"PERSON_CANDIDATE", "LEGAL_PERSON", "EMPLOYEE"}:
            return True
    return False


def authorization_check(manifest: Dict[str, Any]) -> Tuple[bool, List[str]]:
    auth = manifest.get("authorization") or {}
    reasons: List[str] = []

    if not auth.get("approved"):
        reasons.append("AUTHORIZATION_MISSING_OR_NOT_APPROVED")

    scope = auth.get("scope", "provided_records_only")
    if scope not in ALLOWED_SCOPES:
        reasons.append("UNSUPPORTED_SCOPE")

    model_mode = auth.get("model_mode", "LOCAL_ONLY")
    if model_mode == "CLOUD" and not auth.get("cloud_approved"):
        reasons.append("CLOUD_PROCESSING_NOT_APPROVED")

    if model_mode not in {"LOCAL_ONLY", "HYBRID", "CLOUD"}:
        reasons.append("UNKNOWN_MODEL_MODE")

    if has_person_level_entities(manifest) and not auth.get("person_level_approved"):
        reasons.append("PERSON_LEVEL_ANALYSIS_NOT_APPROVED")

    return (len(reasons) == 0), reasons


# --------------------------------------------------------------------
# Timestamp parsing
# --------------------------------------------------------------------

def parse_tz_offset(value: Any) -> Optional[timezone]:
    if value is None:
        return None
    s = normalize_text(value)
    if not s:
        return None
    if s.upper() == "Z":
        return timezone.utc
    m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", s)
    if not m:
        return None
    sign = 1 if m.group(1) == "+" else -1
    hours = int(m.group(2))
    minutes = int(m.group(3))
    return timezone(sign * timedelta(hours=hours, minutes=minutes))


def localize_naive_datetime(
    dt: datetime,
    timezone_hint: Optional[str],
) -> Tuple[datetime, str, List[str]]:
    limitations: List[str] = []

    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc), "EXPLICIT", limitations

    hint = normalize_text(timezone_hint) if timezone_hint else None
    if not hint:
        return dt.replace(tzinfo=timezone.utc), "UNKNOWN", [
            "Timezone unknown; UTC assumed only for deterministic comparison. This is an assumption, not evidence."
        ]

    offset = parse_tz_offset(hint)
    if offset is not None:
        return dt.replace(tzinfo=offset).astimezone(timezone.utc), "EXPLICIT", limitations

    if HAS_ZONEINFO:
        try:
            tz = ZoneInfo(hint)
            aware = dt.replace(tzinfo=tz)
            limitations.append("Named timezone used. DST fold/gap ambiguity is only partially modeled in this starter.")
            return aware.astimezone(timezone.utc), "SOURCE_CONFIGURED", limitations
        except Exception as exc:
            limitations.append(f"ZoneInfo unavailable/error for '{hint}': {exc}")

    limitations.append(f"Timezone '{hint}' could not be resolved; UTC assumed for comparison only.")
    return dt.replace(tzinfo=timezone.utc), "UNKNOWN", limitations


def detect_precision_from_raw(raw: str) -> str:
    s = normalize_text(raw)
    if not s:
        return "UNKNOWN"

    m = re.search(r"[T ]\d{2}:\d{2}:\d{2}\.(\d+)", s)
    if m:
        frac_len = len(m.group(1))
        if frac_len >= 9:
            return "NANOSECOND"
        if frac_len >= 6:
            return "MICROSECOND"
        if frac_len >= 3:
            return "MILLISECOND"
        return "SECOND"

    if re.search(r"[T ]\d{2}:\d{2}:\d{2}", s):
        return "SECOND"
    if re.search(r"[T ]\d{2}:\d{2}(?!:\d)", s):
        return "MINUTE"
    if re.search(r"[T ]\d{2}(?![:\d])", s):
        return "HOUR"
    if re.search(r"\d{4}-\d{2}-\d{2}", s):
        return "DAY"
    if re.search(r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}", s):
        return "DAY"
    if re.search(r"\d{4}-\d{2}(?!-\d)", s):
        return "MONTH"
    if re.search(r"\b\d{4}\b(?![-/\d])", s):
        return "YEAR"
    return "UNKNOWN"


def precision_from_format(fmt: str) -> str:
    if "%f" in fmt:
        return "MICROSECOND"
    if "%S" in fmt:
        return "SECOND"
    if "%M" in fmt:
        return "MINUTE"
    if "%H" in fmt:
        return "HOUR"
    if "%d" in fmt or "%j" in fmt:
        return "DAY"
    if "%m" in fmt:
        return "MONTH"
    if "%Y" in fmt or "%y" in fmt:
        return "YEAR"
    return "UNKNOWN"


def date_format_ambiguity(raw: str, locale_hint: Optional[str]) -> bool:
    s = normalize_text(raw)
    m = re.fullmatch(r"(\d{1,2})[/-](\d{1,2})[/-](\d{2,4})(?:\s+.*)?", s)
    if not m:
        return False
    a = int(m.group(1))
    b = int(m.group(2))
    if a <= 12 and b <= 12 and a != b:
        return not bool(locale_hint)
    return False


def parse_datetime_string(
    raw: str,
    locale_hint: Optional[str] = None,
) -> Tuple[Optional[datetime], Optional[str], str, bool, List[str]]:
    s = normalize_text(raw)
    limitations: List[str] = []

    if not s:
        return None, None, "UNKNOWN", False, ["Empty timestamp."]

    iso_candidate = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso_candidate)
        precision = detect_precision_from_raw(s)
        tz_explicit = dt.tzinfo is not None
        if date_format_ambiguity(s, locale_hint):
            limitations.append("Numeric date format may be ambiguous (DD/MM vs MM/DD).")
        return dt, "ISO8601", precision, tz_explicit, limitations
    except Exception:
        pass

    dayfirst_locales = {"en-gb", "en-in", "dd/mm/yyyy", "dayfirst", "ddmm"}
    dayfirst = normalize_text(locale_hint or "").lower() in dayfirst_locales

    common_formats = [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H",
        "%Y-%m-%d %H",
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%d %B %Y",
        "%d %b %Y",
        "%B %d, %Y",
        "%b %d, %Y",
        "%B %d %Y",
        "%b %d %Y",
        "%Y-%m",
        "%Y",
    ]

    ambiguous_numeric = [
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%d/%m/%Y",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
        "%m/%d/%Y",
        "%d-%m-%Y %H:%M:%S",
        "%d-%m-%Y",
        "%m-%d-%Y %H:%M:%S",
        "%m-%d-%Y",
    ]

    if dayfirst:
        ordered = ambiguous_numeric[:3] + common_formats + ambiguous_numeric[3:]
    else:
        ordered = ambiguous_numeric[3:6] + common_formats + ambiguous_numeric[:3]

    for fmt in ordered:
        try:
            dt = datetime.strptime(s, fmt)
            precision = precision_from_format(fmt)
            tz_explicit = "%z" in fmt
            if date_format_ambiguity(s, locale_hint):
                limitations.append(
                    "Numeric date format may be ambiguous (DD/MM vs MM/DD). Locale hint was not sufficient to resolve confidently."
                )
            return dt, fmt, precision, tz_explicit, limitations
        except Exception:
            continue

    return None, None, "UNKNOWN", False, ["Unrecognized timestamp format."]


def detect_epoch_unit(value: float, hint: Optional[str] = None) -> str:
    if hint:
        h = normalize_text(hint).upper()
        if h in {"SECONDS", "SEC", "S"}:
            return "SECONDS"
        if h in {"MILLISECONDS", "MS"}:
            return "MILLISECONDS"
        if h in {"MICROSECONDS", "US", "MCS"}:
            return "MICROSECONDS"
        if h in {"NANOSECONDS", "NS"}:
            return "NANOSECONDS"

    av = abs(value)
    max_seconds = 4102444800.0
    if av <= max_seconds:
        return "SECONDS"
    if av <= max_seconds * 1e3:
        return "MILLISECONDS"
    if av <= max_seconds * 1e6:
        return "MICROSECONDS"
    if av <= max_seconds * 1e9:
        return "NANOSECONDS"
    return "UNKNOWN"


def parse_epoch_value(
    raw: Any,
    epoch_unit_hint: Optional[str] = None,
) -> Tuple[Optional[datetime], Optional[str], str, bool, List[str]]:
    limitations: List[str] = []
    try:
        value = float(raw)
    except Exception:
        return None, None, "UNKNOWN", False, ["Epoch value not numeric."]

    unit = detect_epoch_unit(value, epoch_unit_hint)
    if unit == "UNKNOWN":
        return None, None, "UNKNOWN", False, ["Epoch unit could not be determined."]

    if unit == "SECONDS":
        seconds = value
        precision = "SECOND" if value == int(value) else "MICROSECOND"
    elif unit == "MILLISECONDS":
        seconds = value / 1e3
        precision = "MILLISECOND"
    elif unit == "MICROSECONDS":
        seconds = value / 1e6
        precision = "MICROSECOND"
    else:
        seconds = value / 1e9
        precision = "NANOSECOND"

    try:
        dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    except Exception as exc:
        return None, None, "UNKNOWN", False, [f"Epoch conversion failed: {exc}"]

    limitations.append(f"Epoch unit inferred/declared as {unit}. Unit detection can be ambiguous without field documentation.")
    return dt, f"EPOCH_{unit}", precision, True, limitations


PRECISION_DELTA_SECONDS = {
    "NANOSECOND": 1e-9,
    "MICROSECOND": 1e-6,
    "MILLISECOND": 1e-3,
    "SECOND": 1.0,
    "MINUTE": 60.0,
    "HOUR": 3600.0,
    "DAY": 86400.0,
    "WEEK": 604800.0,
    "MONTH": 2592000.0,
    "YEAR": 31536000.0,
}


def precision_delta_seconds(precision: str) -> Optional[float]:
    return PRECISION_DELTA_SECONDS.get(precision)


def parse_timestamp_value(
    raw: Any,
    timezone_hint: Optional[str] = None,
    locale_hint: Optional[str] = None,
    precision_hint: Optional[str] = None,
    uncertainty_seconds: Optional[float] = None,
    timestamp_type: Optional[str] = None,
    epoch_unit_hint: Optional[str] = None,
) -> Dict[str, Any]:
    limitations: List[str] = []
    raw_text = normalize_text(raw) if raw is not None else ""

    base = {
        "raw_timestamp": raw_text,
        "normalized_start_utc": None,
        "normalized_end_utc": None,
        "representative_utc": None,
        "precision": normalize_text(precision_hint).upper() or "UNKNOWN",
        "timezone_state": "UNKNOWN",
        "timezone_hint": timezone_hint,
        "format_detected": None,
        "uncertainty_seconds": uncertainty_seconds,
        "timestamp_type": normalize_text(timestamp_type).upper() or "UNKNOWN",
        "limitations": limitations,
    }

    dt: Optional[datetime] = None
    fmt: Optional[str] = None
    precision = normalize_text(precision_hint).upper() or None
    tz_explicit = False

    if isinstance(raw, datetime):
        dt = raw
        precision = precision or detect_precision_from_raw(raw.isoformat())
        tz_explicit = raw.tzinfo is not None
        fmt = "PYTHON_DATETIME"
    elif raw is not None and re.fullmatch(r"-?\d+(?:\.\d+)?", raw_text):
        dt, fmt, parsed_precision, tz_explicit, epoch_lim = parse_epoch_value(raw, epoch_unit_hint)
        precision = precision or parsed_precision
        limitations.extend(epoch_lim)
    else:
        dt, fmt, parsed_precision, tz_explicit, parse_lim = parse_datetime_string(raw_text, locale_hint)
        precision = precision or parsed_precision
        limitations.extend(parse_lim)

    if dt is None:
        base["limitations"].append("Timestamp could not be parsed.")
        base["precision"] = precision or "UNKNOWN"
        return base

    if tz_explicit:
        normalized = dt.astimezone(timezone.utc)
        tz_state = "EXPLICIT"
    else:
        normalized, tz_state, tz_lim = localize_naive_datetime(dt, timezone_hint)
        limitations.extend(tz_lim)

    precision = precision or detect_precision_from_raw(raw_text) or "UNKNOWN"
    base["format_detected"] = fmt
    base["precision"] = precision
    base["timezone_state"] = tz_state

    delta = precision_delta_seconds(precision)
    if delta is not None:
        start = normalized
        end = normalized + timedelta(seconds=delta)
        rep = start + timedelta(seconds=delta / 2.0)
    else:
        start = end = rep = normalized

    if base["uncertainty_seconds"] is None:
        base["uncertainty_seconds"] = (delta / 2.0) if delta is not None else None

    base["normalized_start_utc"] = start
    base["normalized_end_utc"] = end
    base["representative_utc"] = rep

    return base


# --------------------------------------------------------------------
# Sources / coverage / context
# --------------------------------------------------------------------

def collect_referenced_source_ids(manifest: Dict[str, Any]) -> Set[str]:
    ids = set()
    for s in manifest.get("sources", []) or []:
        sid = normalize_text(s.get("source_id"))
        if sid:
            ids.add(sid)
    for ev in manifest.get("events", []) or []:
        sid = normalize_text(ev.get("source_id"))
        if sid:
            ids.add(sid)
    for cov in manifest.get("source_coverage", []) or []:
        sid = normalize_text(cov.get("source_id"))
        if sid:
            ids.add(sid)
    return ids


def ingest_sources(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    sources: Dict[str, Dict[str, Any]] = {}

    for s in manifest.get("sources", []) or []:
        sid = normalize_text(s.get("source_id"))
        if not sid:
            continue
        stype = normalize_text(s.get("source_type", "unknown")).lower()
        reliability = s.get("reliability")
        if reliability is None:
            reliability = SOURCE_RELIABILITY.get(stype, SOURCE_RELIABILITY["unknown"])
        sources[sid] = {
            "source_id": sid,
            "source_type": stype,
            "upstream_source_id": normalize_text(s.get("upstream_source_id")) or None,
            "reliability": clamp(float(reliability)),
            "observed_at": normalize_text(s.get("observed_at")) or None,
            "url": s.get("url"),
            "limitations": list(s.get("limitations", []) or []),
        }

    for sid in collect_referenced_source_ids(manifest):
        if sid not in sources:
            sources[sid] = {
                "source_id": sid,
                "source_type": "unknown",
                "upstream_source_id": None,
                "reliability": SOURCE_RELIABILITY["unknown"],
                "observed_at": None,
                "url": None,
                "limitations": ["Source referenced but not defined in manifest."],
            }

    return sources


def resolve_source_root(sid: str, sources: Dict[str, Dict[str, Any]], memo: Dict[str, str], visiting: Set[str]) -> str:
    if sid in memo:
        return memo[sid]
    if sid in visiting:
        return sid
    visiting.add(sid)
    src = sources.get(sid)
    if not src or not src.get("upstream_source_id"):
        memo[sid] = sid
        visiting.discard(sid)
        return sid
    root = resolve_source_root(src["upstream_source_id"], sources, memo, visiting)
    memo[sid] = root
    visiting.discard(sid)
    return root


def build_source_roots(sources: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    memo: Dict[str, str] = {}
    for sid in sources:
        resolve_source_root(sid, sources, memo, set())
    return memo


def source_family_ids(source_ids: List[str], source_roots: Dict[str, str]) -> List[str]:
    roots = []
    for sid in source_ids:
        roots.append(source_roots.get(sid, sid))
    return list(dict.fromkeys(roots))


def independence_state(families: List[str], sources: Dict[str, Dict[str, Any]], source_ids: List[str]) -> str:
    if not source_ids:
        return "UNKNOWN"
    if len(families) <= 1:
        return "DEPENDENT"
    types = {sources.get(sid, {}).get("source_type", "unknown") for sid in source_ids}
    rels = [sources.get(sid, {}).get("reliability", 0.3) for sid in source_ids]
    if len(types) == 1 and max(rels) < 0.70:
        return "PARTIALLY_DEPENDENT"
    if max(rels) >= 0.70:
        return "INDEPENDENT"
    return "PARTIALLY_DEPENDENT"


def ingest_source_coverage(manifest: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    coverage: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for idx, c in enumerate(manifest.get("source_coverage", []) or []):
        sid = normalize_text(c.get("source_id"))
        if not sid:
            continue
        coverage[sid].append({
            "coverage_id": normalize_text(c.get("coverage_id") or f"COV-{idx}"),
            "source_id": sid,
            "coverage_start_utc": parse_time(c.get("coverage_start")),
            "coverage_end_utc": parse_time(c.get("coverage_end")),
            "operational": bool(c.get("operational", True)),
            "retention_gap": bool(c.get("retention_gap", False)),
            "limitations": list(c.get("limitations", []) or []),
        })
    return dict(coverage)


def check_coverage(
    rep: Optional[datetime],
    source_id: Optional[str],
    coverage_by_source: Dict[str, List[Dict[str, Any]]],
) -> str:
    if not rep or not source_id:
        return "UNKNOWN"
    covs = coverage_by_source.get(source_id, [])
    if not covs:
        return "UNKNOWN"
    for c in covs:
        if not c.get("operational", True):
            return "SOURCE_OUTAGE"
        if c.get("retention_gap"):
            return "RETENTION_GAP"
        start = c.get("coverage_start_utc")
        end = c.get("coverage_end_utc")
        if start and end and start <= rep <= end:
            return "OK"
    return "OUTSIDE_COVERAGE"


def ingest_contexts(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    contexts = []
    for idx, c in enumerate(manifest.get("context", []) or []):
        ctx_id = normalize_text(c.get("context_id") or f"CTX-{idx}")
        contexts.append({
            "context_id": ctx_id,
            "context_type": normalize_text(c.get("context_type", "unknown")).lower(),
            "entity_ids": [normalize_text(x) for x in c.get("entity_ids", []) or [] if normalize_text(x)],
            "valid_from": parse_time(c.get("valid_from")),
            "valid_to": parse_time(c.get("valid_to")),
            "description": normalize_text(c.get("description")),
            "source_id": normalize_text(c.get("source_id")) or None,
            "limitations": list(c.get("limitations", []) or []),
        })
    return contexts


# --------------------------------------------------------------------
# Attribute filtering / volume extraction
# --------------------------------------------------------------------

def filter_sensitive_attributes(attrs_raw: Dict[str, Any], privacy_cfg: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    clean: Dict[str, Any] = {}
    flags: List[str] = []

    for key, value in (attrs_raw or {}).items():
        lk = normalize_text(key).lower()
        if lk in SENSITIVE_KEYS:
            flags.append(f"SENSITIVE_ATTRIBUTE_REMOVED:{lk}")
            continue
        if lk in CONTENT_KEYS:
            flags.append("COMMUNICATION_CONTENT_NOT_USED")
            continue
        if lk in EXACT_LOCATION_KEYS:
            flags.append("EXACT_LOCATION_NOT_USED")
            continue

        if isinstance(value, list):
            clean[lk] = [normalize_text(x) for x in value if normalize_text(x)]
        else:
            nv = normalize_text(value)
            if nv:
                clean[lk] = nv

    return clean, flags


def get_volume(attrs: Dict[str, Any]) -> Optional[float]:
    for k in VOLUME_KEYS:
        v = attrs.get(k)
        if v is None:
            continue
        s = normalize_text(v).replace(",", "")
        m = re.search(r"-?\d+(?:\.\d+)?", s)
        if m:
            try:
                return float(m.group())
            except Exception:
                continue
    return None


# --------------------------------------------------------------------
# Event ingestion / aggregation
# --------------------------------------------------------------------

def choose_primary_timestamp_record(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    def sort_key(r: Dict[str, Any]) -> Tuple[int, datetime, str]:
        ts = r.get("timestamp", {})
        tt = TIMESTAMP_TYPE_PRIORITY.get(ts.get("timestamp_type", "UNKNOWN"), 99)
        rep = ts.get("representative_utc") or FAR_FUTURE
        return (tt, rep, r.get("record_id", ""))

    return sorted(records, key=sort_key)[0]


def ingest_events(
    manifest: Dict[str, Any],
    sources: Dict[str, Dict[str, Any]],
    coverage_by_source: Dict[str, List[Dict[str, Any]]],
    privacy_cfg: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    records: List[Dict[str, Any]] = []
    privacy_flags: List[Dict[str, Any]] = []

    for idx, ev in enumerate(manifest.get("events", []) or []):
        entity_raw = normalize_text(ev.get("entity_id") or ev.get("account_id") or "UNKNOWN_ENTITY")
        if privacy_cfg.get("hash_entities"):
            entity_id = hashlib.sha256(entity_raw.encode("utf-8")).hexdigest()[:16]
        else:
            entity_id = entity_raw

        attrs, flags = filter_sensitive_attributes(ev.get("attributes", {}) or {}, privacy_cfg)
        for f in flags:
            privacy_flags.append({"event_index": idx, "entity_id": entity_id, "type": f})

        ts = parse_timestamp_value(
            ev.get("timestamp") if "timestamp" in ev else ev.get("raw_timestamp"),
            timezone_hint=ev.get("timezone") or ev.get("timezone_hint"),
            locale_hint=ev.get("locale") or ev.get("locale_hint"),
            precision_hint=ev.get("precision"),
            uncertainty_seconds=float(ev["uncertainty_seconds"]) if ev.get("uncertainty_seconds") is not None else None,
            timestamp_type=ev.get("timestamp_type") or "EVENT_TIME",
            epoch_unit_hint=ev.get("epoch_unit"),
        )

        source_id = normalize_text(ev.get("source_id")) or None
        src = sources.get(source_id, {}) if source_id else {}
        ts["source_reliability"] = float(src.get("reliability", SOURCE_RELIABILITY["unknown"]))
        ts["source_type"] = src.get("source_type", "unknown")
        ts["source_coverage_state"] = check_coverage(ts.get("representative_utc"), source_id, coverage_by_source)

        record = {
            "record_id": stable_id("EVR", idx, entity_id, ev.get("event_id"), ts.get("raw_timestamp")),
            "event_id": normalize_text(ev.get("event_id")) or stable_id("EVT", idx, entity_id, ts.get("raw_timestamp")),
            "entity_id": entity_id,
            "entity_type": normalize_text(ev.get("entity_type", "ACCOUNT")).upper(),
            "event_type": normalize_text(ev.get("event_type", "UNKNOWN")).upper().replace(" ", "_").replace("-", "_"),
            "action": normalize_text(ev.get("action")) or None,
            "object": normalize_text(ev.get("object")) or None,
            "target_entity": normalize_text(ev.get("target_entity") or ev.get("target")) or None,
            "session_id": normalize_text(ev.get("session_id")) or None,
            "device_context": normalize_text(ev.get("device_context") or ev.get("device_id")) or None,
            "location_context": normalize_text(ev.get("location_context") or ev.get("location")) or None,
            "attributes": attrs,
            "timestamp": ts,
            "source_id": source_id,
            "evidence_ids": [normalize_text(x) for x in ev.get("evidence_ids", []) or [] if normalize_text(x)],
            "privacy_flags": flags,
            "limitations": list(ev.get("limitations", []) or []),
        }
        records.append(record)

    by_event: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        by_event[r["event_id"]].append(r)

    events: List[Dict[str, Any]] = []
    for eid, rs in by_event.items():
        primary_record = choose_primary_timestamp_record(rs)
        primary_ts = primary_record["timestamp"]

        event_types = Counter(r["event_type"] for r in rs)
        source_ids = sorted({r["source_id"] for r in rs if r.get("source_id")})
        evidence_ids = sorted({x for r in rs for x in r.get("evidence_ids", [])})
        limitations = sorted({x for r in rs for x in r.get("limitations", [])})

        event = {
            "event_id": eid,
            "entity_id": rs[0]["entity_id"],
            "entity_type": rs[0]["entity_type"],
            "event_type": event_types.most_common(1)[0][0] if event_types else "UNKNOWN",
            "action": primary_record.get("action"),
            "object": primary_record.get("object"),
            "target_entity": next((r.get("target_entity") for r in rs if r.get("target_entity")), None),
            "session_id": primary_record.get("session_id"),
            "device_context": primary_record.get("device_context"),
            "location_context": primary_record.get("location_context"),
            "attributes": primary_record.get("attributes", {}),
            "source_ids": source_ids,
            "evidence_ids": evidence_ids,
            "timestamps": rs,
            "start_utc": primary_ts.get("normalized_start_utc"),
            "end_utc": primary_ts.get("normalized_end_utc"),
            "representative_utc": primary_ts.get("representative_utc"),
            "time_precision": primary_ts.get("precision", "UNKNOWN"),
            "time_uncertainty_seconds": primary_ts.get("uncertainty_seconds"),
            "timestamp_type": primary_ts.get("timestamp_type", "UNKNOWN"),
            "timezone_state": primary_ts.get("timezone_state", "UNKNOWN"),
            "source_coverage_state": primary_ts.get("source_coverage_state", "UNKNOWN"),
            "source_reliability": primary_ts.get("source_reliability", SOURCE_RELIABILITY["unknown"]),
            "limitations": limitations + [
                "Account/device/session activity is not automatically attributed to a real person.",
                "Observed behaviour is not intent, motive, personality, or guilt.",
            ],
        }
        events.append(event)

    events.sort(key=lambda e: (e.get("representative_utc") or FAR_FUTURE, e["event_id"]))
    return events, privacy_flags


# --------------------------------------------------------------------
# Sessionization
# --------------------------------------------------------------------

def make_session(entity_id: str, session_id: str, events: List[Dict[str, Any]], method: str) -> Dict[str, Any]:
    starts = [e["start_utc"] for e in events if e.get("start_utc")]
    ends = [e.get("end_utc") or e.get("start_utc") for e in events if e.get("start_utc")]
    return {
        "session_id": session_id,
        "entity_id": entity_id,
        "start_utc": min(starts) if starts else None,
        "end_utc": max(ends) if ends else None,
        "event_ids": [e["event_id"] for e in events],
        "event_types": sorted({e["event_type"] for e in events}),
        "event_count": len(events),
        "source_ids": sorted({sid for e in events for sid in e.get("source_ids", [])}),
        "method": method,
        "limitations": [
            "Session does not prove a single human operator.",
            "Sessions may be shared, automated, compromised, or service-driven.",
        ],
    }


def sessionize(events: List[Dict[str, Any]], gap_minutes: float = 30.0) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    explicit: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    implicit: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for e in events:
        if not e.get("start_utc"):
            continue
        if e.get("session_id"):
            explicit[(e["entity_id"], e["session_id"])].append(e)
        else:
            implicit[e["entity_id"]].append(e)

    sessions: List[Dict[str, Any]] = []

    for (entity_id, sid), evs in explicit.items():
        sessions.append(make_session(entity_id, sid, sorted(evs, key=lambda x: x["start_utc"]), "EXPLICIT_SESSION_ID"))

    for entity_id, evs in implicit.items():
        evs = sorted(evs, key=lambda x: x["start_utc"])
        current: List[Dict[str, Any]] = []
        for e in evs:
            if not current:
                current = [e]
                continue
            prev_end = current[-1].get("end_utc") or current[-1].get("start_utc")
            gap = (e["start_utc"] - prev_end).total_seconds() / 60.0
            if gap <= gap_minutes:
                current.append(e)
            else:
                sid = stable_id("SESS", entity_id, current[0]["event_id"], current[-1]["event_id"])
                sessions.append(make_session(entity_id, sid, current, f"GAP_RULE_{int(gap_minutes)}M"))
                current = [e]
        if current:
            sid = stable_id("SESS", entity_id, current[0]["event_id"], current[-1]["event_id"])
            sessions.append(make_session(entity_id, sid, current, f"GAP_RULE_{int(gap_minutes)}M"))

    rule = {
        "explicit_session_id_used_when_available": True,
        "implicit_gap_minutes": gap_minutes,
        "limitations": [
            "Sessionization rule is exposed for replay.",
            "Session boundaries are analytical, not proof of human continuity.",
        ],
    }
    return sessions, rule


# --------------------------------------------------------------------
# Activity statistics / baselines
# --------------------------------------------------------------------

def compute_activity_stats(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    evs = [e for e in events if e.get("start_utc")]
    n = len(evs)

    type_counts = Counter(e["event_type"] for e in evs)
    hour_counts = Counter(e["start_utc"].hour for e in evs)
    dow_counts = Counter(e["start_utc"].weekday() for e in evs)
    daily_counts = Counter(e["start_utc"].date().isoformat() for e in evs)

    sorted_evs = sorted(evs, key=lambda e: e["start_utc"])
    intervals = [
        (b["start_utc"] - a["start_utc"]).total_seconds()
        for a, b in zip(sorted_evs, sorted_evs[1:])
        if a.get("start_utc") and b.get("start_utc")
    ]
    intervals = [x for x in intervals if x > 0]

    volume_by_type_raw: Dict[str, List[float]] = defaultdict(list)
    for e in evs:
        vol = get_volume(e.get("attributes", {}) or {})
        if vol is not None:
            volume_by_type_raw[e["event_type"]].append(vol)

    volume_by_type = {}
    for k, vals in volume_by_type_raw.items():
        volume_by_type[k] = {
            "count": len(vals),
            "mean": safe_mean(vals),
            "std": safe_stdev(vals),
            "median": safe_median(vals),
        }

    target_counts = Counter(e["target_entity"] for e in evs if e.get("target_entity"))
    bigram_counts = Counter(
        f"{a['event_type']}|{b['event_type']}"
        for a, b in zip(sorted_evs, sorted_evs[1:])
    )

    span_days = 0
    if evs:
        span_days = (max(e["start_utc"] for e in evs) - min(e["start_utc"] for e in evs)).days + 1

    return {
        "event_count": n,
        "span_days": span_days,
        "type_counts": dict(type_counts),
        "type_probs": counter_probs(type_counts),
        "hour_counts": {str(k): v for k, v in hour_counts.items()},
        "hour_probs": {str(k): v for k, v in counter_probs(hour_counts).items()},
        "dow_counts": {str(k): v for k, v in dow_counts.items()},
        "dow_probs": {str(k): v for k, v in counter_probs(dow_counts).items()},
        "daily_counts": dict(daily_counts),
        "daily_mean": safe_mean(daily_counts.values()),
        "daily_std": safe_stdev(daily_counts.values()),
        "day_count": len(daily_counts),
        "interval_count": len(intervals),
        "interval_mean": safe_mean(intervals),
        "interval_median": safe_median(intervals),
        "interval_std": safe_stdev(intervals),
        "volume_by_type": volume_by_type,
        "target_counts": dict(target_counts),
        "target_sample": sum(target_counts.values()),
        "bigram_counts": dict(bigram_counts),
        "bigram_sample": sum(bigram_counts.values()),
        "bigram_probs": counter_probs(bigram_counts),
    }


def downgrade_confidence(conf: str, steps: int = 1) -> str:
    order = ["INSUFFICIENT", "LOW", "MODERATE", "HIGH"]
    if conf not in order:
        conf = "LOW"
    idx = max(0, order.index(conf) - steps)
    return order[idx]


def assess_baseline_quality(
    stats: Dict[str, Any],
    train_events: List[Dict[str, Any]],
    contexts: List[Dict[str, Any]],
    entity_id: str,
    training_start: Optional[datetime],
    training_end: Optional[datetime],
) -> Dict[str, Any]:
    sample = int(stats.get("event_count", 0))
    if sample >= 100:
        conf = "HIGH"
    elif sample >= 30:
        conf = "MODERATE"
    elif sample >= 10:
        conf = "LOW"
    else:
        conf = "INSUFFICIENT"

    contamination = []
    for ctx in contexts:
        if ctx.get("entity_ids") and entity_id not in ctx["entity_ids"]:
            continue
        if time_overlap(ctx.get("valid_from"), ctx.get("valid_to"), training_start, training_end):
            if ctx.get("context_type") in CONTAMINATING_CONTEXT_TYPES:
                contamination.append(ctx["context_type"])

    if contamination:
        conf = downgrade_confidence(conf, 1)

    coverage_states = Counter(e.get("source_coverage_state", "UNKNOWN") for e in train_events)
    problematic = sum(v for k, v in coverage_states.items() if k not in {"OK", "UNKNOWN"})
    completeness = "PARTIAL" if problematic else "UNKNOWN"
    if completeness == "PARTIAL":
        conf = downgrade_confidence(conf, 1)

    span = int(stats.get("span_days", 0))
    dow_unique = len(stats.get("dow_counts", {}))
    if span >= 28 and dow_unique >= 5:
        seasonality = "ADEQUATE"
    elif span >= 7 and dow_unique >= 3:
        seasonality = "PARTIAL"
    else:
        seasonality = "LOW"

    return {
        "confidence": conf,
        "sample_size": sample,
        "span_days": span,
        "seasonality": seasonality,
        "data_completeness": completeness,
        "contamination_contexts": list(dict.fromkeys(contamination)),
        "coverage_states": dict(coverage_states),
        "limitations": [
            "Weak baseline produces weak anomaly conclusions.",
            "Baseline may be contaminated by incidents, migrations, holidays, or special projects.",
        ],
    }


def build_baselines(
    manifest: Dict[str, Any],
    events: List[Dict[str, Any]],
    contexts: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    baselines: List[Dict[str, Any]] = []
    by_entity: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in events:
        if e.get("start_utc"):
            by_entity[e["entity_id"]].append(e)

    explicit_baselines = manifest.get("baselines", []) or []

    if explicit_baselines:
        for cfg in explicit_baselines:
            entity_id = normalize_text(cfg.get("entity_id"))
            if not entity_id:
                continue
            btype = normalize_text(cfg.get("baseline_type", "SELF")).upper()
            tstart = parse_time(cfg.get("training_start"))
            tend = parse_time(cfg.get("training_end"))
            exclude_ids = {normalize_text(x) for x in cfg.get("exclude_event_ids", []) or []}

            train = [
                e for e in by_entity.get(entity_id, [])
                if e["event_id"] not in exclude_ids
                and (not tstart or e["start_utc"] >= tstart)
                and (not tend or e["start_utc"] <= tend)
            ]
            stats = compute_activity_stats(train)
            quality = assess_baseline_quality(stats, train, contexts, entity_id, tstart, tend)
            baselines.append({
                "baseline_id": normalize_text(cfg.get("baseline_id")) or stable_id("BASE", entity_id, btype, iso(tstart), iso(tend)),
                "baseline_type": btype,
                "entity_id": entity_id,
                "peer_group_id": normalize_text(cfg.get("peer_group_id")) or None,
                "training_start": tstart,
                "training_end": tend,
                "evaluation_start": parse_time(cfg.get("evaluation_start")),
                "evaluation_end": parse_time(cfg.get("evaluation_end")),
                "training_event_ids": [e["event_id"] for e in train],
                "stats": stats,
                "quality": quality,
                "limitations": list(cfg.get("limitations", []) or []) + [
                    "Baseline is a statistical reference, not truth.",
                ],
            })
    else:
        for entity_id, evs in by_entity.items():
            evs = sorted(evs, key=lambda e: e["start_utc"])
            if len(evs) >= 10:
                split = max(1, int(len(evs) * 0.7))
                train = evs[:split]
                eval_ids = [e["event_id"] for e in evs[split:]]
            else:
                train = evs
                eval_ids = []

            tstart = train[0]["start_utc"] if train else None
            tend = train[-1]["start_utc"] if train else None
            stats = compute_activity_stats(train)
            quality = assess_baseline_quality(stats, train, contexts, entity_id, tstart, tend)
            baselines.append({
                "baseline_id": stable_id("BASE", entity_id, "SELF_AUTO"),
                "baseline_type": "SELF",
                "entity_id": entity_id,
                "peer_group_id": None,
                "training_start": tstart,
                "training_end": tend,
                "evaluation_start": tend,
                "evaluation_end": None,
                "training_event_ids": [e["event_id"] for e in train],
                "evaluation_event_ids": eval_ids,
                "stats": stats,
                "quality": quality,
                "limitations": [
                    "Auto baseline splits available chronology into training/evaluation; weak if sample is small.",
                ],
            })

    for group in manifest.get("peer_groups", []) or []:
        group_id = normalize_text(group.get("peer_group_id") or stable_id("PEER", *(group.get("entities", []) or [])))
        entities = [normalize_text(x) for x in group.get("entities", []) or [] if normalize_text(x)]
        tstart = parse_time(group.get("training_start"))
        tend = parse_time(group.get("training_end"))

        for target in entities:
            peer_events = [
                e for e in events
                if e.get("start_utc")
                and e["entity_id"] in entities
                and e["entity_id"] != target
                and (not tstart or e["start_utc"] >= tstart)
                and (not tend or e["start_utc"] <= tend)
            ]
            stats = compute_activity_stats(peer_events)
            quality = assess_baseline_quality(stats, peer_events, contexts, target, tstart, tend)
            baselines.append({
                "baseline_id": stable_id("BASE", target, "PEER", group_id),
                "baseline_type": "PEER",
                "entity_id": target,
                "peer_group_id": group_id,
                "training_start": tstart,
                "training_end": tend,
                "evaluation_start": tstart,
                "evaluation_end": tend,
                "training_event_ids": [],
                "stats": stats,
                "quality": quality,
                "limitations": [
                    "Peer baseline is only meaningful if cohort is genuinely comparable.",
                ],
            })

    return baselines


def get_evaluation_events(baseline: Dict[str, Any], events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    entity_id = baseline["entity_id"]
    train_ids = set(baseline.get("training_event_ids", []) or [])
    eval_ids = baseline.get("evaluation_event_ids")
    estart = baseline.get("evaluation_start")
    eend = baseline.get("evaluation_end")

    out = []
    for e in events:
        if e["entity_id"] != entity_id or not e.get("start_utc"):
            continue
        if e["event_id"] in train_ids:
            continue
        if eval_ids is not None and e["event_id"] not in eval_ids:
            continue
        if estart and e["start_utc"] < estart:
            continue
        if eend and e["start_utc"] > eend:
            continue
        out.append(e)
    return sorted(out, key=lambda x: x["start_utc"])


# --------------------------------------------------------------------
# Anomaly detection
# --------------------------------------------------------------------

def make_anomaly(
    entity_id: str,
    baseline_id: str,
    anomaly_type: str,
    severity: str,
    score: float,
    method: str,
    event_ids: List[str],
    details: Dict[str, Any],
    baseline_quality: Dict[str, Any],
) -> Dict[str, Any]:
    conf_map = {
        "HIGH": "MODERATE",
        "MODERATE": "LOW",
        "LOW": "LOW",
        "INSUFFICIENT": "VERY_LOW",
    }
    confidence = conf_map.get(baseline_quality.get("confidence", "LOW"), "LOW")

    return {
        "anomaly_id": stable_id("ANOM", entity_id, baseline_id, anomaly_type, *event_ids),
        "entity_id": entity_id,
        "baseline_id": baseline_id,
        "anomaly_type": anomaly_type,
        "severity": severity,
        "statistical_score": round(float(score), 4),
        "method": method,
        "event_ids": event_ids,
        "details": details,
        "confidence": confidence,
        "status": "CANDIDATE",
        "benign_explanations": [],
        "source_independence_state": "UNKNOWN",
        "raw_source_count": 0,
        "independent_source_family_count": 0,
        "limitations": [
            "Anomaly means deviation from a baseline, not malice, intent, or guilt.",
            "Statistical rarity is not evidence of criminality or policy violation.",
        ],
    }


def detect_anomalies(events: List[Dict[str, Any]], baselines: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []

    for b in baselines:
        stats = b.get("stats", {})
        quality = b.get("quality", {})
        evals = get_evaluation_events(b, events)
        if not evals:
            continue

        min_sample = 30 if b.get("baseline_type") == "SELF" else 20

        # Temporal anomaly: rare hour-of-day
        if int(stats.get("event_count", 0)) >= min_sample:
            hour_probs = {int(k): v for k, v in stats.get("hour_probs", {}).items()}
            seen_hours: Set[Tuple[str, int]] = set()
            for e in evals:
                h = e["start_utc"].hour
                p = hour_probs.get(h, 0.0)
                if p < 0.02 and (e["entity_id"], h) not in seen_hours:
                    seen_hours.add((e["entity_id"], h))
                    severity = "MODERATE" if p == 0 else "LOW"
                    anomalies.append(make_anomaly(
                        e["entity_id"],
                        b["baseline_id"],
                        "TEMPORAL_ANOMALY",
                        severity,
                        1.0 - p,
                        "baseline_hour_probability",
                        [e["event_id"]],
                        {"hour_utc": h, "baseline_hour_probability": round(p, 6)},
                        quality,
                    ))

        # Frequency anomaly: daily count z-score
        if int(stats.get("day_count", 0)) >= 7:
            eval_daily: Dict[str, List[str]] = defaultdict(list)
            for e in evals:
                eval_daily[e["start_utc"].date().isoformat()].append(e["event_id"])
            for day, eids in eval_daily.items():
                count = len(eids)
                z = safe_z(count, float(stats.get("daily_mean", 0.0)), float(stats.get("daily_std", 0.0)))
                if z >= 3:
                    severity = "HIGH" if z >= 5 else "MODERATE"
                    anomalies.append(make_anomaly(
                        evals[0]["entity_id"],
                        b["baseline_id"],
                        "FREQUENCY_ANOMALY",
                        severity,
                        z,
                        "daily_count_z_score",
                        eids,
                        {"date": day, "count": count, "baseline_mean": stats.get("daily_mean"), "baseline_std": stats.get("daily_std")},
                        quality,
                    ))

        # Volume anomaly
        for e in evals:
            vol = get_volume(e.get("attributes", {}) or {})
            vb = stats.get("volume_by_type", {}).get(e["event_type"])
            if vol is not None and vb and int(vb.get("count", 0)) >= 10:
                z = safe_z(vol, float(vb.get("mean", 0.0)), float(vb.get("std", 0.0)))
                if z >= 3:
                    severity = "HIGH" if z >= 5 else "MODERATE"
                    anomalies.append(make_anomaly(
                        e["entity_id"],
                        b["baseline_id"],
                        "VOLUME_ANOMALY",
                        severity,
                        z,
                        "volume_z_score_by_event_type",
                        [e["event_id"]],
                        {"event_type": e["event_type"], "volume": vol, "baseline_mean": vb.get("mean"), "baseline_std": vb.get("std")},
                        quality,
                    ))

        # Sequence anomaly: novel bigram
        if int(stats.get("bigram_sample", 0)) >= 50:
            sorted_evals = sorted(evals, key=lambda x: x["start_utc"])
            seen_bigrams: Set[str] = set()
            for a, b2 in zip(sorted_evals, sorted_evals[1:]):
                key = f"{a['event_type']}|{b2['event_type']}"
                p = float(stats.get("bigram_probs", {}).get(key, 0.0))
                if p == 0.0 and key not in seen_bigrams:
                    seen_bigrams.add(key)
                    anomalies.append(make_anomaly(
                        a["entity_id"],
                        b["baseline_id"],
                        "SEQUENCE_ANOMALY",
                        "MODERATE",
                        1.0,
                        "baseline_novel_bigram",
                        [a["event_id"], b2["event_id"]],
                        {"bigram": key, "baseline_bigram_probability": 0.0},
                        quality,
                    ))

        # Counterparty anomaly
        if int(stats.get("target_sample", 0)) >= 10:
            seen_targets: Set[Tuple[str, str]] = set()
            for e in evals:
                t = e.get("target_entity")
                if t and t not in stats.get("target_counts", {}) and (e["entity_id"], t) not in seen_targets:
                    seen_targets.add((e["entity_id"], t))
                    anomalies.append(make_anomaly(
                        e["entity_id"],
                        b["baseline_id"],
                        "COUNTERPARTY_ANOMALY",
                        "LOW",
                        1.0,
                        "baseline_new_target_entity",
                        [e["event_id"]],
                        {"target_entity": t},
                        quality,
                    ))

    return unique_preserve(anomalies)[:500]


# --------------------------------------------------------------------
# Patterns: periodicity, routine, burst, change point, drift
# --------------------------------------------------------------------

def detect_periodicity(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by: Dict[Tuple[str, str], List[datetime]] = defaultdict(list)
    for e in events:
        if e.get("start_utc"):
            by[(e["entity_id"], e["event_type"])].append(e["start_utc"])

    out = []
    for (entity_id, event_type), times in by.items():
        times = sorted(times)
        if len(times) < 5:
            continue
        intervals = [(b - a).total_seconds() for a, b in zip(times, times[1:]) if (b - a).total_seconds() > 0]
        if len(intervals) < 4:
            continue
        mean = safe_mean(intervals)
        std = safe_stdev(intervals)
        if mean <= 0:
            continue
        cv = std / mean
        if cv < 0.25:
            out.append({
                "periodicity_id": stable_id("PER", entity_id, event_type),
                "entity_id": entity_id,
                "event_type": event_type,
                "interval_count": len(intervals),
                "median_interval_seconds": safe_median(intervals),
                "coefficient_of_variation": round(cv, 4),
                "confidence": "HIGH" if len(intervals) >= 20 else "MODERATE",
                "interpretation": "Regular interval may indicate scheduled or automated process.",
                "limitations": [
                    "Periodicity does not prove automation, benign intent, or malicious intent.",
                ],
            })
    return out


def detect_routines(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_entity: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in events:
        if e.get("start_utc"):
            by_entity[e["entity_id"]].append(e)

    out = []
    for entity_id, evs in by_entity.items():
        stats = compute_activity_stats(evs)
        n = int(stats.get("event_count", 0))
        if n < 10:
            continue
        hour_counts = {int(k): v for k, v in stats.get("hour_counts", {}).items()}
        dow_counts = {int(k): v for k, v in stats.get("dow_counts", {}).items()}
        if not hour_counts or not dow_counts:
            continue
        hour_top_share = max(hour_counts.values()) / n
        dow_top_share = max(dow_counts.values()) / n
        if hour_top_share >= 0.35 and dow_top_share >= 0.35:
            out.append({
                "routine_id": stable_id("ROUT", entity_id),
                "entity_id": entity_id,
                "dominant_hour_utc": max(hour_counts, key=hour_counts.get),
                "dominant_weekday": max(dow_counts, key=dow_counts.get),
                "hour_concentration": round(hour_top_share, 4),
                "weekday_concentration": round(dow_top_share, 4),
                "sample_size": n,
                "confidence": "MODERATE" if n >= 30 else "LOW",
                "limitations": [
                    "Routine candidate only. Do not expose or use private-person schedules for targeting.",
                ],
            })
    return out


def detect_bursts(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_entity: Dict[str, Counter] = defaultdict(Counter)
    for e in events:
        if e.get("start_utc"):
            by_entity[e["entity_id"]][e["start_utc"].date().isoformat()] += 1

    out = []
    for entity_id, counts in by_entity.items():
        vals = list(counts.values())
        if len(vals) < 7:
            continue
        mean = safe_mean(vals)
        std = safe_stdev(vals)
        for day, count in counts.items():
            z = safe_z(count, mean, std)
            if z >= 3:
                out.append({
                    "burst_id": stable_id("BURST", entity_id, day),
                    "entity_id": entity_id,
                    "date": day,
                    "count": count,
                    "baseline_mean": round(mean, 4),
                    "baseline_std": round(std, 4),
                    "z_score": round(z, 4),
                    "severity": "HIGH" if z >= 5 else "MODERATE",
                    "limitations": [
                        "Burst may be campaign, incident, batch job, data ingestion, product event, or measurement artifact.",
                    ],
                })
    return out


def detect_change_points(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_entity: Dict[str, Counter] = defaultdict(Counter)
    for e in events:
        if e.get("start_utc"):
            by_entity[e["entity_id"]][e["start_utc"].date().isoformat()] += 1

    out = []
    for entity_id, counts in by_entity.items():
        series = sorted(counts.items())
        if len(series) < 10:
            continue
        mid = len(series) // 2
        first = [v for _, v in series[:mid]]
        second = [v for _, v in series[mid:]]
        if len(first) < 3 or len(second) < 3:
            continue
        m1, m2 = safe_mean(first), safe_mean(second)
        s1, s2 = safe_stdev(first), safe_stdev(second)
        pooled = math.sqrt((s1 * s1 + s2 * s2) / 2.0) if (s1 or s2) else 0.0
        diff = abs(m2 - m1)
        if pooled <= 1e-9:
            if diff > 0:
                ratio = 10.0
            else:
                continue
        else:
            ratio = diff / pooled
        if ratio >= 2.0:
            change_date = series[mid][0]
            direction = "INCREASE" if m2 > m1 else "DECREASE"
            label = "SUDDEN_SHIFT" if ratio >= 4.0 else "GRADUAL_DRIFT"
            out.append({
                "change_point_id": stable_id("CP", entity_id, change_date),
                "entity_id": entity_id,
                "date": change_date,
                "direction": direction,
                "mean_before": round(m1, 4),
                "mean_after": round(m2, 4),
                "effect_size": round(ratio, 4),
                "label": label,
                "limitations": [
                    "Change point may reflect role change, project, automation, policy change, outage, or data coverage shift.",
                ],
            })
    return out


def detect_behavioral_drift(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_entity: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in events:
        if e.get("start_utc"):
            by_entity[e["entity_id"]].append(e)

    out = []
    for entity_id, evs in by_entity.items():
        evs = sorted(evs, key=lambda x: x["start_utc"])
        if len(evs) < 40:
            continue
        mid = len(evs) // 2
        early = compute_activity_stats(evs[:mid])
        late = compute_activity_stats(evs[mid:])
        tv = tv_distance(early.get("type_probs", {}), late.get("type_probs", {}))
        interval_shift = 0.0
        e_med = float(early.get("interval_median", 0.0) or 0.0)
        l_med = float(late.get("interval_median", 0.0) or 0.0)
        if e_med > 0:
            interval_shift = abs(l_med - e_med) / e_med

        if tv >= 0.25 or interval_shift >= 0.50:
            out.append({
                "drift_id": stable_id("DRIFT", entity_id),
                "entity_id": entity_id,
                "type_distribution_tv_distance": round(tv, 4),
                "interval_median_shift_ratio": round(interval_shift, 4),
                "early_sample": early.get("event_count"),
                "late_sample": late.get("event_count"),
                "confidence": "MODERATE" if min(early.get("event_count", 0), late.get("event_count", 0)) >= 30 else "LOW",
                "limitations": [
                    "Drift is not maliciousness. Role, system, project, or policy changes often create legitimate drift.",
                ],
            })
    return out


def detect_coordination(
    events: List[Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
    source_roots: Dict[str, str],
    sync_window_seconds: float = 60.0,
) -> List[Dict[str, Any]]:
    by_entity: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in events:
        if e.get("start_utc"):
            by_entity[e["entity_id"]].append(e)

    entities = sorted(by_entity)
    out = []

    for i in range(len(entities)):
        for j in range(i + 1, len(entities)):
            a_id, b_id = entities[i], entities[j]
            a_events = sorted(by_entity[a_id], key=lambda x: x["start_utc"])[:300]
            b_events = sorted(by_entity[b_id], key=lambda x: x["start_utc"])[:300]
            pairs = []
            event_types = set()

            for a in a_events:
                for b in b_events:
                    delta = abs((a["start_utc"] - b["start_utc"]).total_seconds())
                    if delta <= sync_window_seconds and a["event_type"] == b["event_type"]:
                        pairs.append((a["event_id"], b["event_id"]))
                        event_types.add(a["event_type"])

            if len(pairs) >= 3:
                source_ids = sorted({
                    sid
                    for eid1, eid2 in pairs
                    for ev in (by_entity[a_id], by_entity[b_id])
                    for e2 in ev
                    if e2["event_id"] in (eid1, eid2)
                    for sid in e2.get("source_ids", [])
                })
                families = source_family_ids(source_ids, source_roots)
                out.append({
                    "coordination_id": stable_id("COORD", a_id, b_id),
                    "entities": [a_id, b_id],
                    "synchronized_event_count": len(pairs),
                    "sync_window_seconds": sync_window_seconds,
                    "event_types": sorted(event_types),
                    "source_independence_state": independence_state(families, sources, source_ids),
                    "confidence": "CANDIDATE",
                    "limitations": [
                        "Synchronized activity may result from same schedule, news event, automation, shared service, or coincidence.",
                        "This does not prove coordination, collusion, common controller, or malicious intent.",
                    ],
                })
    return out


def detect_interactions(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    pairs = Counter()
    for e in events:
        if e.get("target_entity"):
            pairs[(e["entity_id"], e["target_entity"])] += 1

    out = []
    for (src, tgt), count in pairs.most_common(200):
        out.append({
            "interaction_id": stable_id("INTER", src, tgt),
            "source_entity": src,
            "target_entity": tgt,
            "count": count,
            "direction": "SOURCE_TO_TARGET",
            "limitations": [
                "Interaction count does not prove relationship, trust, control, collaboration, or intent.",
            ],
        })
    return out


# --------------------------------------------------------------------
# Benign explanations / enrichment
# --------------------------------------------------------------------

def enrich_anomalies(
    anomalies: List[Dict[str, Any]],
    events_by_id: Dict[str, Dict[str, Any]],
    contexts: List[Dict[str, Any]],
    periodicity: List[Dict[str, Any]],
    peer_baselines_by_entity: Dict[str, Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
    source_roots: Dict[str, str],
) -> None:
    for a in anomalies:
        evs = [events_by_id[eid] for eid in a.get("event_ids", []) if eid in events_by_id]
        if not evs:
            continue

        times = [e["start_utc"] for e in evs if e.get("start_utc")]
        min_t = min(times) if times else None
        max_t = max(times) if times else None

        explanations: List[str] = []

        for ctx in contexts:
            if ctx.get("entity_ids") and not any(e["entity_id"] in ctx["entity_ids"] for e in evs):
                continue
            if time_overlap(ctx.get("valid_from"), ctx.get("valid_to"), min_t, max_t):
                if ctx.get("context_type") in BENIGN_CONTEXT_TYPES:
                    explanations.append(f"Authorized context overlap: {ctx['context_type']} ({ctx.get('description') or ctx['context_id']})")

        coverage_states = {e.get("source_coverage_state", "UNKNOWN") for e in evs}
        if coverage_states - {"OK", "UNKNOWN"}:
            explanations.append("Source coverage gap/outage may affect observed frequency or timing.")

        event_types = {e["event_type"] for e in evs}
        for p in periodicity:
            if p.get("entity_id") == a.get("entity_id") and p.get("event_type") in event_types:
                explanations.append("Recurring periodic pattern may indicate automation or scheduled process.")

        if any(e.get("attributes", {}).get("service_account") or e.get("event_type") in AUTOMATION_EVENT_HINTS for e in evs):
            explanations.append("Service/automation account context possible.")

        if any(e.get("timezone_state") == "UNKNOWN" or e.get("time_precision") in {"DAY", "MONTH", "YEAR", "UNKNOWN"} for e in evs):
            explanations.append("Timezone/timestamp precision uncertainty may affect temporal anomaly.")

        if peer_baselines_by_entity.get(a.get("entity_id")):
            explanations.append("Peer cohort baseline available; compare before escalation.")

        a["benign_explanations"] = list(dict.fromkeys(explanations))

        source_ids = sorted({sid for e in evs for sid in e.get("source_ids", [])})
        families = source_family_ids(source_ids, source_roots)
        a["raw_source_count"] = len(source_ids)
        a["independent_source_family_count"] = len(families)
        a["source_independence_state"] = independence_state(families, sources, source_ids)

        if a["source_independence_state"] == "DEPENDENT":
            a["confidence"] = "LOW"
        if a["benign_explanations"]:
            a["status"] = "BENIGN_EXPLANATION_CANDIDATE"


# --------------------------------------------------------------------
# Fact gate / hypotheses / ACH
# --------------------------------------------------------------------

def apply_known_facts(
    anomalies: List[Dict[str, Any]],
    patterns: List[Dict[str, Any]],
    known_facts: List[Any],
) -> None:
    for fact in known_facts or []:
        if not isinstance(fact, dict):
            continue
        state = normalize_text(fact.get("state", "SUPPORTED")).upper()
        entity_id = normalize_text(fact.get("entity_id"))
        text = normalize_text(fact.get("text") or fact.get("statement"))

        for a in anomalies:
            if entity_id and a.get("entity_id") != entity_id:
                continue
            a.setdefault("fact_gate_notes", []).append({
                "fact_id": fact.get("fact_id"),
                "state": state,
                "text": text,
            })
            if state == "REFUTED":
                a["status"] = "REFUTED_BY_KNOWN_FACT"
            elif state in {"SUPPORTED", "VERIFIED"} and fact.get("benign"):
                a["status"] = "BENIGN_EXPLANATION_SUPPORTED"


def classify_ach(evidence_type: str, hypothesis_category: str) -> str:
    if evidence_type == "rarity":
        if hypothesis_category == "SERIOUS_CANDIDATE":
            return "CONSISTENT"
        return "NEUTRAL"

    if evidence_type in {"benign_context", "periodicity", "peer_similarity", "service_account"}:
        if hypothesis_category == "BENIGN":
            return "CONSISTENT"
        if hypothesis_category == "SERIOUS_CANDIDATE":
            return "INCONSISTENT"
        return "NEUTRAL"

    if evidence_type in {"coverage_gap", "source_dependence", "timezone_uncertainty"}:
        if hypothesis_category == "ARTIFACT":
            return "CONSISTENT"
        if hypothesis_category == "SERIOUS_CANDIDATE":
            return "INCONSISTENT"
        return "NEUTRAL"

    return "NEUTRAL"


def generate_hypotheses_and_ach(
    anomalies: List[Dict[str, Any]],
    events_by_id: Dict[str, Dict[str, Any]],
    periodicity: List[Dict[str, Any]],
    peer_baselines_by_entity: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    hypotheses: List[Dict[str, Any]] = []
    ach_results: List[Dict[str, Any]] = []

    for a in anomalies[:200]:
        h_defs = [
            {
                "hypothesis_id": stable_id("HYP", a["anomaly_id"], "automation"),
                "anomaly_id": a["anomaly_id"],
                "category": "BENIGN",
                "statement": "Observable pattern may be automation, scheduled process, or service-account behaviour.",
            },
            {
                "hypothesis_id": stable_id("HYP", a["anomaly_id"], "legitimate_context"),
                "anomaly_id": a["anomaly_id"],
                "category": "BENIGN",
                "statement": "Authorized role, project, migration, maintenance, policy, or business context may explain the change.",
            },
            {
                "hypothesis_id": stable_id("HYP", a["anomaly_id"], "shared_operator"),
                "anomaly_id": a["anomaly_id"],
                "category": "BENIGN",
                "statement": "Account/session may be shared or operated by another authorized person/system.",
            },
            {
                "hypothesis_id": stable_id("HYP", a["anomaly_id"], "data_artifact"),
                "anomaly_id": a["anomaly_id"],
                "category": "ARTIFACT",
                "statement": "Telemetry gap, duplication, clock/timezone issue, or baseline weakness may create apparent anomaly.",
            },
            {
                "hypothesis_id": stable_id("HYP", a["anomaly_id"], "misuse_candidate"),
                "anomaly_id": a["anomaly_id"],
                "category": "SERIOUS_CANDIDATE",
                "statement": "Unauthorized misuse or compromise remains a candidate requiring independent evidence.",
            },
        ]

        evidence: List[Dict[str, Any]] = []
        evidence.append({
            "evidence_id": stable_id("ACHEV", a["anomaly_id"], "rarity"),
            "type": "rarity",
            "description": f"Statistical signal: {a.get('statistical_score')} via {a.get('method')}",
        })

        for exp in a.get("benign_explanations", []):
            etype = "benign_context"
            if "periodic" in exp.lower():
                etype = "periodicity"
            elif "peer" in exp.lower():
                etype = "peer_similarity"
            elif "service" in exp.lower() or "automation" in exp.lower():
                etype = "service_account"
            evidence.append({
                "evidence_id": stable_id("ACHEV", a["anomaly_id"], etype, exp),
                "type": etype,
                "description": exp,
            })

        evs = [events_by_id[eid] for eid in a.get("event_ids", []) if eid in events_by_id]
        if any(e.get("source_coverage_state") not in {"OK", "UNKNOWN"} for e in evs):
            evidence.append({
                "evidence_id": stable_id("ACHEV", a["anomaly_id"], "coverage_gap"),
                "type": "coverage_gap",
                "description": "One or more supporting events fall outside known source coverage or during outage/gap.",
            })

        if a.get("source_independence_state") == "DEPENDENT":
            evidence.append({
                "evidence_id": stable_id("ACHEV", a["anomaly_id"], "source_dependence"),
                "type": "source_dependence",
                "description": "Supporting sources are not independent.",
            })

        if any(e.get("timezone_state") == "UNKNOWN" for e in evs):
            evidence.append({
                "evidence_id": stable_id("ACHEV", a["anomaly_id"], "timezone_uncertainty"),
                "type": "timezone_uncertainty",
                "description": "Timezone assumption may affect temporal interpretation.",
            })

        matrix = []
        consistent_counts: Counter = Counter()
        for ev in evidence:
            row = {"evidence_id": ev["evidence_id"], "assessments": {}}
            for h in h_defs:
                val = classify_ach(ev["type"], h["category"])
                row["assessments"][h["hypothesis_id"]] = val
                if val == "CONSISTENT":
                    consistent_counts[h["hypothesis_id"]] += 1
            matrix.append(row)

        serious_id = h_defs[-1]["hypothesis_id"]
        benign_ids = {h["hypothesis_id"] for h in h_defs if h["category"] == "BENIGN"}
        artifact_id = h_defs[-2]["hypothesis_id"]

        benign_score = sum(consistent_counts[hid] for hid in benign_ids)
        artifact_score = consistent_counts[artifact_id]
        serious_score = consistent_counts[serious_id]

        if benign_score >= max(2, serious_score):
            status = "BENIGN_EXPLANATION_SUPPORTED"
        elif artifact_score >= max(2, serious_score):
            status = "DATA_ARTIFACT_CANDIDATE"
        elif serious_score > 0 and benign_score == 0 and artifact_score == 0:
            status = "MISUSE_CANDIDATE_UNRESOLVED"
        else:
            status = "UNRESOLVED"

        a["status"] = status
        a["hypothesis_ids"] = [h["hypothesis_id"] for h in h_defs]

        hypotheses.extend(h_defs)
        ach_results.append({
            "anomaly_id": a["anomaly_id"],
            "evidence": evidence,
            "matrix": matrix,
            "status": status,
            "limitations": [
                "ACH output is analytical support, not proof.",
                "Serious hypotheses remain candidates unless independently verified by authorized evidence.",
            ],
        })

    return hypotheses, ach_results


# --------------------------------------------------------------------
# Graph memory
# --------------------------------------------------------------------

class GraphMemory:
    def __init__(self) -> None:
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, Any]] = []
        self._node_ids: Set[str] = set()

    def add_node(self, node_type: str, node_id: str, properties: Optional[Dict[str, Any]] = None) -> None:
        if node_id in self._node_ids:
            return
        self._node_ids.add(node_id)
        self.nodes.append({"type": node_type, "id": node_id, "properties": properties or {}})

    def add_edge(self, from_id: str, to_id: str, edge_type: str, properties: Optional[Dict[str, Any]] = None) -> None:
        self.edges.append({
            "from": from_id,
            "to": to_id,
            "type": edge_type,
            "properties": properties or {},
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": self.nodes[:2000],
            "edges": self.edges[:4000],
            "note": "Behavioural graph preserves observable events, baselines, anomalies, and hypotheses. It does not prove intent, identity, or guilt.",
        }


def build_graph_memory(
    events: List[Dict[str, Any]],
    sessions: List[Dict[str, Any]],
    baselines: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
    patterns: List[Dict[str, Any]],
    hypotheses: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
) -> GraphMemory:
    g = GraphMemory()

    entity_ids = {e["entity_id"] for e in events}
    for eid in entity_ids:
        g.add_node("Entity", eid, {"display": mask_entity(eid)})

    for e in events:
        g.add_node("Event", e["event_id"], {
            "entity_id": e["entity_id"],
            "event_type": e["event_type"],
            "start_utc": iso(e.get("start_utc")),
            "source_coverage_state": e.get("source_coverage_state"),
        })
        g.add_edge(e["entity_id"], e["event_id"], "PERFORMED", {"method": "event_ingestion"})

    for s in sessions:
        g.add_node("Session", s["session_id"], {
            "entity_id": s["entity_id"],
            "start_utc": iso(s.get("start_utc")),
            "event_count": s.get("event_count"),
        })
        for eid in s.get("event_ids", [])[:100]:
            g.add_edge(eid, s["session_id"], "PART_OF_SESSION", {"method": s.get("method")})

    for b in baselines:
        g.add_node("Baseline", b["baseline_id"], {
            "entity_id": b["entity_id"],
            "baseline_type": b["baseline_type"],
            "confidence": b.get("quality", {}).get("confidence"),
        })

    for a in anomalies:
        g.add_node("Anomaly", a["anomaly_id"], {
            "entity_id": a["entity_id"],
            "type": a["anomaly_type"],
            "status": a["status"],
            "severity": a["severity"],
        })
        g.add_edge(a["anomaly_id"], a["baseline_id"], "DEVIATES_FROM", {"method": a.get("method")})
        for eid in a.get("event_ids", [])[:50]:
            g.add_edge(a["anomaly_id"], eid, "SUPPORTED_BY_EVENT", {"confidence": a.get("confidence")})

    for p in patterns:
        pid = p.get("periodicity_id") or p.get("routine_id") or p.get("burst_id") or p.get("change_point_id") or p.get("drift_id") or p.get("coordination_id") or p.get("interaction_id")
        if pid:
            g.add_node("Pattern", pid, {k: v for k, v in p.items() if k != "limitations"})

    for h in hypotheses[:500]:
        g.add_node("Hypothesis", h["hypothesis_id"], {
            "statement": h["statement"],
            "category": h["category"],
            "anomaly_id": h.get("anomaly_id"),
        })

    for gap in gaps[:500]:
        g.add_node("Gap", gap["gap_id"], {
            "type": gap["type"],
            "importance": gap["importance"],
        })

    return g


# --------------------------------------------------------------------
# Gaps / actions / handoffs / observations
# --------------------------------------------------------------------

def build_observations(
    events: List[Dict[str, Any]],
    sessions: List[Dict[str, Any]],
    baselines: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
    patterns: List[Dict[str, Any]],
    privacy_flags: List[Dict[str, Any]],
) -> List[str]:
    obs = []
    obs.append(f"Observable events ingested: {len(events)}.")
    obs.append(f"Sessions constructed: {len(sessions)}.")
    obs.append(f"Baselines built: {len(baselines)}.")
    obs.append(f"Anomaly candidates detected: {len(anomalies)}.")
    obs.append(f"Behavioural patterns detected: {len(patterns)}.")
    if any(b.get("quality", {}).get("confidence") in {"INSUFFICIENT", "LOW"} for b in baselines):
        obs.append("Some baselines are weak; anomaly conclusions are correspondingly weak.")
    if any(a.get("source_independence_state") == "DEPENDENT" for a in anomalies):
        obs.append("Some anomalies rely on dependent sources; do not treat copied telemetry as independent corroboration.")
    if any(a.get("benign_explanations") for a in anomalies):
        obs.append("Benign explanations were tested for material anomalies.")
    if privacy_flags:
        obs.append("Sensitive attributes/content/exact location were removed and not used as behavioural features.")
    obs.append("No intent, motive, personality, mental health, lie detection, dangerousness, criminality, or real-person attribution was inferred.")
    return obs


def build_unknowns(
    events: List[Dict[str, Any]],
    baselines: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
    coordination: List[Dict[str, Any]],
) -> List[str]:
    unknowns = []
    for e in events:
        if e.get("source_coverage_state") not in {"OK", "UNKNOWN"}:
            unknowns.append(f"Event {e['event_id']} source coverage state unresolved: {e.get('source_coverage_state')}.")
    for b in baselines:
        if b.get("quality", {}).get("confidence") in {"INSUFFICIENT", "LOW"}:
            unknowns.append(f"Baseline {b['baseline_id']} quality insufficient for strong anomaly inference.")
    for a in anomalies:
        if a.get("status") in {"CANDIDATE", "UNRESOLVED", "MISUSE_CANDIDATE_UNRESOLVED"}:
            unknowns.append(f"Anomaly {a['anomaly_id']} remains unresolved: {a.get('status')}.")
    for c in coordination:
        unknowns.append(f"Coordination signal {c['coordination_id']} is candidate only; common controller unresolved.")
    unknowns.append("Account operator identity remains unresolved unless separate authorized identity evidence exists.")
    return list(dict.fromkeys(unknowns))[:500]


def build_gaps(
    events: List[Dict[str, Any]],
    baselines: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
    coordination: List[Dict[str, Any]],
    privacy_flags: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    gaps = []

    for b in baselines:
        if b.get("quality", {}).get("confidence") in {"INSUFFICIENT", "LOW"}:
            gaps.append({
                "gap_id": stable_id("GAP", "baseline", b["baseline_id"]),
                "type": "BASELINE_INSUFFICIENT",
                "importance": "HIGH",
                "baseline_id": b["baseline_id"],
                "recommended_source": "Longer clean historical window, peer cohort, role context, or system baseline.",
                "specialist": "BEHAVINT / LOGINT / ORGINT",
                "expected_information_value": "Reduce false anomalies and improve calibration.",
            })

    for e in events:
        if e.get("source_coverage_state") not in {"OK", "UNKNOWN"}:
            gaps.append({
                "gap_id": stable_id("GAP", "coverage", e["event_id"]),
                "type": "SOURCE_COVERAGE_INCOMPLETE",
                "importance": "HIGH",
                "event_id": e["event_id"],
                "recommended_source": "Sensor operational log, retention policy, alternate independent telemetry.",
                "specialist": "BEHAVINT / LOGINT",
                "expected_information_value": "Distinguish missing data from non-occurrence.",
            })

    for a in anomalies:
        if a.get("status") in {"CANDIDATE", "UNRESOLVED", "MISUSE_CANDIDATE_UNRESOLVED"}:
            gaps.append({
                "gap_id": stable_id("GAP", "anomaly", a["anomaly_id"]),
                "type": "ANOMALY_UNRESOLVED",
                "importance": "HIGH" if a.get("severity") == "HIGH" else "MEDIUM",
                "anomaly_id": a["anomaly_id"],
                "recommended_source": "Independent telemetry, authorized context record, peer cohort, or endpoint/session correlation.",
                "specialist": "BEHAVINT / INCIDENTINT / FRAUDINT",
                "expected_information_value": "Test benign explanations before any serious hypothesis.",
            })

    for c in coordination:
        gaps.append({
            "gap_id": stable_id("GAP", "coordination", c["coordination_id"]),
            "type": "COORDINATION_UNRESOLVED",
            "importance": "MEDIUM",
            "coordination_id": c["coordination_id"],
            "recommended_source": "Independent infrastructure, content, scheduling, or relationship evidence.",
            "specialist": "BEHAVINT / RELATIONSHIPINT / CAMPAIGNINT",
            "expected_information_value": "Distinguish synchronization from coordination or common control.",
        })

    for pf in privacy_flags:
        gaps.append({
            "gap_id": stable_id("GAP", "privacy", pf.get("event_index"), pf.get("type")),
            "type": "SENSITIVE_DATA_EXCLUDED",
            "importance": "HIGH",
            "event_index": pf.get("event_index"),
            "recommended_source": "Do not seek sensitive traits/content/exact location unless exceptional lawful necessity and explicit policy permission.",
            "specialist": "PRIVACY / HUMAN_REVIEW",
            "expected_information_value": "Maintain privacy boundary.",
        })

    return gaps[:500]


def build_next_actions(gaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    actions = []
    priority_map = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

    for g in gaps:
        if g["type"] == "BASELINE_INSUFFICIENT":
            action = "Extend clean baseline window, exclude contaminated periods, and compare peer cohort before escalating anomalies."
        elif g["type"] == "SOURCE_COVERAGE_INCOMPLETE":
            action = "Verify sensor operational status, retention, and alternate independent telemetry; absence of record is not absence of event."
        elif g["type"] == "ANOMALY_UNRESOLVED":
            action = "Test benign explanations: automation, role change, project, maintenance, shared account, data artifact, and source dependence."
        elif g["type"] == "COORDINATION_UNRESOLVED":
            action = "Seek independent infrastructure/content/relationship evidence before interpreting synchronization as coordination."
        elif g["type"] == "SENSITIVE_DATA_EXCLUDED":
            action = "Maintain privacy boundary; do not pursue sensitive traits, private content, or exact location."
        else:
            action = "Gather additional authorized observable evidence."

        actions.append({
            "action": action,
            "gap_id": g.get("gap_id"),
            "priority": g.get("importance", "MEDIUM"),
            "expected_information_value": g.get("expected_information_value"),
            "prohibited_alternatives": [
                "Do not stalk or track private persons in real time.",
                "Do not perform biometric identification.",
                "Do not infer intent, motive, personality, mental health, religion, ethnicity, politics, health, or criminality.",
                "Do not generate dangerousness, criminality, or loyalty scores.",
                "Do not manipulate, coerce, or optimize persuasion against individuals.",
                "Do not make autonomous consequential employment, credit, insurance, or law-enforcement decisions.",
            ],
        })

    actions.sort(key=lambda x: priority_map.get(x.get("priority", "LOW"), 9))
    return actions[:200]


def build_handoffs(
    manifest: Dict[str, Any],
    events: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
    coordination: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    blob = collect_user_intent_text(manifest).lower()
    event_types = {e.get("event_type", "").lower() for e in events}
    hands = []

    def add(spec: str, reason: str) -> None:
        hands.append({
            "specialist": spec,
            "reason": reason,
            "payload": ["entity_ids_masked", "event_ids", "anomaly_ids", "time_range", "source_ids", "known_facts", "unknowns", "limitations"],
        })

    if any(x in t for t in event_types for x in ["login", "auth", "privilege", "admin", "endpoint", "network"]) or "cyber" in blob:
        add("INCIDENTINT / CYBINT / LOGINT", "Cyber behavioural anomalies require incident/security specialist interpretation.")
    if any(x in t for t in event_types for x in ["payment", "transaction", "transfer", "invoice"]) or "fraud" in blob:
        add("FININT / FRAUDINT", "Transaction/payment behavioural patterns require financial/fraud specialist interpretation.")
    if any(x in t for t in event_types for x in ["role", "hr", "employee", "org"]) or "role" in blob:
        add("ORGINT", "Role/organizational context may explain behavioural drift.")
    if coordination:
        add("RELATIONSHIPINT / CAMPAIGNINT / NARRATIVEINT", "Coordination signals require relationship/campaign/narrative specialist analysis.")
    if any(a.get("status") == "MISUSE_CANDIDATE_UNRESOLVED" for a in anomalies):
        add("HUMAN_REVIEW", "Serious candidate requires authorized human review before any consequential action.")
    return hands


def dual_ai_review_stub(
    anomalies: List[Dict[str, Any]],
    baselines: List[Dict[str, Any]],
    coordination: List[Dict[str, Any]],
) -> Dict[str, Any]:
    review = {
        "status": "INSUFFICIENT_EVIDENCE",
        "primary_conclusions": [],
        "skeptic_challenges": [],
        "comparison": "NO_SECOND_MODEL_CONFIGURED",
        "notes": [
            "This starter does not call an independent second model.",
            "AI agreement is not independent behavioural evidence.",
            "Human review is required for consequential person-level or misconduct conclusions.",
        ],
    }
    if any(b.get("quality", {}).get("confidence") in {"INSUFFICIENT", "LOW"} for b in baselines):
        review["primary_conclusions"].append("Some baselines are weak.")
        review["skeptic_challenges"].append("Do not escalate anomalies from weak baselines without independent context.")
    if any(a.get("benign_explanations") for a in anomalies):
        review["primary_conclusions"].append("Benign explanations were generated for some anomalies.")
        review["skeptic_challenges"].append("Check whether benign context is authorized, contemporaneous, and independent.")
    if coordination:
        review["primary_conclusions"].append("Coordination candidates detected.")
        review["skeptic_challenges"].append("Synchronization may be schedule/news/automation/shared service; do not infer common controller.")
    if review["primary_conclusions"]:
        review["status"] = "PARTIAL_AGREEMENT"
    return review


# --------------------------------------------------------------------
# Result assembly
# --------------------------------------------------------------------

def empty_result(manifest: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "case_id": manifest.get("case_id", "CASE-UNKNOWN"),
        "task_id": manifest.get("task_id", "TASK-UNKNOWN"),
        "objective": manifest.get("objective", ""),
        "questions": manifest.get("questions", []) or [],
        "generated_at": utc_now(),
        "version": VERSION,
        "source_ids": [],
        "evidence_ids": [],
        "entities": [],
        "accounts": [],
        "systems": [],
        "devices": [],
        "sessions": [],
        "events": [],
        "event_sequences": [],
        "event_chains": [],
        "baselines": [],
        "baseline_quality": [],
        "peer_groups": [],
        "routines": [],
        "patterns": [],
        "periodicity": [],
        "bursts": [],
        "change_points": [],
        "behavioral_drift": [],
        "anomalies": [],
        "anomaly_types": [],
        "anomaly_scores": [],
        "state_transitions": [],
        "interaction_patterns": [],
        "coordination_signals": [],
        "campaign_behavior": [],
        "transaction_behavior": [],
        "cyber_behavior": [],
        "organizational_context": [],
        "source_coverage": [],
        "data_completeness": [],
        "timeline_updates": [],
        "observations": [],
        "candidate_facts": [],
        "supported_facts": [],
        "partial_facts": [],
        "disputed_facts": [],
        "source_reliability": [],
        "source_bias": [],
        "source_limitations": [],
        "source_pedigree": [],
        "source_independence": [],
        "benign_explanations": [],
        "contradictions": [],
        "hypotheses": [],
        "ach_matrix": [],
        "falsification_results": [],
        "privacy_flags": [],
        "unknowns": [],
        "knowledge_gaps": [],
        "recommended_next_actions": [],
        "specialist_handoffs": [],
        "limitations": [],
        "dual_ai_review": {},
        "graph_memory": {},
        "status": "PARTIAL",
    }


def summarize_event(e: Dict[str, Any], privacy_cfg: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "event_id": e["event_id"],
        "entity_display": mask_entity(e["entity_id"], privacy_cfg.get("mask_entity_display", True)),
        "entity_type": e.get("entity_type"),
        "event_type": e.get("event_type"),
        "action": e.get("action"),
        "object": e.get("object"),
        "target_display": mask_entity(e.get("target_entity"), privacy_cfg.get("mask_entity_display", True)) if e.get("target_entity") else None,
        "session_id": e.get("session_id"),
        "device_context": e.get("device_context"),
        "location_context": e.get("location_context"),
        "start_utc": iso(e.get("start_utc")),
        "end_utc": iso(e.get("end_utc")),
        "time_precision": e.get("time_precision"),
        "timezone_state": e.get("timezone_state"),
        "timestamp_type": e.get("timestamp_type"),
        "source_ids": e.get("source_ids", []),
        "source_coverage_state": e.get("source_coverage_state"),
        "evidence_ids": e.get("evidence_ids", []),
        "attributes": e.get("attributes", {}),
        "limitations": e.get("limitations", []),
    }


def summarize_baseline(b: Dict[str, Any]) -> Dict[str, Any]:
    stats = b.get("stats", {})
    return {
        "baseline_id": b["baseline_id"],
        "baseline_type": b["baseline_type"],
        "entity_display": mask_entity(b["entity_id"]),
        "peer_group_id": b.get("peer_group_id"),
        "training_start": iso(b.get("training_start")),
        "training_end": iso(b.get("training_end")),
        "evaluation_start": iso(b.get("evaluation_start")),
        "evaluation_end": iso(b.get("evaluation_end")),
        "sample_size": stats.get("event_count"),
        "span_days": stats.get("span_days"),
        "top_event_types": dict(Counter(stats.get("type_counts", {})).most_common(10)),
        "hour_distribution": stats.get("hour_counts", {}),
        "weekday_distribution": stats.get("dow_counts", {}),
        "daily_mean": stats.get("daily_mean"),
        "daily_std": stats.get("daily_std"),
        "interval_median_seconds": stats.get("interval_median"),
        "quality": b.get("quality", {}),
        "limitations": b.get("limitations", []),
    }


def summarize_anomaly(a: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(a)
    out["entity_display"] = mask_entity(a.get("entity_id"))
    out.pop("entity_id", None)
    return out


def finalize_status(
    result: Dict[str, Any],
    events: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
    auth_ok: bool,
    policy_blocked: List[str],
) -> str:
    if policy_blocked:
        return "POLICY_BLOCKED"
    if not auth_ok:
        return "BLOCKED_PERMISSION"
    if not events:
        return "INSUFFICIENT_INPUT"
    if any(a.get("status") in {"MISUSE_CANDIDATE_UNRESOLVED", "CANDIDATE", "UNRESOLVED"} for a in anomalies):
        return "PARTIAL"
    if result.get("knowledge_gaps"):
        return "PARTIAL"
    return "SUCCEEDED"


def analyze_behavint_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    result = empty_result(manifest)

    policy_blocked = policy_screen(manifest)
    if policy_blocked:
        result["status"] = "POLICY_BLOCKED"
        result["violations"] = policy_blocked
        result["privacy_flags"] = [{"type": label, "action": "PROHIBITED_REQUEST_NOT_PERFORMED"} for label in policy_blocked]
        result["limitations"] = [
            "BEHAVINT does not stalk, track privately, biometrically identify, psychologically profile, lie-detect, infer sensitive traits, score dangerousness/criminality/loyalty, manipulate, or make autonomous consequential decisions."
        ]
        return result

    auth_ok, auth_reasons = authorization_check(manifest)
    if not auth_ok:
        result["status"] = "BLOCKED_PERMISSION"
        result["limitations"] = auth_reasons
        return result

    privacy_cfg = privacy_config(manifest)
    sources = ingest_sources(manifest)
    source_roots = build_source_roots(sources)
    coverage_by_source = ingest_source_coverage(manifest)
    contexts = ingest_contexts(manifest)

    events, privacy_flags = ingest_events(manifest, sources, coverage_by_source, privacy_cfg)
    if not events:
        result["status"] = "INSUFFICIENT_INPUT"
        result["limitations"].append("No observable events provided.")
        return result

    sessions, session_rule = sessionize(events, gap_minutes=float(manifest.get("session_gap_minutes", 30.0)))
    baselines = build_baselines(manifest, events, contexts)
    peer_baselines_by_entity = {
        b["entity_id"]: b for b in baselines if b.get("baseline_type") == "PEER"
    }

    anomalies = detect_anomalies(events, baselines)
    enrich_anomalies(
        anomalies,
        {e["event_id"]: e for e in events},
        contexts,
        detect_periodicity(events),
        peer_baselines_by_entity,
        sources,
        source_roots,
    )

    periodicity = detect_periodicity(events)
    routines = detect_routines(events)
    bursts = detect_bursts(events)
    change_points = detect_change_points(events)
    drift = detect_behavioral_drift(events)
    coordination = detect_coordination(events, sources, source_roots)
    interactions = detect_interactions(events)

    patterns = periodicity + routines + bursts + change_points + drift + coordination + interactions

    apply_known_facts(anomalies, patterns, manifest.get("known_facts", []) or [])
    hypotheses, ach_results = generate_hypotheses_and_ach(
        anomalies,
        {e["event_id"]: e for e in events},
        periodicity,
        peer_baselines_by_entity,
    )

    observations = build_observations(events, sessions, baselines, anomalies, patterns, privacy_flags)
    unknowns = build_unknowns(events, baselines, anomalies, coordination)
    gaps = build_gaps(events, baselines, anomalies, coordination, privacy_flags)
    actions = build_next_actions(gaps)
    handoffs = build_handoffs(manifest, events, anomalies, coordination)
    dual_review = dual_ai_review_stub(anomalies, baselines, coordination)
    graph = build_graph_memory(events, sessions, baselines, anomalies, patterns, hypotheses, gaps)

    result["events"] = [summarize_event(e, privacy_cfg) for e in events]
    result["sessions"] = sessions
    result["sessionization_rule"] = session_rule
    result["baselines"] = [summarize_baseline(b) for b in baselines]
    result["baseline_quality"] = [{"baseline_id": b["baseline_id"], "quality": b.get("quality", {})} for b in baselines]
    result["anomalies"] = [summarize_anomaly(a) for a in anomalies]
    result["anomaly_types"] = [{"anomaly_id": a["anomaly_id"], "type": a["anomaly_type"]} for a in anomalies]
    result["anomaly_scores"] = [{"anomaly_id": a["anomaly_id"], "score": a.get("statistical_score"), "method": a.get("method")} for a in anomalies]
    result["periodicity"] = periodicity
    result["routines"] = routines
    result["bursts"] = bursts
    result["change_points"] = change_points
    result["behavioral_drift"] = drift
    result["coordination_signals"] = coordination
    result["interaction_patterns"] = interactions
    result["patterns"] = patterns
    result["hypotheses"] = hypotheses
    result["ach_matrix"] = ach_results
    result["falsification_results"] = [
        {
            "anomaly_id": r["anomaly_id"],
            "status": r["status"],
            "limitations": r["limitations"],
        }
        for r in ach_results
    ]
    result["benign_explanations"] = [
        {"anomaly_id": a["anomaly_id"], "explanations": a.get("benign_explanations", [])}
        for a in anomalies
        if a.get("benign_explanations")
    ]
    result["observations"] = observations
    result["unknowns"] = unknowns
    result["knowledge_gaps"] = gaps
    result["recommended_next_actions"] = actions
    result["specialist_handoffs"] = handoffs
    result["dual_ai_review"] = dual_review
    result["graph_memory"] = graph.to_dict()
    result["privacy_flags"] = privacy_flags

    for sid, src in sources.items():
        result["source_ids"].append(sid)
        result["source_reliability"].append({
            "source_id": sid,
            "source_type": src.get("source_type"),
            "reliability": src.get("reliability"),
        })
        result["source_pedigree"].append({
            "source_id": sid,
            "upstream_source_id": src.get("upstream_source_id"),
            "root_source_id": source_roots.get(sid, sid),
        })

    for e in events:
        for evid in e.get("evidence_ids", []):
            result["evidence_ids"].append(evid)
        result["data_completeness"].append({
            "event_id": e["event_id"],
            "source_coverage_state": e.get("source_coverage_state"),
        })

    for a in anomalies:
        result["source_independence"].append({
            "anomaly_id": a["anomaly_id"],
            "state": a.get("source_independence_state"),
            "raw_source_count": a.get("raw_source_count"),
            "independent_source_family_count": a.get("independent_source_family_count"),
        })
        if a.get("status") in {"BENIGN_EXPLANATION_SUPPORTED", "BENIGN_EXPLANATION_CANDIDATE"}:
            result["partial_facts"].append({"anomaly_id": a["anomaly_id"], "statement": "Benign explanation candidate supported but not conclusive."})
        elif a.get("status") == "REFUTED_BY_KNOWN_FACT":
            result["disputed_facts"].append({"anomaly_id": a["anomaly_id"], "statement": "Anomaly candidate refuted by known fact."})
        else:
            result["candidate_facts"].append({"anomaly_id": a["anomaly_id"], "statement": "Behavioural anomaly candidate."})

    base_limits = [
        "BEHAVINT starter uses only provided/local authorized observable records; no external network lookup was performed.",
        "Observable behaviour is not intent, motive, personality, mental health, guilt, or criminality.",
        "Account/device/session activity is not automatically attributed to a real person.",
        "Anomaly means deviation from a baseline, not malice.",
        "Coordination signals are candidates only and do not prove common controller, collusion, or conspiracy.",
        "Weak or contaminated baselines produce weak anomaly conclusions.",
        "Dependent/copied telemetry is not independent corroboration.",
        "Absence of event in available telemetry is not proof the event did not occur.",
        "No stalking, real-time private tracking, biometric identification, psychological profiling, lie detection, sensitive-trait inference, dangerousness scoring, manipulation, or autonomous consequential decision was performed.",
    ]
    if auth_reasons:
        base_limits.extend(auth_reasons)
    result["limitations"] = list(dict.fromkeys(base_limits))

    result["status"] = finalize_status(result, events, anomalies, auth_ok, policy_blocked)
    return result


# --------------------------------------------------------------------
# Report generation
# --------------------------------------------------------------------

def generate_report(result: Dict[str, Any]) -> str:
    lines = []
    lines.append("# BEHAVINT Evidence-Linked Report")
    lines.append("")
    lines.append(f"- Case ID: `{result.get('case_id')}`")
    lines.append(f"- Task ID: `{result.get('task_id')}`")
    lines.append(f"- Generated: `{result.get('generated_at')}`")
    lines.append(f"- Version: `{result.get('version')}`")
    lines.append(f"- Status: `{result.get('status')}`")
    lines.append("")

    if result.get("status") == "POLICY_BLOCKED":
        lines.append("## POLICY BLOCKED")
        lines.append("The request violated BEHAVINT hard restrictions:")
        for v in result.get("violations", []):
            lines.append(f"- `{v}`")
        lines.append("")
        lines.append("No behavioural analysis was performed.")
        return "\n".join(lines)

    lines.append("## Objective")
    lines.append(str(result.get("objective", "")))
    lines.append("")

    lines.append("## Required Analyst Summary")
    events = result.get("events", [])
    anomalies = result.get("anomalies", [])
    baselines = result.get("baselines", [])
    coordination = result.get("coordination_signals", [])
    lines.append(f"- OBSERVABLE EVENTS: {len(events)}")
    lines.append(f"- SESSIONS: {len(result.get('sessions', []))}")
    lines.append(f"- BASELINES: {len(baselines)}")
    lines.append(f"- ANOMALY CANDIDATES: {len(anomalies)}")
    lines.append(f"- COORDINATION SIGNALS: {len(coordination)}")
    lines.append(f"- BENIGN EXPLANATION ITEMS: {len(result.get('benign_explanations', []))}")
    lines.append(f"- PRIVACY FLAGS: {len(result.get('privacy_flags', []))}")
    lines.append(f"- UNKNOWN ITEMS: {len(result.get('unknowns', []))}")
    lines.append("- ATTRIBUTION STATUS: ACCOUNT_LEVEL_ONLY; REAL_PERSON_ATTRIBUTION=NOT_PERFORMED")
    lines.append("- INTENT STATUS: NOT_INFERRED")
    lines.append("- NEXT ACTION: " + (result.get("recommended_next_actions", [{}])[0].get("action", "None") if result.get("recommended_next_actions") else "None"))
    lines.append("")

    lines.append("## Privacy / Behavioural Boundaries")
    lines.append("- Observable behaviour only; no mind reading, intent inference, motive inference, or psychological diagnosis.")
    lines.append("- No stalking, real-time private tracking, biometric identification, or private-location inference.")
    lines.append("- No sensitive-trait inference: religion, ethnicity, race, political belief, sexual orientation, health, mental health, disability.")
    lines.append("- No dangerousness, criminality, loyalty, or predictive-policing scores.")
    lines.append("- No manipulation, coercion, or persuasion optimization.")
    lines.append("- Account/device/session activity is not automatically person activity.")
    lines.append("")

    lines.append("## Source Coverage / Data Completeness")
    coverage_counter = Counter(e.get("source_coverage_state", "UNKNOWN") for e in events)
    lines.append("- Source coverage states: " + ", ".join(f"{k}={v}" for k, v in coverage_counter.most_common()))
    lines.append("- Absence of record is not absence of event.")
    lines.append("")

    lines.append("## Event Inventory")
    for e in events[:200]:
        lines.append(f"### `{e.get('event_id')}` — {e.get('event_type')}")
        lines.append(f"- Entity: `{e.get('entity_display')}` type=`{e.get('entity_type')}`")
        lines.append(f"- Time: `{e.get('start_utc')}` precision=`{e.get('time_precision')}` tz_state=`{e.get('timezone_state')}`")
        lines.append(f"- Source coverage: `{e.get('source_coverage_state')}`")
        if e.get("target_display"):
            lines.append(f"- Target: `{e.get('target_display')}`")
        if e.get("session_id"):
            lines.append(f"- Session: `{e.get('session_id')}`")
        if e.get("attributes"):
            lines.append(f"- Attributes: `{json.dumps(e['attributes'], ensure_ascii=False)}`"[:500])
        lines.append("")

    lines.append("## Sessions")
    for s in result.get("sessions", [])[:100]:
        lines.append(f"- `{s.get('session_id')}` entity=`{mask_entity(s.get('entity_id'))}` events={s.get('event_count')} start=`{iso(s.get('start_utc')) if isinstance(s.get('start_utc'), datetime) else s.get('start_utc')}` method=`{s.get('method')}`")
    lines.append("")

    lines.append("## Baselines")
    for b in baselines[:100]:
        q = b.get("quality", {})
        lines.append(f"### `{b.get('baseline_id')}`")
        lines.append(f"- Entity: `{b.get('entity_display')}` type=`{b.get('baseline_type')}`")
        lines.append(f"- Training: `{b.get('training_start')}` to `{b.get('training_end')}`")
        lines.append(f"- Sample: `{b.get('sample_size')}` span_days=`{b.get('span_days')}`")
        lines.append(f"- Quality: `{q.get('confidence')}` completeness=`{q.get('data_completeness')}` seasonality=`{q.get('seasonality')}`")
        if q.get("contamination_contexts"):
            lines.append(f"- Contamination contexts: {', '.join(q['contamination_contexts'])}")
        lines.append("")

    lines.append("## Patterns")
    for p in result.get("periodicity", [])[:100]:
        lines.append(f"- Periodicity `{p.get('periodicity_id')}` entity=`{mask_entity(p.get('entity_id'))}` type=`{p.get('event_type')}` median_interval_s=`{p.get('median_interval_seconds')}` cv=`{p.get('coefficient_of_variation')}`")
    for p in result.get("routines", [])[:100]:
        lines.append(f"- Routine `{p.get('routine_id')}` entity=`{mask_entity(p.get('entity_id'))}` dominant_hour=`{p.get('dominant_hour_utc')}` dominant_weekday=`{p.get('dominant_weekday')}`")
    for p in result.get("bursts", [])[:100]:
        lines.append(f"- Burst `{p.get('burst_id')}` entity=`{mask_entity(p.get('entity_id'))}` date=`{p.get('date')}` z=`{p.get('z_score')}`")
    for p in result.get("change_points", [])[:100]:
        lines.append(f"- Change point `{p.get('change_point_id')}` entity=`{mask_entity(p.get('entity_id'))}` date=`{p.get('date')}` label=`{p.get('label')}` effect=`{p.get('effect_size')}`")
    for p in result.get("behavioral_drift", [])[:100]:
        lines.append(f"- Drift `{p.get('drift_id')}` entity=`{mask_entity(p.get('entity_id'))}` tv=`{p.get('type_distribution_tv_distance')}` interval_shift=`{p.get('interval_median_shift_ratio')}`")
    lines.append("")

    lines.append("## Anomalies")
    for a in anomalies[:200]:
        lines.append(f"### `{a.get('anomaly_id')}`")
        lines.append(f"- Entity: `{a.get('entity_display')}`")
        lines.append(f"- Type: `{a.get('anomaly_type')}` severity=`{a.get('severity')}` confidence=`{a.get('confidence')}` status=`{a.get('status')}`")
        lines.append(f"- Method: `{a.get('method')}` score=`{a.get('statistical_score')}`")
        lines.append(f"- Baseline: `{a.get('baseline_id')}`")
        lines.append(f"- Events: {', '.join(a.get('event_ids', [])[:20])}")
        lines.append(f"- Source independence: `{a.get('source_independence_state')}` raw_sources=`{a.get('raw_source_count')}` independent_families=`{a.get('independent_source_family_count')}`")
        if a.get("benign_explanations"):
            lines.append("- Benign explanations:")
            for exp in a["benign_explanations"][:10]:
                lines.append(f"  - {exp}")
        if a.get("details"):
            lines.append(f"- Details: `{json.dumps(a['details'], ensure_ascii=False, default=str)}`"[:700])
        lines.append("")

    lines.append("## Coordination Signals")
    for c in result.get("coordination_signals", [])[:100]:
        lines.append(f"- `{c.get('coordination_id')}` entities={[mask_entity(x) for x in c.get('entities', [])]} count={c.get('synchronized_event_count')} independence=`{c.get('source_independence_state')}`")
        for lim in c.get("limitations", [])[:3]:
            lines.append(f"  - {lim}")
    lines.append("")

    lines.append("## Interaction Patterns")
    for i in result.get("interaction_patterns", [])[:100]:
        lines.append(f"- `{i.get('source_entity')}` -> `{i.get('target_entity')}` count={i.get('count')}")
    lines.append("")

    lines.append("## Hypotheses / ACH")
    for r in result.get("ach_matrix", [])[:100]:
        lines.append(f"### Anomaly `{r.get('anomaly_id')}` status=`{r.get('status')}`")
        for ev in r.get("evidence", [])[:20]:
            lines.append(f"- Evidence `{ev.get('evidence_id')}` [{ev.get('type')}]: {ev.get('description')}")
        for row in r.get("matrix", [])[:20]:
            lines.append(f"  - {row.get('evidence_id')}: {json.dumps(row.get('assessments', {}), ensure_ascii=False)}"[:700])
    lines.append("")

    lines.append("## Knowledge Gaps")
    for g in result.get("knowledge_gaps", [])[:200]:
        lines.append(f"- `{g.get('gap_id')}` [{g.get('importance')}] {g.get('type')}: {g.get('recommended_source')}")
    lines.append("")

    lines.append("## Recommended Next Actions")
    for a in result.get("recommended_next_actions", [])[:200]:
        lines.append(f"- [{a.get('priority')}] {a.get('action')}")
    lines.append("")

    lines.append("## Specialist Handoffs")
    for h in result.get("specialist_handoffs", []):
        lines.append(f"- {h.get('specialist')}: {h.get('reason')}")
    lines.append("")

    lines.append("## Dual-AI Review Stub")
    dr = result.get("dual_ai_review", {})
    lines.append(f"- Comparison: `{dr.get('comparison')}`")
    for n in dr.get("notes", []):
        lines.append(f"- {n}")
    for c in dr.get("primary_conclusions", [])[:50]:
        lines.append(f"- Primary: {c}")
    for c in dr.get("skeptic_challenges", [])[:50]:
        lines.append(f"- Skeptic: {c}")
    lines.append("")

    lines.append("## Limitations")
    for lim in result.get("limitations", []):
        lines.append(f"- {lim}")
    lines.append("")

    lines.append("## Non-Negotiable Boundary")
    lines.append("- Observe first.")
    lines.append("- Normalize events and timestamps.")
    lines.append("- Check source coverage before interpreting absence.")
    lines.append("- Build a clean baseline before calling something anomalous.")
    lines.append("- Test benign explanations before serious hypotheses.")
    lines.append("- Separate account/device/session activity from real-person attribution.")
    lines.append("- Separate anomaly from malice, intent, motive, guilt, personality, or criminality.")
    lines.append("- Attribute last, and only with independent authorized evidence.")

    return "\n".join(lines)


# --------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="TRACEATLAS BEHAVINT safe starter")
    parser.add_argument("--manifest", required=True, help="Path to BEHAVINT manifest JSON")
    parser.add_argument("--output", default="behavint_result.json", help="Output JSON path")
    parser.add_argument("--report", default="behavint_report.md", help="Output Markdown report path")
    args = parser.parse_args()

    try:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"ERROR reading manifest: {exc}", file=sys.stderr)
        return 2

    result = analyze_behavint_manifest(manifest)

    Path(args.output).write_text(
        json.dumps(json_safe(result), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    Path(args.report).write_text(generate_report(result), encoding="utf-8")

    print(f"Wrote: {args.output}")
    print(f"Wrote: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

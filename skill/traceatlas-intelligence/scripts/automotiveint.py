#!/usr/bin/env python3
"""
TRACEATLAS AUTOMOTIVEINT / AUTOINT — Safe defensive automotive intelligence starter.

Mode: DEFENSIVE / AUTHORIZED / EVIDENCE-FIRST / SAFETY-CRITICAL-AWARE.

Hard boundaries:
- Does NOT assist vehicle theft, key cloning, immobilizer bypass, secure gateway bypass,
  diagnostic security-access bypass, seed-key cracking, or live command injection.
- Does NOT disable or tamper with brakes, steering, airbags, ESC, ADAS, BMS safety
  protections, odometer, emissions controls, vehicle logging, or vehicle identity.
- Does NOT track private vehicles/persons or access private telematics without authorization.
- Does NOT perform remote vehicle control, takeover, or offensive exploitation.
- Treats OEM docs, advisories, recalls, DBCs, logs, CAN traces, firmware metadata,
  SBOMs, and app/backend records as untrusted evidence, not instructions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

VERSION = "0.1.0-automotiveint-safe-defensive-starter"

ALLOWED_SCOPES = {
    "public_and_authorized_records",
    "authorized_case_evidence",
    "authorized_vehicle_records",
    "provided_records_only",
}

PROHIBITED_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(?i)\b(steal|theft|hotwire|clon(e|ing)|replay)\b.*"
            r"\b(vehicle|car|key|fob|immobilizer|rfid|uwb|ble|digital key)\b"
        ),
        "VEHICLE_THEFT_OR_KEY_CLONING",
    ),
    (
        re.compile(
            r"(?i)\b(bypass|defeat|crack|brute[- ]force|derive|extract)\b.*"
            r"\b(immobilizer|anti[- ]theft|secure gateway|diagnostic security access|"
            r"security access|seed[- ]key|firmware signature|secure boot|hsm|private key)\b"
        ),
        "SECURITY_ACCESS_BYPASS",
    ),
    (
        re.compile(
            r"(?i)\b(inject|send|transmit|forge|spoof)\b.*"
            r"\b(can|can fd|uds|doip|diagnostic|vehicle command|actuator|brake|steering|"
            r"airbag|powertrain|torque|v2x)\b"
        ),
        "LIVE_COMMAND_INJECTION_OR_SPOOFING",
    ),
    (
        re.compile(
            r"(?i)\b(disable|defeat|tamper|alter)\b.*"
            r"\b(brake|steering|airbag|stability control|esc|abs|adas|bms|battery safety|"
            r"odometer|emissions|regulatory control|vehicle logging)\b"
        ),
        "SAFETY_OR_REGULATORY_TAMPERING",
    ),
    (
        re.compile(
            r"(?i)\b(track|stalk|locate|surveil|follow)\b.*"
            r"\b(vehicle|car|person|individual|owner|driver|telematics|gps|location)\b"
        ),
        "PRIVATE_TRACKING_OR_STALKING",
    ),
    (
        re.compile(
            r"(?i)\b(access|retrieve|exfiltrate|use)\b.*"
            r"\b(private telematics|owner data|driver data|location history|contacts|voice|vehicle logs)\b"
            r".*\b(without authorization|unauthorized|private)\b"
        ),
        "UNAUTHORIZED_PRIVATE_TELEMATICS",
    ),
    (
        re.compile(
            r"(?i)\b(clone|spoof|forge|alter)\b.*\b(vin|vehicle identity|title|ownership)\b"
        ),
        "VEHICLE_IDENTITY_FRAUD",
    ),
    (
        re.compile(
            r"(?i)\b(remote[- ]control|takeover|hijack|unlock|start|drive)\b.*"
            r"\b(vehicle|car|ecu|telematics)\b"
        ),
        "REMOTE_VEHICLE_CONTROL_OR_TAKEOVER",
    ),
]

NETWORK_TYPES = {
    "CAN", "CAN_FD", "LIN", "FLEXRAY", "AUTOMOTIVE_ETHERNET",
    "MOST", "DOIP", "PROPRIETARY", "OTHER", "UNKNOWN",
}

ECU_TYPES = {
    "ECU", "GATEWAY", "SECURE_GATEWAY", "DOMAIN_CONTROLLER", "ZONAL_CONTROLLER",
    "TCU", "IVI", "ADAS_CONTROLLER", "BMS", "OBC", "INVERTER", "MOTOR_CONTROLLER",
    "ABS_CONTROLLER", "AIRBAG_CONTROLLER", "BODY_CONTROLLER", "KEYLESS_ENTRY_MODULE",
    "CHARGING_CONTROLLER", "V2X_MODULE", "GNSS_MODULE", "MODEM", "SENSOR",
    "ACTUATOR", "OTHER", "UNKNOWN",
}

SAFETY_IMPACT_STATES = {
    "NO_KNOWN_SAFETY_IMPACT", "INDIRECT_SAFETY_RELEVANCE",
    "POTENTIAL_SAFETY_IMPACT", "SAFETY_CRITICAL", "UNKNOWN",
}

APPLICABILITY_STATES = {
    "NOT_ASSESSED", "NOT_APPLICABLE", "POSSIBLY_APPLICABLE",
    "PROBABLY_APPLICABLE", "APPLICABLE_SUPPORTED", "FIXED",
    "MITIGATED", "UNKNOWN",
}

EXPLOIT_AVAILABILITY_STATES = {
    "NO_PUBLIC_EXPLOIT_KNOWN", "POC_REPORTED", "PUBLIC_RESEARCH_EXISTS",
    "EXPLOITATION_REPORTED", "UNKNOWN",
}

REMOTE_EXPLOITABILITY_STATES = {
    "LOCAL_PHYSICAL", "PROXIMITY_REQUIRED", "AUTHORIZED_ACCOUNT_REQUIRED",
    "NETWORK_ADJACENT", "REMOTE_SERVICE_DEPENDENT", "REMOTE_CANDIDATE",
    "REMOTE_SUPPORTED", "UNKNOWN",
}

OTA_STATES = {
    "AVAILABLE", "SCHEDULED", "DOWNLOADED", "VERIFIED",
    "INSTALLED_REPORTED", "INSTALLATION_VERIFIED", "FAILED",
    "ROLLED_BACK", "UNKNOWN",
}

RECALL_STATUSES = {
    "OPEN", "COMPLETED", "PENDING_PARTS", "REMEDIED", "TERMINATED",
    "UNKNOWN",
}

DTC_STATUSES = {
    "CURRENT", "PENDING", "HISTORICAL", "CLEARED", "CONFIRMED",
    "TEST_FAILED", "UNKNOWN",
}

INCIDENT_TYPES = {
    "CYBERSECURITY_EVENT", "FLEET_ANOMALY", "SOFTWARE_FAILURE",
    "OTA_FAILURE", "SERVICE_OUTAGE", "TELEMETRY_ISSUE",
    "COMPONENT_DEFECT", "DIAGNOSTIC_SESSION", "OTHER", "UNKNOWN",
}

INCIDENT_STATES = {
    "NO_CYBER_EVIDENCE", "ANOMALY_OBSERVED", "CYBER_EVENT_CANDIDATE",
    "CYBER_EVENT_SUPPORTED", "MALFUNCTION_CANDIDATE", "INCONCLUSIVE",
}

SOURCE_RELIABILITY: Dict[str, float] = {
    "oem_advisory": 0.90,
    "regulatory_recall": 0.90,
    "supplier_bulletin": 0.86,
    "authorized_ecu_record": 0.86,
    "authorized_diagnostic_export": 0.84,
    "authorized_can_trace": 0.82,
    "authorized_telematics_export": 0.80,
    "official_service_manual": 0.78,
    "public_cve": 0.74,
    "academic_research": 0.68,
    "conference_research": 0.66,
    "commercial_database": 0.58,
    "media_article": 0.45,
    "forum_post": 0.30,
    "unknown": 0.30,
}


# --------------------------------------------------------------------
# Generic helpers
# --------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_id(prefix: str, *parts: Any) -> str:
    raw = "|".join(str(json_safe(p)) for p in parts)
    return f"{prefix}-{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]}"


def json_safe(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [json_safe(x) for x in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
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


def normalize_token(value: Any) -> str:
    s = normalize_text(value).upper()
    s = re.sub(r"[^A-Z0-9]+", "_", s)
    return s.strip("_")


def iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if isinstance(dt, datetime) else None


def parse_time(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    s = normalize_text(value)
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%Y-%m",
        "%Y",
    ):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None


def parse_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    s = normalize_text(value)
    if not s:
        return None
    try:
        return int(float(s))
    except Exception:
        return None


def parse_float(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    s = normalize_text(value).replace(",", "")
    m = re.search(r"[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?", s)
    if not m:
        return None
    try:
        return float(m.group())
    except Exception:
        return None


def source_list(*items: Any) -> List[str]:
    out: List[str] = []
    for it in items:
        if it is None:
            continue
        if isinstance(it, list):
            out.extend(normalize_text(x) for x in it if normalize_text(x))
        else:
            s = normalize_text(it)
            if s:
                out.append(s)
    return list(dict.fromkeys(out))


def unique_preserve(items: Iterable[Any]) -> List[Any]:
    seen: Set[str] = set()
    out = []
    for item in items:
        key = json.dumps(json_safe(item), sort_keys=True, ensure_ascii=False)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def norm_enum(value: Any, allowed: Set[str], default: str = "UNKNOWN") -> str:
    s = normalize_token(value)
    return s if s in allowed else default


def mask_value(value: Any, keep_prefix: int = 2, keep_suffix: int = 2) -> str:
    s = normalize_text(value)
    if not s:
        return ""
    if len(s) <= keep_prefix + keep_suffix:
        return "*" * len(s)
    return s[:keep_prefix] + "*" * (len(s) - keep_prefix - keep_suffix) + s[-keep_suffix:]


def mask_vin(value: Any) -> str:
    s = normalize_text(value).upper()
    if not s:
        return ""
    clean = re.sub(r"[^A-Z0-9]", "", s)
    if len(clean) >= 6:
        return f"REDACTED_VIN_LAST6:{clean[-6:]}"
    return mask_value(clean, 1, 1)


def vin_hash(value: Any) -> Optional[str]:
    s = normalize_text(value).upper()
    if not s:
        return None
    clean = re.sub(r"[^A-Z0-9]", "", s)
    if not clean:
        return None
    return hashlib.sha256(clean.encode("utf-8")).hexdigest()


def days_between(a: Optional[datetime], b: Optional[datetime]) -> Optional[int]:
    if not a or not b:
        return None
    return (b - a).days


def within_time(ts: Optional[datetime], start: Optional[datetime], end: Optional[datetime]) -> bool:
    if ts is None:
        return False
    if start and ts < start:
        return False
    if end and ts > end:
        return False
    return True


def normalize_version(value: Any) -> str:
    return normalize_text(value).lower()


def version_in_list(value: Any, values: Any) -> Optional[bool]:
    v = normalize_version(value)
    if not v or values in (None, "", []):
        return None
    if isinstance(values, str):
        vals = [values]
    elif isinstance(values, list):
        vals = values
    else:
        vals = [str(values)]
    norm = [normalize_text(x).lower() for x in vals if normalize_text(x)]
    if not norm:
        return None
    if v in norm:
        return True
    if any(re.search(r"[-~]|through|to|<|>|=", x) for x in norm):
        return None
    return False


def field_match(left: Any, right: Any) -> Optional[bool]:
    l = normalize_text(left).lower()
    r = normalize_text(right).lower()
    if not l or not r:
        return None
    return l == r


def list_match(values: Any, value: Any) -> Optional[bool]:
    vals = source_list(values)
    v = normalize_text(value).lower()
    if not vals or not v:
        return None
    return v in [normalize_text(x).lower() for x in vals]


# --------------------------------------------------------------------
# Policy / authorization
# --------------------------------------------------------------------

def collect_intent_text(manifest: Dict[str, Any]) -> str:
    parts = [
        normalize_text(manifest.get("objective", "")),
        " ".join(normalize_text(q) for q in manifest.get("questions", []) or []),
        " ".join(normalize_text(x) for x in manifest.get("requested_actions", []) or []),
    ]
    return " ".join(parts)


def policy_screen(manifest: Dict[str, Any]) -> List[str]:
    blob = collect_intent_text(manifest)
    blocked = []
    for pat, label in PROHIBITED_PATTERNS:
        if pat.search(blob):
            blocked.append(label)
    return list(dict.fromkeys(blocked))


def has_safety_critical_data(manifest: Dict[str, Any]) -> bool:
    for e in manifest.get("ecus", []) or []:
        if bool(e.get("safety_critical")):
            return True
    for v in manifest.get("vulnerabilities", []) or manifest.get("vulnerability_data", []) or []:
        if normalize_token(v.get("safety_impact")) == "SAFETY_CRITICAL":
            return True
    for i in manifest.get("incidents", []) or []:
        if normalize_token(i.get("safety_impact")) == "SAFETY_CRITICAL":
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

    mode = auth.get("model_mode", "LOCAL_ONLY")
    if mode not in {"LOCAL_ONLY", "HYBRID", "CLOUD"}:
        reasons.append("UNKNOWN_MODEL_MODE")
    if mode == "CLOUD" and not auth.get("cloud_approved"):
        reasons.append("CLOUD_PROCESSING_NOT_APPROVED")

    vehicle_data_keys = (
        "vehicles", "ecus", "network_architecture", "can_traces",
        "diagnostic_exports", "dtcs", "telematics_data", "ota_metadata",
        "sboms", "firmware_versions", "mobile_apps", "backend_services",
    )
    if any(manifest.get(k) for k in vehicle_data_keys) and not auth.get("vehicle_data_approved"):
        reasons.append("VEHICLE_DATA_NOT_APPROVED")

    if manifest.get("active_testing_requested") and not auth.get("active_testing_approved"):
        reasons.append("ACTIVE_TESTING_NOT_APPROVED")

    if manifest.get("private_telematics_requested") and not auth.get("private_telematics_approved"):
        reasons.append("PRIVATE_TELEMATICS_NOT_APPROVED")

    if has_safety_critical_data(manifest) and not auth.get("safety_review_approved"):
        reasons.append("SAFETY_CRITICAL_HUMAN_REVIEW_REQUIRED")

    return len(reasons) == 0, reasons


# --------------------------------------------------------------------
# Sources / pedigree / independence
# --------------------------------------------------------------------

def collect_referenced_source_ids(obj: Any) -> Set[str]:
    ids: Set[str] = set()

    def walk(x: Any) -> None:
        if isinstance(x, dict):
            for k, v in x.items():
                if k in ("source_id", "source_ids"):
                    if isinstance(v, list):
                        ids.update(normalize_text(i) for i in v if normalize_text(i))
                    else:
                        s = normalize_text(v)
                        if s:
                            ids.add(s)
                walk(v)
        elif isinstance(x, list):
            for i in x:
                walk(i)

    walk(obj)
    return ids


def ingest_sources(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    sources: Dict[str, Dict[str, Any]] = {}
    for s in manifest.get("sources", []) or []:
        sid = normalize_text(s.get("source_id"))
        if not sid:
            continue
        stype = normalize_text(s.get("source_type", "unknown")).lower().replace("-", "_").replace(" ", "_")
        rel = s.get("reliability", SOURCE_RELIABILITY.get(stype, SOURCE_RELIABILITY["unknown"]))
        sources[sid] = {
            "source_id": sid,
            "source_type": stype,
            "upstream_source_id": normalize_text(s.get("upstream_source_id")) or None,
            "reliability": clamp(float(rel)),
            "observed_at": normalize_text(s.get("observed_at")) or None,
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
    else:
        memo[sid] = resolve_source_root(src["upstream_source_id"], sources, memo, visiting)
    visiting.discard(sid)
    return memo[sid]


def build_source_roots(sources: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    memo: Dict[str, str] = {}
    for sid in sources:
        resolve_source_root(sid, sources, memo, set())
    return memo


def source_family_ids(source_ids: List[str], roots: Dict[str, str]) -> List[str]:
    return list(dict.fromkeys(roots.get(sid, sid) for sid in source_ids))


def source_quality(source_ids: List[str], sources: Dict[str, Dict[str, Any]]) -> Tuple[float, float]:
    vals = [float(sources.get(sid, {}).get("reliability", SOURCE_RELIABILITY["unknown"])) for sid in source_ids]
    if not vals:
        return SOURCE_RELIABILITY["unknown"], SOURCE_RELIABILITY["unknown"]
    return max(vals), sum(vals) / len(vals)


def independence_state(families: List[str], sources: Dict[str, Dict[str, Any]], source_ids: List[str]) -> str:
    if not source_ids:
        return "UNKNOWN"
    if len(families) <= 1:
        return "DEPENDENT"
    rels = [sources.get(sid, {}).get("reliability", 0.3) for sid in source_ids]
    types = {sources.get(sid, {}).get("source_type", "unknown") for sid in source_ids}
    if len(types) == 1 and max(rels) < 0.70:
        return "PARTIALLY_DEPENDENT"
    if max(rels) >= 0.70:
        return "INDEPENDENT"
    return "PARTIALLY_DEPENDENT"


def source_assessment(sids: List[str], sources: Dict[str, Dict[str, Any]], roots: Dict[str, str]) -> Dict[str, Any]:
    fams = source_family_ids(sids, roots)
    state = independence_state(fams, sources, sids)
    max_rel, avg_rel = source_quality(sids, sources)
    return {
        "source_ids": sids,
        "source_families": fams,
        "state": state,
        "max_reliability": round(max_rel, 4),
        "avg_reliability": round(avg_rel, 4),
    }


# --------------------------------------------------------------------
# Ingestion
# --------------------------------------------------------------------

def ingest_vehicles(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    vehicles: Dict[str, Dict[str, Any]] = {}
    for idx, v in enumerate(manifest.get("vehicles", []) or []):
        vid = normalize_text(v.get("vehicle_id") or v.get("id") or f"VEHICLE-{idx}")
        vin = normalize_text(v.get("vin_reference") or v.get("vin"))
        vehicles[vid] = {
            "vehicle_id": vid,
            "make": normalize_text(v.get("make")) or None,
            "brand": normalize_text(v.get("brand")) or None,
            "model": normalize_text(v.get("model")) or None,
            "generation": normalize_text(v.get("generation")) or None,
            "model_year": normalize_text(v.get("model_year")) or None,
            "platform": normalize_text(v.get("platform")) or None,
            "body_style": normalize_text(v.get("body_style")) or None,
            "powertrain": normalize_text(v.get("powertrain")) or None,
            "trim": normalize_text(v.get("trim")) or None,
            "variant": normalize_text(v.get("variant")) or None,
            "region": normalize_text(v.get("region")) or None,
            "build_date": parse_time(v.get("build_date")),
            "vin_masked": mask_vin(vin),
            "vin_hash": vin_hash(vin),
            "software_generation": normalize_text(v.get("software_generation")) or None,
            "connectivity_package": normalize_text(v.get("connectivity_package")) or None,
            "adas_package": normalize_text(v.get("adas_package")) or None,
            "source_ids": source_list(v.get("source_ids"), v.get("source_id")),
            "confidence": clamp(float(v.get("confidence", 0.70))),
            "limitations": list(v.get("limitations", []) or []) + [
                "VIN-derived fields are claims until authoritative mapping supports them.",
                "Model is not model year; model year is not build date; platform is not individual vehicle.",
            ],
        }
    return vehicles


def ingest_ecus(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for idx, e in enumerate(manifest.get("ecus", []) or []):
        out.append({
            "ecu_id": normalize_text(e.get("ecu_id") or e.get("id") or f"ECU-{idx}"),
            "vehicle_id": normalize_text(e.get("vehicle_id")) or None,
            "ecu_type": norm_enum(e.get("ecu_type"), ECU_TYPES),
            "manufacturer": normalize_text(e.get("manufacturer")) or None,
            "supplier": normalize_text(e.get("supplier")) or None,
            "oem_part_number": normalize_text(e.get("oem_part_number")) or None,
            "supplier_part_number": normalize_text(e.get("supplier_part_number")) or None,
            "hardware_version": normalize_text(e.get("hardware_version")) or None,
            "software_version": normalize_text(e.get("software_version")) or None,
            "firmware_version": normalize_text(e.get("firmware_version")) or None,
            "bootloader_version": normalize_text(e.get("bootloader_version")) or None,
            "network_interfaces": source_list(e.get("network_interfaces")),
            "diagnostic_interfaces": source_list(e.get("diagnostic_interfaces")),
            "security_features": source_list(e.get("security_features")),
            "safety_critical": bool(e.get("safety_critical")),
            "valid_from": parse_time(e.get("valid_from")),
            "valid_to": parse_time(e.get("valid_to")),
            "source_ids": source_list(e.get("source_ids"), e.get("source_id")),
            "confidence": clamp(float(e.get("confidence", 0.65))),
            "limitations": [
                "ECU function name is not exact ECU implementation.",
                "Part-number family is not exact hardware without revision/version evidence.",
            ],
        })
    return out


def ingest_records(
    manifest: Dict[str, Any],
    key: str,
    id_prefix: str,
    extra_str_fields: Tuple[str, ...] = (),
    extra_list_fields: Tuple[str, ...] = (),
    extra_bool_fields: Tuple[str, ...] = (),
    extra_time_fields: Tuple[str, ...] = (),
    extra_int_fields: Tuple[str, ...] = (),
    extra_float_fields: Tuple[str, ...] = (),
) -> List[Dict[str, Any]]:
    out = []
    for idx, r in enumerate(manifest.get(key, []) or []):
        rec = {
            "record_id": normalize_text(r.get("id") or r.get(f"{id_prefix.lower()}_id")) or f"{id_prefix}-{idx}",
            "vehicle_id": normalize_text(r.get("vehicle_id")) or None,
            "ecu_id": normalize_text(r.get("ecu_id")) or None,
            "source_ids": source_list(r.get("source_ids"), r.get("source_id")),
            "confidence": clamp(float(r.get("confidence", 0.60))),
        }
        for f in extra_str_fields:
            rec[f] = normalize_text(r.get(f)) or None
        for f in extra_list_fields:
            rec[f] = source_list(r.get(f))
        for f in extra_bool_fields:
            rec[f] = bool(r.get(f)) if r.get(f) is not None else None
        for f in extra_time_fields:
            rec[f] = parse_time(r.get(f))
        for f in extra_int_fields:
            rec[f] = parse_int(r.get(f))
        for f in extra_float_fields:
            rec[f] = parse_float(r.get(f))
        out.append(rec)
    return out


def index_by_vehicle(records: List[Dict[str, Any]], valid_ids: Set[str], record_type: str) -> Tuple[Dict[str, List[Dict[str, Any]]], List[Dict[str, Any]]]:
    d: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    unknown = []
    for r in records:
        vid = r.get("vehicle_id")
        if vid and vid in valid_ids:
            d[vid].append(r)
        else:
            unknown.append({
                "record_type": record_type,
                "record_id": r.get("record_id"),
                "vehicle_id": vid,
                "ecu_id": r.get("ecu_id"),
            })
    return d, unknown


def determine_as_of(
    manifest: Dict[str, Any],
    vehicles: Dict[str, Dict[str, Any]],
    all_records: Dict[str, List[Dict[str, Any]]],
    sources: Dict[str, Dict[str, Any]],
) -> Optional[datetime]:
    candidates: List[datetime] = []
    as_of = parse_time((manifest.get("time_range") or {}).get("as_of"))
    if as_of:
        candidates.append(as_of)
    for v in vehicles.values():
        for k in ("build_date",):
            dt = v.get(k)
            if isinstance(dt, datetime):
                candidates.append(dt)
    date_keys = (
        "timestamp", "occurred_at", "first_seen", "cleared_at",
        "effective_at", "installed_at", "generated_at", "valid_from",
        "valid_to", "start", "end", "observed_at",
    )
    for recs in all_records.values():
        for r in recs:
            for k in date_keys:
                dt = r.get(k)
                if isinstance(dt, datetime):
                    candidates.append(dt)
    for s in sources.values():
        dt = parse_time(s.get("observed_at"))
        if dt:
            candidates.append(dt)
    return max(candidates) if candidates else None


# --------------------------------------------------------------------
# Assessment
# --------------------------------------------------------------------

def assess_vehicle_identity(v: Dict[str, Any], sa: Dict[str, Any]) -> Dict[str, Any]:
    max_rel = float(sa.get("max_reliability", 0.0))

    def state(field: str, threshold: float = 0.80) -> str:
        if not v.get(field):
            return "UNKNOWN"
        return "SUPPORTED" if max_rel >= threshold else "CANDIDATE"

    return {
        "make_state": state("make"),
        "model_state": state("model"),
        "model_year_state": state("model_year"),
        "generation_state": state("generation"),
        "platform_state": state("platform"),
        "trim_state": state("trim"),
        "variant_state": state("variant"),
        "region_state": state("region"),
        "powertrain_state": state("powertrain"),
        "vin_privacy_state": "REDACTED_BY_DEFAULT",
        "source_assessment": sa,
        "limitations": [
            "VIN is privacy-sensitive and masked in normal reports.",
            "VIN does not identify owner/driver automatically.",
        ],
    }


def assess_ecu(e: Dict[str, Any], sa: Dict[str, Any]) -> Dict[str, Any]:
    max_rel = float(sa.get("max_reliability", 0.0))

    def state(field: str, threshold: float = 0.80) -> str:
        if not e.get(field):
            return "UNKNOWN"
        return "SUPPORTED" if max_rel >= threshold else "CANDIDATE"

    part_state = "UNKNOWN"
    if e.get("oem_part_number") or e.get("supplier_part_number"):
        part_state = "SUPPORTED" if max_rel >= 0.80 else "CANDIDATE"

    return {
        "ecu_type_state": state("ecu_type"),
        "manufacturer_state": state("manufacturer"),
        "supplier_state": state("supplier"),
        "part_number_state": part_state,
        "hardware_version_state": state("hardware_version"),
        "software_version_state": state("software_version"),
        "firmware_version_state": state("firmware_version"),
        "bootloader_version_state": state("bootloader_version"),
        "safety_critical": bool(e.get("safety_critical")),
        "source_assessment": sa,
        "limitations": [
            "ECU class/name is not exact implementation.",
            "Hardware revision and software/firmware version affect applicability.",
        ],
    }


def assess_recall(rec: Dict[str, Any], vehicle: Dict[str, Any], sa: Dict[str, Any]) -> Dict[str, Any]:
    matches: List[Optional[bool]] = []
    if rec.get("oem"):
        matches.append(field_match(rec.get("oem"), vehicle.get("make")))
    if rec.get("makes"):
        matches.append(list_match(rec.get("makes"), vehicle.get("make")))
    if rec.get("models"):
        matches.append(list_match(rec.get("models"), vehicle.get("model")))
    if rec.get("model_years"):
        matches.append(list_match(rec.get("model_years"), vehicle.get("model_year")))
    if rec.get("variants"):
        matches.append(list_match(rec.get("variants"), vehicle.get("variant")))
    if rec.get("regions"):
        matches.append(list_match(rec.get("regions"), vehicle.get("region")))

    direct = bool(rec.get("vehicle_id") and rec.get("vehicle_id") == vehicle.get("vehicle_id"))

    if direct:
        state = "APPLICABLE_SUPPORTED" if sa.get("max_reliability", 0) >= 0.80 else "PROBABLY_APPLICABLE"
        reason = "Direct vehicle-scoped recall record supplied."
    elif not matches:
        state = "UNKNOWN"
        reason = "Recall lacks sufficient vehicle identity fields for applicability."
    elif any(x is False for x in matches):
        state = "NOT_APPLICABLE"
        reason = "At least one recall identity field mismatches vehicle record."
    elif all(x is True for x in matches):
        if rec.get("vin_range_start") or rec.get("vin_range_end"):
            state = "APPLICABLE_PENDING_VIN_RANGE"
            reason = "Model/year/variant fields match, but VIN range applicability is unresolved."
        else:
            state = "APPLICABLE_SUPPORTED" if sa.get("max_reliability", 0) >= 0.80 else "PROBABLY_APPLICABLE"
            reason = "Recall identity fields match vehicle record."
    elif any(x is True for x in matches):
        state = "POSSIBLY_APPLICABLE"
        reason = "Partial recall identity match; exact applicability unresolved."
    else:
        state = "UNKNOWN"
        reason = "Insufficient recall identity evidence."

    return {
        **rec,
        "applicability_state": state,
        "applicability_reason": reason,
        "field_matches": matches,
        "source_assessment": sa,
        "limitations": [
            "Recall is not automatically a cybersecurity vulnerability.",
            "Model-family match is not individual-vehicle match without VIN range/variant evidence.",
        ],
    }


def assess_tsb(rec: Dict[str, Any], vehicle: Dict[str, Any], sa: Dict[str, Any]) -> Dict[str, Any]:
    matches = []
    if rec.get("models"):
        matches.append(list_match(rec.get("models"), vehicle.get("model")))
    if rec.get("model_years"):
        matches.append(list_match(rec.get("model_years"), vehicle.get("model_year")))
    if rec.get("variants"):
        matches.append(list_match(rec.get("variants"), vehicle.get("variant")))

    if not matches:
        state = "UNKNOWN"
    elif any(x is False for x in matches):
        state = "NOT_APPLICABLE"
    elif all(x is True for x in matches):
        state = "APPLICABLE_SUPPORTED" if sa.get("max_reliability", 0) >= 0.80 else "PROBABLY_APPLICABLE"
    else:
        state = "POSSIBLY_APPLICABLE"

    return {
        **rec,
        "applicability_state": state,
        "field_matches": matches,
        "source_assessment": sa,
        "limitations": [
            "TSB is not a safety recall confirmation.",
            "Service bulletin may describe known issue, diagnostic procedure, or repair.",
        ],
    }


def assess_vulnerability_for_ecu(
    vuln: Dict[str, Any],
    ecu: Dict[str, Any],
    vehicle: Dict[str, Any],
    sa: Dict[str, Any],
) -> Dict[str, Any]:
    checks = [
        field_match(vuln.get("vendor"), ecu.get("manufacturer")),
        field_match(vuln.get("supplier"), ecu.get("supplier")),
        field_match(vuln.get("product"), ecu.get("ecu_type")),
        field_match(vuln.get("component"), ecu.get("oem_part_number")),
        field_match(vuln.get("component"), ecu.get("supplier_part_number")),
    ]
    versions = [ecu.get("software_version"), ecu.get("firmware_version")]
    affected = any(version_in_list(x, vuln.get("affected_versions")) is True for x in versions if x)
    fixed = any(version_in_list(x, vuln.get("fixed_versions")) is True for x in versions if x)

    if fixed:
        state = "FIXED"
        reason = "Installed software/firmware matches a fixed version in supplied vulnerability record."
    elif any(x is False for x in checks):
        state = "NOT_APPLICABLE"
        reason = "Vendor/supplier/product/component mismatch against ECU record."
    elif affected and any(x is True for x in checks):
        state = "APPLICABLE_SUPPORTED" if sa.get("max_reliability", 0) >= 0.82 else "PROBABLY_APPLICABLE"
        reason = "Component and affected version fields match ECU record; configuration/reachability still require validation."
    elif affected:
        state = "PROBABLY_APPLICABLE"
        reason = "Affected version matches, but component identity evidence is partial."
    elif any(x is True for x in checks):
        state = "POSSIBLY_APPLICABLE"
        reason = "Component identity partially matches, but version evidence is incomplete or range-based."
    else:
        state = "UNKNOWN"
        reason = "Insufficient ECU component/version evidence."

    safety = norm_enum(vuln.get("safety_impact"), SAFETY_IMPACT_STATES)
    if safety == "UNKNOWN" and ecu.get("safety_critical"):
        safety = "POTENTIAL_SAFETY_IMPACT"

    remote = norm_enum(vuln.get("remote_exploitability"), REMOTE_EXPLOITABILITY_STATES)

    return {
        "vulnerability_id": vuln.get("record_id"),
        "cve": vuln.get("cve"),
        "vehicle_id": vehicle.get("vehicle_id"),
        "ecu_id": ecu.get("ecu_id"),
        "applicability_state": state,
        "applicability_reason": reason,
        "safety_impact": safety,
        "remote_exploitability": remote,
        "exploit_availability": norm_enum(vuln.get("exploit_availability"), EXPLOIT_AVAILABILITY_STATES),
        "known_exploitation_reported": bool(vuln.get("known_exploitation_reported")),
        "kev": bool(vuln.get("kev")),
        "epss": vuln.get("epss"),
        "mitigations": vuln.get("mitigations", []),
        "source_assessment": sa,
        "limitations": [
            "CVE/advisory is not vehicle vulnerability without exact component/version/configuration evidence.",
            "Vulnerability is not exploitation.",
            "Public PoC/research is not field exploitation.",
            "Physical-access research is not remote compromise.",
        ],
    }


def assess_vulnerabilities_for_vehicle(
    global_vulns: List[Dict[str, Any]],
    vehicle: Dict[str, Any],
    ecu_rows: List[Dict[str, Any]],
    ecus_by_id: Dict[str, Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
    roots: Dict[str, str],
) -> List[Dict[str, Any]]:
    rows = []
    ecu_ids = {e.get("ecu_id") for e in ecu_rows}
    for v in global_vulns:
        sa = source_assessment(v.get("source_ids", []), sources, roots)
        target_ecus: List[Dict[str, Any]] = []
        if v.get("ecu_id") and v.get("ecu_id") in ecus_by_id:
            ecu = ecus_by_id[v["ecu_id"]]
            if ecu.get("vehicle_id") == vehicle.get("vehicle_id") or not ecu.get("vehicle_id"):
                target_ecus.append(ecu)
        elif v.get("vehicle_id") == vehicle.get("vehicle_id"):
            target_ecus = [e for e in ecu_rows if e.get("ecu_id") in ecu_ids]

        for ecu in target_ecus:
            rows.append(assess_vulnerability_for_ecu(v, ecu, vehicle, sa))

        if not target_ecus and (v.get("vehicle_id") == vehicle.get("vehicle_id") or v.get("ecu_id") in ecu_ids):
            rows.append({
                "vulnerability_id": v.get("record_id"),
                "cve": v.get("cve"),
                "vehicle_id": vehicle.get("vehicle_id"),
                "ecu_id": v.get("ecu_id"),
                "applicability_state": "UNKNOWN",
                "applicability_reason": "Vulnerability references vehicle/ECU but exact installed component/version evidence is insufficient.",
                "safety_impact": norm_enum(v.get("safety_impact"), SAFETY_IMPACT_STATES),
                "remote_exploitability": norm_enum(v.get("remote_exploitability"), REMOTE_EXPLOITABILITY_STATES),
                "exploit_availability": norm_enum(v.get("exploit_availability"), EXPLOIT_AVAILABILITY_STATES),
                "known_exploitation_reported": bool(v.get("known_exploitation_reported")),
                "kev": bool(v.get("kev")),
                "epss": v.get("epss"),
                "mitigations": v.get("mitigations", []),
                "source_assessment": sa,
                "limitations": ["CVE is not vehicle vulnerability without applicability evidence."],
            })
    return rows


def assess_ota(ota: Dict[str, Any], ecu_rows: List[Dict[str, Any]], ecus_by_id: Dict[str, Dict[str, Any]], sa: Dict[str, Any]) -> Dict[str, Any]:
    ecu = None
    if ota.get("ecu_id") and ota.get("ecu_id") in ecus_by_id:
        ecu = ecus_by_id[ota["ecu_id"]]
    else:
        for e in ecu_rows:
            if e.get("ecu_id") == ota.get("ecu_id"):
                ecu = e
                break

    state = norm_enum(ota.get("state"), OTA_STATES)
    installed = state in {"INSTALLED_REPORTED", "INSTALLATION_VERIFIED"}
    verified = state == "INSTALLATION_VERIFIED" or bool(ota.get("installation_verified"))

    version_conflict = None
    if ecu and verified and ota.get("target_version") and ecu.get("software_version"):
        if normalize_version(ota["target_version"]) != normalize_version(ecu["software_version"]):
            version_conflict = {
                "type": "OTA_VERIFIED_VERSION_VS_ECU_SOFTWARE_CONFLICT",
                "ota_target_version": ota.get("target_version"),
                "ecu_software_version": ecu.get("software_version"),
            }

    return {
        **ota,
        "ota_state": state,
        "installed": installed,
        "installation_verified": verified,
        "available_not_installed": state in {"AVAILABLE", "SCHEDULED", "DOWNLOADED", "VERIFIED"},
        "version_conflict": version_conflict,
        "source_assessment": sa,
        "limitations": [
            "OTA available does not prove installed.",
            "OTA installed-reported does not prove verified.",
        ],
    }


def maintenance_context(ts: Optional[datetime], maintenance: List[Dict[str, Any]]) -> str:
    for m in maintenance:
        if within_time(ts, m.get("start"), m.get("end")):
            if m.get("approved") is True:
                return "SUPPORTED"
            return "CANDIDATE"
    return "NONE"


def assess_can(frames: List[Dict[str, Any]], maintenance: List[Dict[str, Any]], as_of: Optional[datetime]) -> Dict[str, Any]:
    unknown_ids = []
    anomalies = []
    id_counts = Counter()
    bus_counts = Counter()
    for f in frames:
        cid = f.get("can_id")
        if cid is not None:
            id_counts[cid] += 1
        if f.get("bus"):
            bus_counts[f["bus"]] += 1
        if normalize_token(f.get("decode_status")) == "UNKNOWN":
            unknown_ids.append(cid)
        if bool(f.get("anomaly")) or f.get("baseline_expected") is False:
            mctx = maintenance_context(f.get("timestamp"), maintenance)
            if mctx == "SUPPORTED":
                status = "EXPLAINED_BY_MAINTENANCE"
            elif mctx == "CANDIDATE":
                status = "MAINTENANCE_CANDIDATE"
            else:
                status = "ANOMALY_CANDIDATE"
            anomalies.append({
                "record_id": f.get("record_id"),
                "timestamp": f.get("timestamp"),
                "can_id": cid,
                "bus": f.get("bus"),
                "decode_status": f.get("decode_status"),
                "dbc_version": f.get("dbc_version"),
                "status": status,
                "maintenance_context": mctx,
            })

    return {
        "frame_count": len(frames),
        "id_counts": {str(k): v for k, v in id_counts.items()},
        "bus_counts": dict(bus_counts),
        "unknown_can_ids": list(dict.fromkeys([x for x in unknown_ids if x is not None])),
        "anomalies": anomalies,
        "dbc_coverage": "PARTIAL" if any(f.get("dbc_version") for f in frames) and unknown_ids else ("FULL" if frames and not unknown_ids else "UNKNOWN"),
        "limitations": [
            "CAN ID is not human-readable command semantics without trusted DBC/mapping.",
            "Unknown message means mapping incomplete, not malicious.",
            "No deployment-ready control frames are generated.",
        ],
    }


def assess_dtcs(dtcs: List[Dict[str, Any]], as_of: Optional[datetime]) -> Dict[str, Any]:
    items = []
    current = []
    pending = []
    historical = []
    for d in dtcs:
        status = norm_enum(d.get("status"), DTC_STATUSES)
        cleared = d.get("cleared_at")
        first = d.get("first_seen")
        is_current = status == "CURRENT" and (not cleared or (as_of and cleared >= as_of))
        is_pending = status == "PENDING"
        is_historical = bool(cleared and as_of and cleared < as_of) or status in {"HISTORICAL", "CLEARED"}
        if is_current:
            current.append(d.get("record_id"))
        elif is_pending:
            pending.append(d.get("record_id"))
        elif is_historical:
            historical.append(d.get("record_id"))
        items.append({
            **d,
            "normalized_status": status,
            "current": is_current,
            "pending": is_pending,
            "historical": is_historical,
        })
    return {
        "items": items,
        "current_dtcs": current,
        "pending_dtcs": pending,
        "historical_dtcs": historical,
        "limitations": [
            "DTC indicates detected condition, not confirmed root cause.",
            "Old DTC is not current failure without status/history evidence.",
        ],
    }


def assess_incident(
    inc: Dict[str, Any],
    vehicle: Dict[str, Any],
    ecu_rows: List[Dict[str, Any]],
    vuln_rows: List[Dict[str, Any]],
    ota_rows: List[Dict[str, Any]],
    can: Dict[str, Any],
    dtcs: Dict[str, Any],
    maintenance: List[Dict[str, Any]],
    as_of: Optional[datetime],
    sa: Dict[str, Any],
) -> Dict[str, Any]:
    mctx = maintenance_context(inc.get("occurred_at"), maintenance)
    state = "NO_CYBER_EVIDENCE"
    if bool(inc.get("vehicle_side_confirmation")):
        state = "CYBER_EVENT_SUPPORTED" if bool(inc.get("cyber_claim")) else "ANOMALY_OBSERVED"
    elif bool(inc.get("cyber_claim")):
        state = "CYBER_EVENT_CANDIDATE"
    elif bool(inc.get("backend_event_accepted")) and not bool(inc.get("vehicle_side_confirmation")):
        state = "INCONCLUSIVE"
    elif bool(inc.get("malfunction_candidate")) or bool(inc.get("maintenance_candidate")) or mctx != "NONE":
        state = "MALFUNCTION_CANDIDATE"
    elif can.get("anomalies") or dtcs.get("current_dtcs"):
        state = "ANOMALY_OBSERVED"

    safety = norm_enum(inc.get("safety_impact"), SAFETY_IMPACT_STATES)
    involved_ecu_ids = source_list(inc.get("involved_ecu_ids"))
    if safety == "UNKNOWN":
        if any(e.get("safety_critical") and e.get("ecu_id") in involved_ecu_ids for e in ecu_rows):
            safety = "POTENTIAL_SAFETY_IMPACT"
        elif any(e.get("safety_critical") for e in ecu_rows if not involved_ecu_ids):
            safety = "UNKNOWN"

    backend_not_executed = bool(inc.get("backend_event_accepted")) and not bool(inc.get("vehicle_side_confirmation"))

    return {
        **inc,
        "incident_state": state,
        "maintenance_context": mctx,
        "safety_impact": safety,
        "backend_event_not_vehicle_execution": backend_not_executed,
        "source_assessment": sa,
        "limitations": [
            "Incident is not automatically cyberattack.",
            "Backend event acceptance does not prove vehicle execution.",
            "Malfunction may be hardware, software bug, configuration, maintenance, environmental, or cyber.",
        ],
    }


def assess_vehicle_case(
    vehicle: Dict[str, Any],
    records_by_vehicle: Dict[str, Dict[str, List[Dict[str, Any]]]],
    fleets_by_vehicle: Dict[str, List[Dict[str, Any]]],
    ecus_by_id: Dict[str, Dict[str, Any]],
    global_vulns: List[Dict[str, Any]],
    maintenance_by_vehicle: Dict[str, List[Dict[str, Any]]],
    sources: Dict[str, Dict[str, Any]],
    roots: Dict[str, str],
    as_of: Optional[datetime],
) -> Dict[str, Any]:
    vid = vehicle["vehicle_id"]
    v_sa = source_assessment(vehicle.get("source_ids", []), sources, roots)
    identity = assess_vehicle_identity(vehicle, v_sa)

    ecu_rows = []
    for e in records_by_vehicle["ecus"].get(vid, []):
        esa = source_assessment(e.get("source_ids", []), sources, roots)
        ecu_rows.append({**e, "assessment": assess_ecu(e, esa)})

    networks = []
    for n in records_by_vehicle["networks"].get(vid, []):
        nsa = source_assessment(n.get("source_ids", []), sources, roots)
        networks.append({
            **n,
            "assessment": {
                "network_type": norm_enum(n.get("network_type"), NETWORK_TYPES),
                "observed": True,
                "source_assessment": nsa,
                "limitations": ["Network architecture observation is not attack-path generation."],
            },
        })

    can = assess_can(records_by_vehicle["can_frames"].get(vid, []), maintenance_by_vehicle.get(vid, []), as_of)
    dtcs = assess_dtcs(records_by_vehicle["dtcs"].get(vid, []), as_of)

    recalls = []
    for r in records_by_vehicle["recalls"].get(vid, []):
        rsa = source_assessment(r.get("source_ids", []), sources, roots)
        recalls.append(assess_recall(r, vehicle, rsa))

    tsbs = []
    for t in records_by_vehicle["tsbs"].get(vid, []):
        tsa = source_assessment(t.get("source_ids", []), sources, roots)
        tsbs.append(assess_tsb(t, vehicle, tsa))

    service_campaigns = records_by_vehicle["service_campaigns"].get(vid, [])

    vulns = assess_vulnerabilities_for_vehicle(global_vulns, vehicle, ecu_rows, ecus_by_id, sources, roots)

    otas = []
    for o in records_by_vehicle["otas"].get(vid, []):
        osa = source_assessment(o.get("source_ids", []), sources, roots)
        otas.append(assess_ota(o, ecu_rows, ecus_by_id, osa))

    incidents = []
    for i in records_by_vehicle["incidents"].get(vid, []):
        isa = source_assessment(i.get("source_ids", []), sources, roots)
        incidents.append(assess_incident(i, vehicle, ecu_rows, vulns, otas, can, dtcs, maintenance_by_vehicle.get(vid, []), as_of, isa))

    mobile_apps = records_by_vehicle["mobile_apps"].get(vid, [])
    backend_services = records_by_vehicle["backend_services"].get(vid, [])
    cloud_dependencies = records_by_vehicle["cloud_dependencies"].get(vid, [])
    telematics_context = records_by_vehicle["telematics_context"].get(vid, [])
    certificates = records_by_vehicle["certificates"].get(vid, [])
    sboms = records_by_vehicle["sboms"].get(vid, [])
    fleet_context = fleets_by_vehicle.get(vid, [])

    suppliers = []
    for e in ecu_rows:
        if e.get("manufacturer"):
            suppliers.append({"role": "MANUFACTURER", "name": e["manufacturer"], "ecu_id": e.get("ecu_id")})
        if e.get("supplier"):
            suppliers.append({"role": "SUPPLIER", "name": e["supplier"], "ecu_id": e.get("ecu_id")})
    suppliers = unique_preserve(suppliers)

    safety_flags = []
    if any(e.get("safety_critical") for e in ecu_rows):
        safety_flags.append("Safety-critical ECU present; analysis-only and qualified human safety review required.")
    if any(v.get("safety_impact") in {"POTENTIAL_SAFETY_IMPACT", "SAFETY_CRITICAL"} for v in vulns):
        safety_flags.append("Vulnerability context includes potential or safety-critical impact; do not inflate or operationalize.")
    if any(i.get("safety_impact") in {"POTENTIAL_SAFETY_IMPACT", "SAFETY_CRITICAL"} for i in incidents):
        safety_flags.append("Incident context includes potential safety impact; correlate with authorized functional-safety evidence.")

    privacy_flags = [
        "VIN masked by default.",
        "No private-person owner/driver inference performed.",
        "No vehicle location tracking or private telematics retrieval performed.",
        "Paired device is not driver/owner identity.",
    ]

    applicable_vulns = [v for v in vulns if v.get("applicability_state") in {
        "APPLICABLE_SUPPORTED", "PROBABLY_APPLICABLE", "POSSIBLY_APPLICABLE"
    }]
    open_recalls = [r for r in recalls if r.get("applicability_state") in {
        "APPLICABLE_SUPPORTED", "PROBABLY_APPLICABLE", "POSSIBLY_APPLICABLE", "APPLICABLE_PENDING_VIN_RANGE"
    } and normalize_token(r.get("status")) not in {"COMPLETED", "REMEDIED"}]
    unverified_ota = [o for o in otas if not o.get("installation_verified")]
    incident_state = incidents[0]["incident_state"] if incidents else "NO_INCIDENT_PROVIDED"

    risk_dimensions = {
        "vehicle_identity_confidence": identity.get("source_assessment", {}).get("max_reliability", 0.0),
        "safety_critical_ecu_present": any(e.get("safety_critical") for e in ecu_rows),
        "vulnerability_applicability": "PRESENT_PENDING_VALIDATION" if applicable_vulns else "NONE_PROVIDED",
        "recall_exposure": "PRESENT_PENDING_REMEDY" if open_recalls else ("NONE_PROVIDED" if recalls else "UNKNOWN"),
        "patch_ota_state": "UNVERIFIED" if unverified_ota else ("VERIFIED" if otas else "UNKNOWN"),
        "incident_state": incident_state,
        "can_unknown_mapping": bool(can.get("unknown_can_ids")),
        "connectivity_surface_present": bool(telematics_context or mobile_apps or backend_services or cloud_dependencies),
        "privacy_sensitivity": "VEHICLE_IDENTITY_AND_TELEMATICS_SENSITIVE",
    }

    return {
        "vehicle": vehicle,
        "identity_resolution": identity,
        "ecus": ecu_rows,
        "networks": networks,
        "can_context": can,
        "dtcs": dtcs,
        "recalls": recalls,
        "tsbs": tsbs,
        "service_campaigns": service_campaigns,
        "vulnerabilities": vulns,
        "otas": otas,
        "incidents": incidents,
        "mobile_apps": mobile_apps,
        "backend_services": backend_services,
        "cloud_dependencies": cloud_dependencies,
        "telematics_context": telematics_context,
        "certificates": certificates,
        "sboms": sboms,
        "suppliers": suppliers,
        "fleet_context": fleet_context,
        "safety_flags": safety_flags,
        "privacy_flags": privacy_flags,
        "risk_dimensions": risk_dimensions,
        "limitations": [
            "Passive/authorized evidence analysis only; no live vehicle interaction performed.",
            "Vehicle identity, ECU implementation, version, network semantics, vulnerability applicability, recall applicability, OTA state, and incident cause are separate claims.",
        ],
    }


# --------------------------------------------------------------------
# Contradictions / hypotheses / gaps / actions / handoffs
# --------------------------------------------------------------------

def detect_contradictions(
    cases: List[Dict[str, Any]],
    unknown_refs: List[Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
    roots: Dict[str, str],
    as_of: Optional[datetime],
) -> List[Dict[str, Any]]:
    contr: List[Dict[str, Any]] = []

    for ur in unknown_refs:
        contr.append({
            "contradiction_id": stable_id("CTR", "unknown_ref", ur.get("record_type"), ur.get("record_id"), ur.get("vehicle_id"), ur.get("ecu_id")),
            "type": "RECORD_REFERENCES_UNKNOWN_VEHICLE_OR_ECU",
            "severity": "MATERIAL",
            "detail": f"{ur.get('record_type')} record {ur.get('record_id')} references unknown vehicle_id={ur.get('vehicle_id')} or ecu_id={ur.get('ecu_id')}.",
            "possible_causes": ["stale inventory", "record typo", "new ECU", "service replacement", "data error"],
        })

    for case in cases:
        vid = case["vehicle"]["vehicle_id"]
        ecu_by_id = {e.get("ecu_id"): e for e in case.get("ecus", [])}

        for o in case.get("otas", []):
            if o.get("version_conflict"):
                contr.append({
                    "contradiction_id": stable_id("CTR", "ota_version", vid, o.get("record_id")),
                    "type": o["version_conflict"]["type"],
                    "severity": "MATERIAL",
                    "vehicle_id": vid,
                    "ecu_id": o.get("ecu_id"),
                    "detail": json_safe(o["version_conflict"]),
                    "possible_causes": ["OTA not actually installed", "ECU inventory stale", "wrong target ECU", "partial update", "data error"],
                })

        for r in case.get("recalls", []):
            if r.get("applicability_state") in {"APPLICABLE_SUPPORTED", "PROBABLY_APPLICABLE"} and any(x is False for x in r.get("field_matches", [])):
                contr.append({
                    "contradiction_id": stable_id("CTR", "recall_match", vid, r.get("record_id")),
                    "type": "RECALL_APPLICABILITY_MATCH_CONFLICT",
                    "severity": "MATERIAL",
                    "vehicle_id": vid,
                    "recall_id": r.get("record_id"),
                    "detail": "Recall marked applicable despite at least one mismatching identity field.",
                    "possible_causes": ["regional variant", "mid-year change", "data error", "overbroad mapping"],
                })

        for v in case.get("vulnerabilities", []):
            if v.get("applicability_state") in {"APPLICABLE_SUPPORTED", "PROBABLY_APPLICABLE"} and v.get("remote_exploitability") == "LOCAL_PHYSICAL":
                contr.append({
                    "contradiction_id": stable_id("CTR", "remote_local", vid, v.get("vulnerability_id"), v.get("ecu_id")),
                    "type": "REMOTE_CLAIM_WITH_LOCAL_PHYSICAL_PREREQUISITE",
                    "severity": "MEDIUM",
                    "vehicle_id": vid,
                    "ecu_id": v.get("ecu_id"),
                    "detail": "Vulnerability applicability is elevated but supplied exploitability is local/physical; do not describe as remote compromise.",
                    "possible_causes": ["advisory wording ambiguity", "research lab setup", "missing prerequisite context"],
                })

        for i in case.get("incidents", []):
            if i.get("backend_event_not_vehicle_execution"):
                contr.append({
                    "contradiction_id": stable_id("CTR", "backend_execution", vid, i.get("record_id")),
                    "type": "BACKEND_EVENT_WITHOUT_VEHICLE_SIDE_CONFIRMATION",
                    "severity": "MATERIAL",
                    "vehicle_id": vid,
                    "incident_id": i.get("record_id"),
                    "detail": "Backend/service event accepted but no vehicle-side execution evidence supplied.",
                    "possible_causes": ["command failed before vehicle", "telemetry gap", "gateway filtered", "data error"],
                })
            if i.get("cyber_claim") and not i.get("vehicle_side_confirmation"):
                contr.append({
                    "contradiction_id": stable_id("CTR", "cyber_claim", vid, i.get("record_id")),
                    "type": "CYBER_CLAIM_WITHOUT_VEHICLE_SIDE_EVIDENCE",
                    "severity": "MATERIAL",
                    "vehicle_id": vid,
                    "incident_id": i.get("record_id"),
                    "detail": "Incident claims cyber activity but lacks vehicle-side confirmation.",
                    "possible_causes": ["misclassified alert", "malfunction", "maintenance", "backend-only event"],
                })

        for d in case.get("dtcs", {}).get("items", []):
            if d.get("normalized_status") == "CURRENT" and d.get("cleared_at") and as_of and d["cleared_at"] < as_of:
                contr.append({
                    "contradiction_id": stable_id("CTR", "dtc_status", vid, d.get("record_id")),
                    "type": "DTC_CURRENT_VS_CLEARED_CONFLICT",
                    "severity": "MEDIUM",
                    "vehicle_id": vid,
                    "dtc_id": d.get("record_id"),
                    "detail": "DTC marked current but cleared_at is before as-of date.",
                    "possible_causes": ["status not refreshed", "intermittent fault", "clear/repopulate", "data error"],
                })

        if case.get("can_context", {}).get("unknown_can_ids") and case.get("can_context", {}).get("dbc_coverage") == "FULL":
            contr.append({
                "contradiction_id": stable_id("CTR", "can_dbc", vid),
                "type": "UNKNOWN_CAN_IDS_WITH_FULL_DBC_CLAIM",
                "severity": "MEDIUM",
                "vehicle_id": vid,
                "detail": "Unknown CAN IDs observed while DBC coverage is marked full.",
                "possible_causes": ["wrong DBC version", "new ECU", "diagnostic traffic", "gateway/proxy", "data error"],
            })

    return unique_preserve(contr)


def build_hypotheses(cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    hyp: List[Dict[str, Any]] = []

    def add(subject_type: str, subject_id: str, category: str, statement: str,
            support: List[str], opposition: List[str], unknowns: List[str],
            falsify: List[str]) -> None:
        hyp.append({
            "hypothesis_id": stable_id("HYP", subject_type, subject_id, category),
            "subject_type": subject_type,
            "subject_id": subject_id,
            "category": category,
            "statement": statement,
            "support": support,
            "opposition": opposition,
            "unknowns": unknowns,
            "falsification_conditions": falsify,
            "status": "CANDIDATE",
        })

    for case in cases:
        vid = case["vehicle"]["vehicle_id"]
        for e in case.get("ecus", []):
            eid = e.get("ecu_id")
            add("ECU", eid, "VULNERABLE_ECU_VERSION_PRESENT",
                "ECU may contain affected software/firmware version.",
                [f"software={e.get('software_version')}", f"firmware={e.get('firmware_version')}"],
                ["Service replacement, later revision, or patched build possible."],
                ["exact part revision", "calibration", "patch state"],
                ["Authorized ECU inventory or diagnostic export confirms fixed/unaffected version."])
            add("ECU", eid, "FIXED_OR_REPLACED_REVISION",
                "ECU may have been updated or replaced after manufacture.",
                ["service/OTA/recall history can change ECU state"],
                ["no update/replacement evidence"],
                ["workshop records", "OTA logs", "part supersession"],
                ["Authoritative version evidence shows affected version still installed."])

        for v in case.get("vulnerabilities", []):
            vidu = v.get("vulnerability_id")
            eid = v.get("ecu_id")
            state = v.get("applicability_state")
            if state in {"UNKNOWN", "POSSIBLY_APPLICABLE", "PROBABLY_APPLICABLE"}:
                add("VULNERABILITY", f"{vid}:{eid}:{vidu}", "APPLICABLE_WITH_COMPENSATING_CONTROLS",
                    "Vulnerability may apply but segmentation/gateway/disabled feature/patch status may reduce practical risk.",
                    [f"applicability={state}"],
                    ["Exact configuration/reachability unknown."],
                    ["gateway rules", "service exposure", "feature state"],
                    ["Authorized configuration review confirms not reachable/not enabled."])
                add("VULNERABILITY", f"{vid}:{eid}:{vidu}", "NOT_APPLICABLE_TO_THIS_VARIANT",
                    "Advisory may not apply due to region/variant/hardware/software mismatch.",
                    [f"applicability={state}"],
                    ["Exact installed component/version matches advisory."],
                    ["hardware revision", "regional config", "supplier switch"],
                    ["Authoritative ECU inventory confirms exact affected component/version installed."])
                add("VULNERABILITY", f"{vid}:{eid}:{vidu}", "NO_OBSERVED_EXPLOITATION",
                    "Vulnerability presence does not prove exploitation.",
                    ["CVE/advisory context only"],
                    ["incident/telemetry evidence shows exploitation behavior."],
                    ["vehicle logs", "IDS alerts", "backend logs", "forensics"],
                    ["Independent vehicle-side telemetry/incident evidence demonstrates exploitation."])

        for r in case.get("recalls", []):
            rid = r.get("record_id")
            if r.get("applicability_state") in {"POSSIBLY_APPLICABLE", "PROBABLY_APPLICABLE", "APPLICABLE_PENDING_VIN_RANGE"}:
                add("RECALL", f"{vid}:{rid}", "RECALL_APPLIES_PENDING_VIN_RANGE",
                    "Recall may apply but VIN range/production range is unresolved.",
                    [f"state={r.get('applicability_state')}"],
                    ["Vehicle outside production range or regional variant."],
                    ["VIN range", "build date", "plant"],
                    ["Authoritative recall database confirms vehicle VIN outside range."])

        for o in case.get("otas", []):
            oid = o.get("record_id")
            if not o.get("installation_verified"):
                add("OTA", f"{vid}:{oid}", "UPDATE_AVAILABLE_NOT_INSTALLED",
                    "OTA campaign may be available but not installed/verified on this vehicle.",
                    [f"state={o.get('ota_state')}"],
                    ["Installation verified by authorized vehicle diagnostic."],
                    ["vehicle telemetry", "service record", "backend campaign status"],
                    ["Authorized vehicle-side evidence confirms installation and version."])

        for i in case.get("incidents", []):
            iid = i.get("record_id")
            if i.get("incident_state") in {"ANOMALY_OBSERVED", "CYBER_EVENT_CANDIDATE", "INCONCLUSIVE", "MALFUNCTION_CANDIDATE"}:
                add("INCIDENT", f"{vid}:{iid}", "CYBER_EVENT_CANDIDATE",
                    "Incident may involve cyber activity.",
                    [f"state={i.get('incident_state')}", f"maintenance={i.get('maintenance_context')}"],
                    ["Malfunction, maintenance, software bug, backend-only event possible."],
                    ["vehicle-side logs", "IDS", "gateway logs", "forensic artifacts"],
                    ["Independent vehicle-side evidence excludes benign causes and confirms cyber pathway."])
                add("INCIDENT", f"{vid}:{iid}", "BENIGN_OPERATIONAL_OR_MECHANICAL_CAUSE",
                    "Observed event may be non-cyber malfunction, maintenance, or backend-only behavior.",
                    [f"maintenance_context={i.get('maintenance_context')}"],
                    ["strong vehicle-side cyber evidence"],
                    ["service records", "DTC history", "component fault data"],
                    ["Cyber pathway confirmed and benign causes excluded."])

        can = case.get("can_context", {})
        for a in can.get("anomalies", [])[:50]:
            aid = a.get("record_id")
            add("CAN", f"{vid}:{aid}", "DIAGNOSTIC_OR_MAINTENANCE_TRAFFIC",
                "CAN anomaly may be diagnostic session, maintenance, ECU fault, or mode change.",
                [f"maintenance_context={a.get('maintenance_context')}"],
                ["No authorized maintenance/diagnostic evidence."],
                ["DBC mapping", "service session", "ECU state"],
                ["Authorized logs exclude diagnostic/maintenance and anomaly persists."])
            add("CAN", f"{vid}:{aid}", "UNKNOWN_MAPPING_INCOMPLETE",
                "Unknown CAN ID may reflect incomplete DBC/mapping rather than malicious message.",
                [f"decode_status={a.get('decode_status')}"],
                ["Trusted DBC and sender attribution confirm unexpected semantic."],
                ["DBC version", "vehicle variant", "bus topology"],
                ["Correct DBC/variant mapping identifies signal and context shows anomaly."])

    return hyp[:2000]


def build_gaps(
    cases: List[Dict[str, Any]],
    unknown_refs: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    manifest: Dict[str, Any],
) -> List[Dict[str, Any]]:
    gaps: List[Dict[str, Any]] = []

    if not cases:
        gaps.append({
            "gap_id": stable_id("GAP", "no_vehicles"),
            "type": "VEHICLE_UNRESOLVED",
            "importance": "HIGH",
            "recommended_source": "Authorized vehicle inventory, VIN/dealer record, fleet management, OEM documentation.",
            "specialist": "AUTOMOTIVEINT",
            "expected_information_value": "Resolve vehicle identity before component/risk analysis.",
        })

    for ur in unknown_refs:
        gaps.append({
            "gap_id": stable_id("GAP", "unknown_ref", ur.get("record_type"), ur.get("record_id")),
            "type": "RECORD_REFERENCE_UNRESOLVED",
            "importance": "HIGH",
            "record_type": ur.get("record_type"),
            "recommended_source": "Correct vehicle_id/ecu_id or add missing authorized inventory record.",
            "specialist": "AUTOMOTIVEINT",
            "expected_information_value": "Prevent orphan ECU/recall/vulnerability/OTA records.",
        })

    for case in cases:
        vid = case["vehicle"]["vehicle_id"]
        ident = case.get("identity_resolution", {})
        for field in ("make_state", "model_state", "model_year_state", "platform_state", "variant_state", "region_state"):
            if ident.get(field) in {"UNKNOWN", "CANDIDATE"}:
                gaps.append({
                    "gap_id": stable_id("GAP", field, vid),
                    "type": "VEHICLE_IDENTITY_UNRESOLVED",
                    "importance": "HIGH" if field in {"model_state", "model_year_state", "variant_state"} else "MEDIUM",
                    "vehicle_id": vid,
                    "field": field,
                    "recommended_source": "Authorized VIN decode, OEM build data, registration/fleet record, type approval where public.",
                    "specialist": "AUTOMOTIVEINT / TECHINT",
                    "expected_information_value": "Avoid model-family-level findings being treated as vehicle-specific.",
                })

        for e in case.get("ecus", []):
            eid = e.get("ecu_id")
            ass = e.get("assessment", {})
            if ass.get("part_number_state") in {"UNKNOWN", "CANDIDATE"}:
                gaps.append({
                    "gap_id": stable_id("GAP", "ecu_part", eid),
                    "type": "ECU_PART_NUMBER_UNRESOLVED",
                    "importance": "HIGH",
                    "vehicle_id": vid,
                    "ecu_id": eid,
                    "recommended_source": "Authorized ECU inventory, diagnostic readout, label/photo where authorized, parts catalog.",
                    "specialist": "AUTOMOTIVEINT / TECHINT",
                    "expected_information_value": "Resolve exact ECU implementation.",
                })
            if ass.get("hardware_version_state") in {"UNKNOWN", "CANDIDATE"}:
                gaps.append({
                    "gap_id": stable_id("GAP", "ecu_hw", eid),
                    "type": "ECU_HARDWARE_REVISION_UNRESOLVED",
                    "importance": "HIGH",
                    "vehicle_id": vid,
                    "ecu_id": eid,
                    "recommended_source": "Authorized inventory, service record, supplier documentation, bench/teardown where authorized.",
                    "specialist": "TECHINT / AUTOMOTIVEINT",
                    "expected_information_value": "Revision can change vulnerability applicability.",
                })
            if ass.get("software_version_state") in {"UNKNOWN", "CANDIDATE"} or ass.get("firmware_version_state") in {"UNKNOWN", "CANDIDATE"}:
                gaps.append({
                    "gap_id": stable_id("GAP", "ecu_sw_fw", eid),
                    "type": "ECU_SOFTWARE_FIRMWARE_UNRESOLVED",
                    "importance": "HIGH",
                    "vehicle_id": vid,
                    "ecu_id": eid,
                    "recommended_source": "Authorized diagnostic export, OTA status, service record, OEM advisory.",
                    "specialist": "AUTOMOTIVEINT / VULNINT",
                    "expected_information_value": "Resolve patch/version state before vulnerability conclusion.",
                })
            if ass.get("supplier_state") in {"UNKNOWN", "CANDIDATE"}:
                gaps.append({
                    "gap_id": stable_id("GAP", "supplier", eid),
                    "type": "SUPPLIER_UNRESOLVED",
                    "importance": "MEDIUM",
                    "vehicle_id": vid,
                    "ecu_id": eid,
                    "recommended_source": "Parts marking where authorized, supplier bulletin, OEM supply-chain record.",
                    "specialist": "SUPPLYCHAININT / TECHINT",
                    "expected_information_value": "Separate OEM/Tier-1/Tier-2 and component supplier.",
                })
            if e.get("safety_critical"):
                gaps.append({
                    "gap_id": stable_id("GAP", "safety_ecu", eid),
                    "type": "SAFETY_CRITICAL_HUMAN_REVIEW_REQUIRED",
                    "importance": "HIGH",
                    "vehicle_id": vid,
                    "ecu_id": eid,
                    "recommended_source": "Qualified automotive safety engineer / OEM safety process.",
                    "specialist": "SAFETY_HUMAN_REVIEW / AUTOMOTIVEINT",
                    "expected_information_value": "Prevent unsafe analysis or operational recommendations.",
                })

        if not case.get("networks"):
            gaps.append({
                "gap_id": stable_id("GAP", "network", vid),
                "type": "NETWORK_ARCHITECTURE_INCOMPLETE",
                "importance": "MEDIUM",
                "vehicle_id": vid,
                "recommended_source": "Authorized wiring diagram, gateway configuration, ECU network interfaces, OEM architecture doc.",
                "specialist": "AUTOMOTIVEINT / NETINT",
                "expected_information_value": "Understand bus/gateway context without generating attack paths.",
            })

        can = case.get("can_context", {})
        if can.get("unknown_can_ids"):
            gaps.append({
                "gap_id": stable_id("GAP", "can_unknown", vid),
                "type": "CAN_SEMANTICS_UNRESOLVED",
                "importance": "MEDIUM",
                "vehicle_id": vid,
                "recommended_source": "Correct DBC for model/year/variant, authorized OEM signal mapping, correlation with ECU behavior.",
                "specialist": "AUTOMOTIVEINT / TECHINT",
                "expected_information_value": "Avoid labeling unknown CAN messages malicious.",
            })

        for r in case.get("recalls", []):
            if r.get("applicability_state") in {"UNKNOWN", "POSSIBLY_APPLICABLE", "PROBABLY_APPLICABLE", "APPLICABLE_PENDING_VIN_RANGE"}:
                gaps.append({
                    "gap_id": stable_id("GAP", "recall", vid, r.get("record_id")),
                    "type": "RECALL_APPLICABILITY_UNRESOLVED",
                    "importance": "HIGH",
                    "vehicle_id": vid,
                    "recall_id": r.get("record_id"),
                    "recommended_source": "Official recall database, VIN range, build date, production plant records.",
                    "specialist": "AUTOMOTIVEINT / REGULATORY_REVIEW",
                    "expected_information_value": "Distinguish recall exposure from cyber vulnerability.",
                })

        for v in case.get("vulnerabilities", []):
            if v.get("applicability_state") in {"UNKNOWN", "POSSIBLY_APPLICABLE", "PROBABLY_APPLICABLE"}:
                gaps.append({
                    "gap_id": stable_id("GAP", "vuln", vid, v.get("vulnerability_id"), v.get("ecu_id")),
                    "type": "VULNERABILITY_APPLICABILITY_UNRESOLVED",
                    "importance": "HIGH",
                    "vehicle_id": vid,
                    "ecu_id": v.get("ecu_id"),
                    "vulnerability_id": v.get("vulnerability_id"),
                    "recommended_source": "Exact ECU part/revision/software/firmware/configuration evidence; VULNINT adjudication.",
                    "specialist": "VULNINT / AUTOMOTIVEINT / TECHINT",
                    "expected_information_value": "Avoid CVE-to-vehicle overclaim.",
                })

        for o in case.get("otas", []):
            if not o.get("installation_verified"):
                gaps.append({
                    "gap_id": stable_id("GAP", "ota", vid, o.get("record_id")),
                    "type": "PATCH_OTA_STATE_UNVERIFIED",
                    "importance": "HIGH",
                    "vehicle_id": vid,
                    "ecu_id": o.get("ecu_id"),
                    "recommended_source": "Authorized vehicle diagnostic, OTA backend campaign status, service record.",
                    "specialist": "AUTOMOTIVEINT / CLOUDINT",
                    "expected_information_value": "Distinguish available/downloaded/installed/verified.",
                })

        for i in case.get("incidents", []):
            if i.get("incident_state") in {"ANOMALY_OBSERVED", "CYBER_EVENT_CANDIDATE", "INCONCLUSIVE", "MALFUNCTION_CANDIDATE"}:
                gaps.append({
                    "gap_id": stable_id("GAP", "incident", vid, i.get("record_id")),
                    "type": "INCIDENT_CAUSE_UNRESOLVED",
                    "importance": "HIGH",
                    "vehicle_id": vid,
                    "incident_id": i.get("record_id"),
                    "recommended_source": "Vehicle-side logs, IDS, gateway logs, backend logs, DTC history, maintenance records, forensic artifacts.",
                    "specialist": "INCIDENTINT / LOGINT / AUTOMOTIVEINT",
                    "expected_information_value": "Separate cyber event from malfunction/maintenance.",
                })

        if case.get("risk_dimensions", {}).get("connectivity_surface_present") and not case.get("telematics_context"):
            gaps.append({
                "gap_id": stable_id("GAP", "telematics", vid),
                "type": "TELEMATICS_CONTEXT_INCOMPLETE",
                "importance": "MEDIUM",
                "vehicle_id": vid,
                "recommended_source": "Authorized telematics export, OEM service documentation, mobile/backend dependency metadata.",
                "specialist": "AUTOMOTIVEINT / CLOUDINT / MOBILEINT",
                "expected_information_value": "Map connectivity dependencies without tracking private persons.",
            })

    if manifest.get("clock_offset_unknown"):
        gaps.append({
            "gap_id": stable_id("GAP", "clock"),
            "type": "TIMESTAMP_UNCERTAINTY",
            "importance": "MEDIUM",
            "recommended_source": "ECU local time, GPS time, server time, capture time, timezone normalization metadata.",
            "specialist": "AUTOMOTIVEINT / LOGINT",
            "expected_information_value": "Prevent false event ordering.",
        })

    for c in contradictions:
        gaps.append({
            "gap_id": stable_id("GAP", "contradiction", c["contradiction_id"]),
            "type": "AUTOMOTIVE_CONTRADICTION_UNRESOLVED",
            "importance": "HIGH" if c.get("severity") == "MATERIAL" else "MEDIUM",
            "contradiction_id": c["contradiction_id"],
            "recommended_source": "Authoritative ECU inventory, recall database, OEM advisory, vehicle-side telemetry, service records.",
            "specialist": "AUTOMOTIVEINT / HUMAN_REVIEW",
            "expected_information_value": "Resolve conflict before consequential defensive action.",
        })

    return gaps[:1000]


def build_next_actions(gaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    actions = []
    prio = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for g in gaps:
        t = g.get("type")
        if t == "VEHICLE_UNRESOLVED":
            action = "Resolve vehicle identity from authorized VIN/fleet/OEM records; do not infer owner/driver."
        elif t == "RECORD_REFERENCE_UNRESOLVED":
            action = "Correct vehicle_id/ecu_id linkage or add missing authorized inventory record."
        elif t == "VEHICLE_IDENTITY_UNRESOLVED":
            action = "Retrieve authoritative model/year/variant/platform/region evidence before applicability conclusions."
        elif t == "ECU_PART_NUMBER_UNRESOLVED":
            action = "Verify ECU OEM/supplier part number from authorized diagnostic inventory or parts records."
        elif t == "ECU_HARDWARE_REVISION_UNRESOLVED":
            action = "Resolve hardware revision from authorized inventory/service/supplier evidence; revision affects applicability."
        elif t == "ECU_SOFTWARE_FIRMWARE_UNRESOLVED":
            action = "Retrieve current software/firmware/calibration version from authorized diagnostic export or OTA/service records."
        elif t == "SUPPLIER_UNRESOLVED":
            action = "Resolve OEM/Tier-1/Tier-2/component supplier relationships with time-bound evidence."
        elif t == "SAFETY_CRITICAL_HUMAN_REVIEW_REQUIRED":
            action = "Escalate to qualified automotive safety engineer; remain analysis-only."
        elif t == "NETWORK_ARCHITECTURE_INCOMPLETE":
            action = "Review authorized wiring/gateway/domain architecture; do not generate attack paths."
        elif t == "CAN_SEMANTICS_UNRESOLVED":
            action = "Obtain correct DBC for model/year/variant and correlate with authorized ECU behavior; unknown ID is not malicious."
        elif t == "RECALL_APPLICABILITY_UNRESOLVED":
            action = "Check official recall database and VIN/build range before treating recall as applicable."
        elif t == "VULNERABILITY_APPLICABILITY_UNRESOLVED":
            action = "Hand exact component/version/configuration to VULNINT; do not test exploitability on live vehicles."
        elif t == "PATCH_OTA_STATE_UNVERIFIED":
            action = "Verify OTA installation state through authorized vehicle diagnostics/backend records."
        elif t == "INCIDENT_CAUSE_UNRESOLVED":
            action = "Correlate vehicle-side logs, IDS, gateway, backend, DTCs, and maintenance before attributing cyber cause."
        elif t == "TELEMATICS_CONTEXT_INCOMPLETE":
            action = "Map authorized telematics/mobile/backend dependencies without private-person location analysis."
        elif t == "TIMESTAMP_UNCERTAINTY":
            action = "Normalize timestamps using authorized ECU/GPS/server/capture clock metadata."
        elif t == "AUTOMOTIVE_CONTRADICTION_UNRESOLVED":
            action = "Resolve using authoritative primary evidence and human review before consequential action."
        else:
            action = "Gather additional authorized passive automotive evidence."

        actions.append({
            "action": action,
            "gap_id": g.get("gap_id"),
            "priority": g.get("importance", "MEDIUM"),
            "expected_information_value": g.get("expected_information_value"),
            "prohibited_alternatives": [
                "Do not steal vehicles, clone keys, bypass immobilizers/gateways/diagnostic security access.",
                "Do not inject live CAN/UDS/DoIP commands or disable safety/regulatory systems.",
                "Do not tamper with odometer/emissions/vehicle identity or extract private keys.",
                "Do not track private vehicles/persons or access private telematics without authorization.",
                "Do not perform remote vehicle control/takeover or offensive exploitation.",
            ],
        })
    actions.sort(key=lambda x: prio.get(x.get("priority", "LOW"), 9))
    return actions[:300]


def build_handoffs(cases: List[Dict[str, Any]], gaps: List[Dict[str, Any]], contradictions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    hands = []
    seen = set()

    def add(spec: str, reason: str, payload: Dict[str, Any]) -> None:
        key = (spec, json.dumps(json_safe(payload), sort_keys=True, ensure_ascii=False))
        if key not in seen:
            seen.add(key)
            hands.append({"specialist": spec, "reason": reason, "payload": payload})

    if any(case.get("ecus") for case in cases):
        add("TECHINT", "ECU/component/part-number/hardware revision technical resolution may be required.", {
            "vehicle_ids": [c["vehicle"]["vehicle_id"] for c in cases][:100],
        })
    if any(v.get("applicability_state") in {"UNKNOWN", "POSSIBLY_APPLICABLE", "PROBABLY_APPLICABLE", "APPLICABLE_SUPPORTED"} for c in cases for v in c.get("vulnerabilities", [])):
        add("VULNINT", "Automotive CVE/component applicability, fixed versions, KEV/EPSS, and exploitation context required.", {
            "vulnerability_ids": [v.get("vulnerability_id") for c in cases for v in c.get("vulnerabilities", [])][:100],
        })
    if any(c.get("incidents") for c in cases):
        add("INCIDENTINT / LOGINT", "Vehicle incident reconstruction and multi-source log correlation required.", {
            "vehicle_ids": [c["vehicle"]["vehicle_id"] for c in cases if c.get("incidents")][:100],
        })
    if any(c.get("otas") for c in cases):
        add("CLOUDINT / AUTOMOTIVE_BACKEND", "OTA campaign/backend update state verification required under authorization.", {
            "vehicle_ids": [c["vehicle"]["vehicle_id"] for c in cases if c.get("otas")][:100],
        })
    if any(c.get("mobile_apps") or c.get("backend_services") or c.get("cloud_dependencies") for c in cases):
        add("MOBILEINT / APPINT / CLOUDINT", "Companion app and backend/cloud dependency analysis required; no account takeover.", {
            "vehicle_ids": [c["vehicle"]["vehicle_id"] for c in cases if c.get("mobile_apps") or c.get("backend_services") or c.get("cloud_dependencies")][:100],
        })
    if any(c.get("suppliers") for c in cases):
        add("SUPPLYCHAININT", "OEM/Tier-1/Tier-2/component supplier concentration and dependency risk required.", {
            "vehicle_ids": [c["vehicle"]["vehicle_id"] for c in cases if c.get("suppliers")][:100],
        })
    if any(c.get("certificates") for c in cases):
        add("CERTINT", "Vehicle/PKI/code-signing/TLS certificate context required; no private key use.", {
            "vehicle_ids": [c["vehicle"]["vehicle_id"] for c in cases if c.get("certificates")][:100],
        })
    if any(g.get("type") == "SAFETY_CRITICAL_HUMAN_REVIEW_REQUIRED" for g in gaps):
        add("SAFETY_HUMAN_REVIEW / OEM_SAFETY_PROCESS", "Safety-critical ECU or impact requires qualified human safety review.", {
            "gap_ids": [g["gap_id"] for g in gaps if g.get("type") == "SAFETY_CRITICAL_HUMAN_REVIEW_REQUIRED"][:100],
        })
    if any(c.get("can_context", {}).get("anomalies") for c in cases):
        add("NETINT / IDS", "In-vehicle network anomaly correlation and defensive IDS context required; no live injection.", {
            "vehicle_ids": [c["vehicle"]["vehicle_id"] for c in cases if c.get("can_context", {}).get("anomalies")][:100],
        })
    if contradictions:
        add("HUMAN_REVIEW / OEM_VENDOR_LIAISON", "Material contradictions require human review before vendor/OEM notification or remediation decisions.", {
            "contradiction_ids": [c["contradiction_id"] for c in contradictions][:100],
        })
    return hands


class GraphMemory:
    def __init__(self) -> None:
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, Any]] = []
        self.ids: Set[str] = set()

    def node(self, ntype: str, nid: str, props: Optional[Dict[str, Any]] = None) -> None:
        if nid and nid not in self.ids:
            self.ids.add(nid)
            self.nodes.append({"type": ntype, "id": nid, "properties": props or {}})

    def edge(self, frm: str, to: str, etype: str, props: Optional[Dict[str, Any]] = None) -> None:
        if frm and to:
            self.edges.append({"from": frm, "to": to, "type": etype, "properties": props or {}})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": self.nodes[:3000],
            "edges": self.edges[:6000],
            "note": "Automotive graph preserves vehicle identity, ECU/version eras, supplier relationships, recall/vulnerability applicability uncertainty, safety classification, and source dependence. It does not prove compromise or authorize vehicle interaction.",
        }


def build_graph(cases: List[Dict[str, Any]], contradictions: List[Dict[str, Any]], hypotheses: List[Dict[str, Any]], gaps: List[Dict[str, Any]], sources: Dict[str, Dict[str, Any]]) -> GraphMemory:
    g = GraphMemory()
    for case in cases:
        v = case["vehicle"]
        vid = v["vehicle_id"]
        g.node("Vehicle", vid, {
            "make": v.get("make"),
            "model": v.get("model"),
            "model_year": v.get("model_year"),
            "variant": v.get("variant"),
            "platform": v.get("platform"),
            "vin_masked": v.get("vin_masked"),
        })
        for typ, val in (
            ("Make", v.get("make")),
            ("Brand", v.get("brand")),
            ("Model", v.get("model")),
            ("ModelYear", v.get("model_year")),
            ("Generation", v.get("generation")),
            ("Platform", v.get("platform")),
            ("Trim", v.get("trim")),
            ("Variant", v.get("variant")),
            ("Powertrain", v.get("powertrain")),
            ("Region", v.get("region")),
        ):
            if val:
                nid = stable_id(typ, val)
                g.node(typ, nid, {"value": val})
                g.edge(vid, nid, f"HAS_{typ.upper()}_CANDIDATE", {})
        for e in case.get("ecus", []):
            eid = e.get("ecu_id")
            g.node("ECU", eid, {
                "ecu_type": e.get("ecu_type"),
                "safety_critical": e.get("safety_critical"),
                "software_version": e.get("software_version"),
                "firmware_version": e.get("firmware_version"),
            })
            g.edge(eid, vid, "INSTALLED_IN", {})
            for typ, val in (("Manufacturer", e.get("manufacturer")), ("Supplier", e.get("supplier"))):
                if val:
                    nid = stable_id(typ, val)
                    g.node(typ, nid, {"value": val})
                    g.edge(eid, nid, f"HAS_{typ.upper()}_CANDIDATE", {})
        for n in case.get("networks", []):
            nid = n.get("record_id")
            g.node("NetworkBus", nid, {"network_type": n.get("network_type"), "bus_name": n.get("bus_name")})
            g.edge(nid, vid, "PART_OF_VEHICLE", {})
        for r in case.get("recalls", []):
            rid = r.get("record_id")
            g.node("Recall", rid, {"status": r.get("status"), "applicability_state": r.get("applicability_state")})
            g.edge(vid, rid, "SUBJECT_TO_RECALL_CANDIDATE", {"state": r.get("applicability_state")})
        for vu in case.get("vulnerabilities", []):
            vidu = vu.get("vulnerability_id")
            g.node("Vulnerability", vidu, {"cve": vu.get("cve"), "applicability_state": vu.get("applicability_state"), "safety_impact": vu.get("safety_impact")})
            if vu.get("ecu_id"):
                g.edge(vu["ecu_id"], vidu, "POSSIBLY_AFFECTED_BY", {"state": vu.get("applicability_state")})
        for o in case.get("otas", []):
            oid = o.get("record_id")
            g.node("OTAUpdate", oid, {"state": o.get("ota_state"), "target_version": o.get("target_version")})
            if o.get("ecu_id"):
                g.edge(o["ecu_id"], oid, "UPDATED_BY_CANDIDATE", {})
        for i in case.get("incidents", []):
            iid = i.get("record_id")
            g.node("Incident", iid, {"type": i.get("incident_type"), "state": i.get("incident_state")})
            g.edge(vid, iid, "OBSERVED_IN_INCIDENT", {})
        for sid in v.get("source_ids", []):
            g.node("Source", sid, {"source_type": sources.get(sid, {}).get("source_type")})
            g.edge(vid, sid, "SUPPORTED_BY_SOURCE", {})

    for c in contradictions[:500]:
        g.node("Contradiction", c["contradiction_id"], {"type": c.get("type"), "severity": c.get("severity")})
    for h in hypotheses[:500]:
        g.node("Hypothesis", h["hypothesis_id"], {"category": h.get("category"), "subject_id": h.get("subject_id")})
    for gap in gaps[:500]:
        g.node("Gap", gap["gap_id"], {"type": gap.get("type"), "importance": gap.get("importance")})
    return g


def dual_ai_review_stub(cases: List[Dict[str, Any]], contradictions: List[Dict[str, Any]], gaps: List[Dict[str, Any]]) -> Dict[str, Any]:
    review = {
        "status": "INSUFFICIENT_EVIDENCE",
        "primary_conclusions": [],
        "skeptic_challenges": [],
        "comparison": "NO_SECOND_MODEL_CONFIGURED",
        "notes": [
            "Starter does not call an independent second model.",
            "AI agreement is not automotive corroboration.",
            "Human/qualified safety review required for safety-critical ECUs, remote-control claims, theft/key implications, live testing, fleet remediation, recall escalation, or public disclosure.",
        ],
    }
    if any(v.get("applicability_state") in {"APPLICABLE_SUPPORTED", "PROBABLY_APPLICABLE", "POSSIBLY_APPLICABLE"} for c in cases for v in c.get("vulnerabilities", [])):
        review["primary_conclusions"].append("Some vulnerability applicability states are resolved/candidate from supplied records.")
        review["skeptic_challenges"].append("Check exact ECU part/revision/software/firmware, region/variant, supplier switch, service replacement, and configuration/reachability.")
    if any(r.get("applicability_state") in {"APPLICABLE_SUPPORTED", "PROBABLY_APPLICABLE", "POSSIBLY_APPLICABLE", "APPLICABLE_PENDING_VIN_RANGE"} for c in cases for r in c.get("recalls", [])):
        review["primary_conclusions"].append("Some recall applicability is candidate/pending VIN range.")
        review["skeptic_challenges"].append("Do not equate recall with cyber vulnerability; verify VIN/build range and remedy status.")
    if any(i.get("incident_state") in {"ANOMALY_OBSERVED", "CYBER_EVENT_CANDIDATE", "INCONCLUSIVE"} for c in cases for i in c.get("incidents", [])):
        review["primary_conclusions"].append("Some incident causes remain unresolved.")
        review["skeptic_challenges"].append("Do not equate malfunction/backend event with cyberattack; correlate vehicle-side evidence.")
    if contradictions:
        review["primary_conclusions"].append(f"{len(contradictions)} automotive contradiction candidate(s) detected.")
        review["skeptic_challenges"].append("Contradictions may be stale inventory, replacement, regional variant, OTA mismatch, DBC error, or dependent sources.")
    if any(g.get("type") == "SAFETY_CRITICAL_HUMAN_REVIEW_REQUIRED" for g in gaps):
        review["primary_conclusions"].append("Safety-critical human review required.")
        review["skeptic_challenges"].append("Remain analysis-only; do not provide control/testing procedures for safety-critical functions.")
    if review["primary_conclusions"]:
        review["status"] = "PARTIAL_AGREEMENT"
    return review


# --------------------------------------------------------------------
# Result / report
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
        "vehicles": [],
        "makes": [],
        "brands": [],
        "models": [],
        "model_years": [],
        "generations": [],
        "platforms": [],
        "trims": [],
        "variants": [],
        "powertrains": [],
        "vin_references": [],
        "vehicle_configuration_eras": [],
        "ecus": [],
        "ecu_types": [],
        "part_numbers": [],
        "hardware_versions": [],
        "software_versions": [],
        "firmware_versions": [],
        "bootloaders": [],
        "suppliers": [],
        "oems": [],
        "tier1s": [],
        "tier2s": [],
        "chipsets": [],
        "sensors": [],
        "actuators": [],
        "gateways": [],
        "domain_controllers": [],
        "zonal_controllers": [],
        "tcus": [],
        "ivi_systems": [],
        "adas_systems": [],
        "bms_systems": [],
        "charging_systems": [],
        "network_buses": [],
        "can_context": [],
        "can_fd_context": [],
        "lin_context": [],
        "flexray_context": [],
        "ethernet_context": [],
        "doip_context": [],
        "uds_context": [],
        "obd_context": [],
        "dtcs": [],
        "diagnostic_context": [],
        "mobile_apps": [],
        "backend_services": [],
        "cloud_dependencies": [],
        "telematics_context": [],
        "ota_updates": [],
        "secure_boot_context": [],
        "code_signing_context": [],
        "certificate_context": [],
        "hsm_context": [],
        "sboms": [],
        "packages": [],
        "vulnerabilities": [],
        "cves": [],
        "vulnerability_applicability": [],
        "exploit_context": [],
        "recalls": [],
        "tsbs": [],
        "service_campaigns": [],
        "fleet_context": [],
        "charging_network_context": [],
        "v2x_context": [],
        "incident_context": [],
        "forensic_context": [],
        "safety_impact": [],
        "cybersecurity_regulatory_context": [],
        "source_reliability": [],
        "source_bias": [],
        "source_limitations": [],
        "source_pedigree": [],
        "source_independence": [],
        "timeline_updates": [],
        "observations": [],
        "candidate_facts": [],
        "supported_facts": [],
        "partial_facts": [],
        "disputed_facts": [],
        "contradictions": [],
        "hypotheses": [],
        "falsification_results": [],
        "privacy_flags": [
            "VIN masked by default.",
            "No private-person owner/driver inference performed.",
            "No vehicle location tracking or private telematics retrieval performed.",
        ],
        "safety_flags": [
            "Safety-critical functions default to analysis-only.",
            "No live vehicle command, diagnostic bypass, key operation, firmware modification, or safety-system interaction performed.",
            "Qualified human safety review required for consequential decisions.",
        ],
        "legal_flags": [
            "AUTOMOTIVEINT does not make final legal certification, recall compliance, or liability determinations.",
        ],
        "unknowns": [],
        "knowledge_gaps": [],
        "recommended_next_actions": [],
        "specialist_handoffs": [],
        "limitations": [],
        "dual_ai_review": {},
        "graph_memory": {},
        "status": "PARTIAL",
    }


def compute_source_bias(sources: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for sid, src in sources.items():
        st = normalize_text(src.get("source_type", "unknown")).lower()
        bias = []
        if st in {"oem_advisory", "official_service_manual"}:
            bias.append("OEM scope/marketing/simplification bias; may not match region/variant/build")
        if st in {"regulatory_recall"}:
            bias.append("recall range/publication lag; remedy completion may require service records")
        if st in {"academic_research", "conference_research"}:
            bias.append("lab conditions, selected trim/software, physical-access prerequisites")
        if st in {"public_cve", "commercial_database"}:
            bias.append("aggregation lag, component naming ambiguity, applicability overbreadth")
        if st in {"authorized_can_trace", "authorized_diagnostic_export"}:
            bias.append("visibility gaps, DBC version mismatch, clock drift, session context")
        out.append({
            "source_id": sid,
            "source_type": st,
            "potential_bias": bias,
            "limitations": src.get("limitations", []),
        })
    return out


def finalize_status(policy_blocked: List[str], auth_ok: bool, cases: List[Dict[str, Any]], contradictions: List[Dict[str, Any]], gaps: List[Dict[str, Any]]) -> str:
    if policy_blocked:
        return "POLICY_BLOCKED"
    if not auth_ok:
        return "BLOCKED_PERMISSION"
    if not cases:
        return "VEHICLE_UNRESOLVED"
    if contradictions:
        return "PARTIAL"
    if any(g.get("importance") == "HIGH" for g in gaps):
        return "PARTIAL"
    if gaps:
        return "PARTIAL"
    return "SUCCEEDED"


def analyze_automotiveint_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    result = empty_result(manifest)

    policy_blocked = policy_screen(manifest)
    if policy_blocked:
        result["status"] = "POLICY_BLOCKED"
        result["violations"] = policy_blocked
        result["limitations"] = [
            "AUTOMOTIVEINT does not assist theft, key cloning, immobilizer/gateway/diagnostic bypass, live command injection, safety tampering, odometer/emissions fraud, VIN cloning, private tracking, remote vehicle control, or offensive exploitation."
        ]
        return result

    auth_ok, auth_reasons = authorization_check(manifest)
    if not auth_ok:
        result["status"] = "BLOCKED_PERMISSION"
        result["limitations"] = auth_reasons
        return result

    sources = ingest_sources(manifest)
    roots = build_source_roots(sources)
    vehicles = ingest_vehicles(manifest)
    ecus = ingest_ecus(manifest)

    networks = ingest_records(manifest, "network_architecture", "NET",
        extra_str_fields=("network_type", "bus_name", "segment", "description"),
        extra_list_fields=("connected_ecu_ids", "gateways"))
    can_frames = ingest_records(manifest, "can_traces", "CAN",
        extra_str_fields=("bus", "decode_status", "dbc_version", "signal_meaning", "direction"),
        extra_time_fields=("timestamp",),
        extra_int_fields=("can_id", "dlc", "length"),
        extra_bool_fields=("anomaly", "baseline_expected"))
    dtcs = ingest_records(manifest, "dtcs", "DTC",
        extra_str_fields=("code", "module", "status", "description"),
        extra_time_fields=("first_seen", "cleared_at"))
    recalls = ingest_records(manifest, "recalls", "RECALL",
        extra_str_fields=("authority", "oem", "issue", "risk", "remedy", "status", "vin_range_start", "vin_range_end"),
        extra_list_fields=("makes", "models", "model_years", "variants", "regions"),
        extra_time_fields=("effective_at",))
    tsbs = ingest_records(manifest, "tsbs", "TSB",
        extra_str_fields=("title", "issue", "remedy", "status"),
        extra_list_fields=("models", "model_years", "variants"))
    service_campaigns = ingest_records(manifest, "service_campaigns", "SVCAMP",
        extra_str_fields=("title", "scope", "remedy", "status"),
        extra_list_fields=("models", "model_years", "variants"))
    vulnerabilities = ingest_records(manifest, "vulnerabilities", "VULN",
        extra_str_fields=("cve", "vendor", "supplier", "product", "component", "advisory"),
        extra_list_fields=("affected_versions", "fixed_versions", "mitigations"),
        extra_bool_fields=("known_exploitation_reported", "kev"),
        extra_float_fields=("epss",),
        )
    # Normalize vulnerability enum-ish strings after ingest
    for v in vulnerabilities:
        v["exploit_availability"] = norm_enum(v.get("exploit_availability"), EXPLOIT_AVAILABILITY_STATES)
        v["safety_impact"] = normalize_token(v.get("safety_impact")) or None
        v["remote_exploitability"] = normalize_token(v.get("remote_exploitability")) or None

    otas = ingest_records(manifest, "ota_metadata", "OTA",
        extra_str_fields=("campaign", "target_version", "signature_present", "state", "region"),
        extra_bool_fields=("installation_verified", "rollback_available"),
        extra_time_fields=("installed_at",))
    incidents = ingest_records(manifest, "incidents", "INC",
        extra_str_fields=("incident_type", "description", "safety_impact"),
        extra_list_fields=("involved_ecu_ids",),
        extra_bool_fields=("backend_event_accepted", "vehicle_side_confirmation", "cyber_claim", "malfunction_candidate", "maintenance_candidate"),
        extra_time_fields=("occurred_at",))
    mobile_apps = ingest_records(manifest, "mobile_apps", "APP",
        extra_str_fields=("name", "platform", "package", "version", "authentication_architecture"),
        extra_list_fields=("permissions", "api_endpoints", "backend_dependencies"))
    backend_services = ingest_records(manifest, "backend_services", "BE",
        extra_str_fields=("service", "provider", "endpoint", "auth", "role"))
    cloud_dependencies = ingest_records(manifest, "cloud_dependencies", "CLOUD",
        extra_str_fields=("provider", "service", "endpoint", "role"))
    telematics_context = ingest_records(manifest, "telematics_data", "TELEM",
        extra_str_fields=("provider", "service"),
        extra_list_fields=("capabilities", "data_categories", "privacy_sensitivity"))
    certificates = ingest_records(manifest, "certificates", "CERT",
        extra_str_fields=("role", "subject", "issuer", "fingerprint"),
        extra_time_fields=("valid_from", "valid_to"))
    sboms = ingest_records(manifest, "sboms", "SBOM",
        extra_str_fields=("format",),
        extra_list_fields=("components",),
        extra_time_fields=("generated_at",))
    fleet_context = ingest_records(manifest, "fleet_context", "FLEET",
        extra_str_fields=("organization", "model_distribution", "software_versions", "recall_exposure", "patch_coverage"),
        extra_list_fields=("vehicle_ids",))
    maintenance = ingest_records(manifest, "maintenance_windows", "MAINT",
        extra_str_fields=("description", "ticket"),
        extra_bool_fields=("approved",),
        extra_time_fields=("start", "end"))

    valid_vehicle_ids = set(vehicles)
    ecus_by_id = {e["ecu_id"]: e for e in ecus}
    unknown_refs: List[Dict[str, Any]] = []

    records_by_vehicle: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    vehicle_scoped = {
        "ecus": ecus,
        "networks": networks,
        "can_frames": can_frames,
        "dtcs": dtcs,
        "recalls": recalls,
        "tsbs": tsbs,
        "service_campaigns": service_campaigns,
        "otas": otas,
        "incidents": incidents,
        "mobile_apps": mobile_apps,
        "backend_services": backend_services,
        "cloud_dependencies": cloud_dependencies,
        "telematics_context": telematics_context,
        "certificates": certificates,
        "sboms": sboms,
    }
    for typ, recs in vehicle_scoped.items():
        d, u = index_by_vehicle(recs, valid_vehicle_ids, typ)
        records_by_vehicle[typ] = d
        unknown_refs.extend(u)

    for v in vulnerabilities:
        if v.get("vehicle_id") and v["vehicle_id"] not in valid_vehicle_ids:
            unknown_refs.append({"record_type": "vulnerability", "record_id": v.get("record_id"), "vehicle_id": v.get("vehicle_id"), "ecu_id": v.get("ecu_id")})
        if v.get("ecu_id") and v["ecu_id"] not in ecus_by_id:
            unknown_refs.append({"record_type": "vulnerability", "record_id": v.get("record_id"), "vehicle_id": v.get("vehicle_id"), "ecu_id": v.get("ecu_id")})

    maintenance_by_vehicle, _ = index_by_vehicle(maintenance, valid_vehicle_ids, "maintenance")

    fleets_by_vehicle: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for f in fleet_context:
        for vid in f.get("vehicle_ids", []):
            if vid in valid_vehicle_ids:
                fleets_by_vehicle[vid].append(f)
            else:
                unknown_refs.append({"record_type": "fleet", "record_id": f.get("record_id"), "vehicle_id": vid, "ecu_id": None})

    all_records_for_asof = {
        "can_frames": can_frames, "dtcs": dtcs, "recalls": recalls, "otas": otas,
        "incidents": incidents, "maintenance": maintenance, "certificates": certificates,
        "sboms": sboms,
    }
    as_of = determine_as_of(manifest, vehicles, all_records_for_asof, sources)

    cases = [
        assess_vehicle_case(vehicle, records_by_vehicle, fleets_by_vehicle, ecus_by_id, vulnerabilities, maintenance_by_vehicle, sources, roots, as_of)
        for vehicle in vehicles.values()
    ]

    contradictions = detect_contradictions(cases, unknown_refs, sources, roots, as_of)
    hypotheses = build_hypotheses(cases)
    gaps = build_gaps(cases, unknown_refs, contradictions, manifest)
    actions = build_next_actions(gaps)
    handoffs = build_handoffs(cases, gaps, contradictions)
    graph = build_graph(cases, contradictions, hypotheses, gaps, sources)
    review = dual_ai_review_stub(cases, contradictions, gaps)

    observations = [
        f"Vehicles ingested: {len(vehicles)}.",
        f"ECUs ingested: {len(ecus)}.",
        f"Network architecture records: {len(networks)}.",
        f"CAN frames: {len(can_frames)}.",
        f"DTCs: {len(dtcs)}; recalls: {len(recalls)}; TSBs: {len(tsbs)}.",
        f"Vulnerability records: {len(vulnerabilities)}.",
        f"OTA records: {len(otas)}; incidents: {len(incidents)}.",
        f"Mobile/backend/cloud/telematics records: {len(mobile_apps)}/{len(backend_services)}/{len(cloud_dependencies)}/{len(telematics_context)}.",
        f"Certificates/SBOMs/fleet/maintenance records: {len(certificates)}/{len(sboms)}/{len(fleet_context)}/{len(maintenance)}.",
        f"As-of date used for temporal validation: {iso(as_of)}.",
        f"Contradiction candidates: {len(contradictions)}.",
        f"Competing hypotheses: {len(hypotheses)}.",
        "No live vehicle interaction, command injection, key operation, diagnostic bypass, firmware modification, safety-system tampering, private tracking, or remote control was performed.",
        "VIN was masked; no owner/driver inference was performed.",
        "CAN IDs were not equated with command semantics without DBC/mapping.",
        "CVE/advisory was not equated with vehicle vulnerability without exact component/version evidence.",
        "Backend event acceptance was not equated with vehicle execution.",
        "Recall was not equated with cybersecurity vulnerability.",
        "Safety-critical ECUs were treated as analysis-only with human review flags.",
    ]

    unknowns = []
    for case in cases:
        vid = case["vehicle"]["vehicle_id"]
        ident = case.get("identity_resolution", {})
        if ident.get("model_state") in {"UNKNOWN", "CANDIDATE"}:
            unknowns.append(f"Vehicle model unresolved for {vid}.")
        if ident.get("variant_state") in {"UNKNOWN", "CANDIDATE"}:
            unknowns.append(f"Vehicle variant unresolved for {vid}.")
        for e in case.get("ecus", []):
            ass = e.get("assessment", {})
            if ass.get("software_version_state") in {"UNKNOWN", "CANDIDATE"}:
                unknowns.append(f"ECU software version unresolved for {e.get('ecu_id')}.")
            if ass.get("hardware_version_state") in {"UNKNOWN", "CANDIDATE"}:
                unknowns.append(f"ECU hardware revision unresolved for {e.get('ecu_id')}.")
        for v in case.get("vulnerabilities", []):
            if v.get("applicability_state") in {"UNKNOWN", "POSSIBLY_APPLICABLE", "PROBABLY_APPLICABLE"}:
                unknowns.append(f"Vulnerability applicability unresolved for {v.get('vulnerability_id')} on {v.get('ecu_id')}.")
        for i in case.get("incidents", []):
            if i.get("incident_state") in {"ANOMALY_OBSERVED", "CYBER_EVENT_CANDIDATE", "INCONCLUSIVE", "MALFUNCTION_CANDIDATE"}:
                unknowns.append(f"Incident cause unresolved for {i.get('record_id')}.")
    unknowns.append("Model-family research is not individual-vehicle exploitation evidence.")
    unknowns.append("Paired device is not driver/owner identity.")
    result["unknowns"] = list(dict.fromkeys(unknowns))[:500]

    result["vehicles"] = cases
    for case in cases:
        v = case["vehicle"]
        vid = v["vehicle_id"]
        result["makes"].append({"vehicle_id": vid, "make": v.get("make")})
        result["brands"].append({"vehicle_id": vid, "brand": v.get("brand")})
        result["models"].append({"vehicle_id": vid, "model": v.get("model")})
        result["model_years"].append({"vehicle_id": vid, "model_year": v.get("model_year")})
        result["generations"].append({"vehicle_id": vid, "generation": v.get("generation")})
        result["platforms"].append({"vehicle_id": vid, "platform": v.get("platform")})
        result["trims"].append({"vehicle_id": vid, "trim": v.get("trim")})
        result["variants"].append({"vehicle_id": vid, "variant": v.get("variant")})
        result["powertrains"].append({"vehicle_id": vid, "powertrain": v.get("powertrain")})
        result["vin_references"].append({"vehicle_id": vid, "vin_masked": v.get("vin_masked"), "vin_hash": v.get("vin_hash")})
        result["ecus"].extend([{**e, "vehicle_id": vid} for e in case.get("ecus", [])])
        result["ecu_types"].extend([{"ecu_id": e.get("ecu_id"), "ecu_type": e.get("ecu_type")} for e in case.get("ecus", [])])
        result["part_numbers"].extend([{"ecu_id": e.get("ecu_id"), "oem_part_number": e.get("oem_part_number"), "supplier_part_number": e.get("supplier_part_number")} for e in case.get("ecus", [])])
        result["hardware_versions"].extend([{"ecu_id": e.get("ecu_id"), "hardware_version": e.get("hardware_version")} for e in case.get("ecus", [])])
        result["software_versions"].extend([{"ecu_id": e.get("ecu_id"), "software_version": e.get("software_version")} for e in case.get("ecus", [])])
        result["firmware_versions"].extend([{"ecu_id": e.get("ecu_id"), "firmware_version": e.get("firmware_version")} for e in case.get("ecus", [])])
        result["bootloaders"].extend([{"ecu_id": e.get("ecu_id"), "bootloader_version": e.get("bootloader_version")} for e in case.get("ecus", [])])
        result["suppliers"].extend(case.get("suppliers", []))
        result["network_buses"].extend(case.get("networks", []))
        result["can_context"].append({"vehicle_id": vid, **case.get("can_context", {})})
        result["dtcs"].extend(case.get("dtcs", {}).get("items", []))
        result["recalls"].extend(case.get("recalls", []))
        result["tsbs"].extend(case.get("tsbs", []))
        result["service_campaigns"].extend(case.get("service_campaigns", []))
        result["vulnerabilities"].extend(case.get("vulnerabilities", []))
        result["cves"].extend([{"vulnerability_id": x.get("vulnerability_id"), "cve": x.get("cve")} for x in case.get("vulnerabilities", [])])
        result["vulnerability_applicability"].extend(case.get("vulnerabilities", []))
        result["exploit_context"].extend([{"vulnerability_id": x.get("vulnerability_id"), "exploit_availability": x.get("exploit_availability"), "known_exploitation_reported": x.get("known_exploitation_reported")} for x in case.get("vulnerabilities", [])])
        result["ota_updates"].extend(case.get("otas", []))
        result["incident_context"].extend(case.get("incidents", []))
        result["mobile_apps"].extend(case.get("mobile_apps", []))
        result["backend_services"].extend(case.get("backend_services", []))
        result["cloud_dependencies"].extend(case.get("cloud_dependencies", []))
        result["telematics_context"].extend(case.get("telematics_context", []))
        result["certificates"].extend(case.get("certificates", []))
        result["sboms"].extend(case.get("sboms", []))
        result["fleet_context"].extend(case.get("fleet_context", []))
        result["safety_impact"].extend([{"vehicle_id": vid, "safety_flags": case.get("safety_flags", []), "risk_dimensions": case.get("risk_dimensions", {})}])
        result["timeline_updates"].append({"vehicle_id": vid, "as_of": iso(as_of)})

    for sid, src in sources.items():
        result["source_ids"].append(sid)
        result["source_reliability"].append({
            "source_id": sid,
            "source_type": src.get("source_type"),
            "reliability": src.get("reliability"),
        })
        result["source_limitations"].append({
            "source_id": sid,
            "limitations": src.get("limitations", []),
        })
        result["source_pedigree"].append({
            "source_id": sid,
            "upstream_source_id": src.get("upstream_source_id"),
            "root_source_id": roots.get(sid, sid),
        })
    result["source_bias"] = compute_source_bias(sources)

    for case in cases:
        vid = case["vehicle"]["vehicle_id"]
        result["source_independence"].append({
            "vehicle_id": vid,
            "state": case.get("identity_resolution", {}).get("source_assessment", {}).get("state"),
            "max_reliability": case.get("identity_resolution", {}).get("source_assessment", {}).get("max_reliability"),
        })

    for case in cases:
        vid = case["vehicle"]["vehicle_id"]
        ident = case.get("identity_resolution", {})
        if ident.get("model_state") == "SUPPORTED":
            result["supported_facts"].append({"vehicle_id": vid, "statement": f"Authorized records support vehicle model identity for {vid}."})
        elif ident.get("model_state") == "CANDIDATE":
            result["partial_facts"].append({"vehicle_id": vid, "statement": f"Vehicle model identity is candidate for {vid}; exact model requires stronger evidence."})
        else:
            result["candidate_facts"].append({"vehicle_id": vid, "statement": f"Vehicle {vid} ingested but identity incomplete."})
        for v in case.get("vulnerabilities", []):
            result["candidate_facts"].append({
                "vehicle_id": vid,
                "ecu_id": v.get("ecu_id"),
                "vulnerability_id": v.get("vulnerability_id"),
                "statement": f"Vulnerability applicability state={v.get('applicability_state')}; reason={v.get('applicability_reason')}.",
            })

    for c in contradictions:
        result["disputed_facts"].append({
            "contradiction_id": c["contradiction_id"],
            "statement": c.get("detail", "Automotive contradiction candidate."),
        })

    base_limits = [
        "AUTOMOTIVEINT starter uses only provided/local authorized records; no live vehicle access, active scanning, command injection, diagnostic bypass, key operation, firmware modification, telematics retrieval, tracking, or exploitation was performed.",
        "Passive-first default; active testing requires separate explicit authorization, controlled lab/HIL/SIL environment, safety guardrails, rate limits, and human approval.",
        "Vehicle identity ladder is preserved: make/model/year/generation/platform/trim/variant/region/individual vehicle are separate claims.",
        "VIN is privacy-sensitive and masked; VIN does not identify owner/driver automatically.",
        "ECU function name is not exact ECU implementation; part-number family is not exact hardware without revision/version evidence.",
        "CAN ID is not command semantics without trusted DBC/mapping; unknown message is not malicious.",
        "DTC is not confirmed root cause; old DTC is not current failure.",
        "Recall is not automatically cybersecurity vulnerability; model-family recall match is not individual-vehicle match without VIN/build range evidence.",
        "TSB is not safety recall confirmation.",
        "CVE/advisory is not vehicle vulnerability without exact component/version/configuration evidence.",
        "Vulnerability is not exploitation; public PoC/research is not field exploitation; physical-access research is not remote compromise.",
        "OTA available does not prove installed; installed-reported does not prove verified.",
        "Backend event acceptance does not prove vehicle execution.",
        "Incident is not automatically cyberattack; malfunction may have non-cyber causes.",
        "Safety-critical functions are analysis-only and require qualified human review.",
        "No private-person location/tracking or unauthorized telematics access was performed.",
    ]
    if auth_reasons:
        base_limits.extend(auth_reasons)
    result["limitations"] = list(dict.fromkeys(base_limits))

    result["contradictions"] = contradictions
    result["hypotheses"] = hypotheses
    result["falsification_results"] = [
        {
            "hypothesis_id": h["hypothesis_id"],
            "category": h.get("category"),
            "opposition": h.get("opposition", []),
            "falsification_conditions": h.get("falsification_conditions", []),
        }
        for h in hypotheses
    ]
    result["knowledge_gaps"] = gaps
    result["recommended_next_actions"] = actions
    result["specialist_handoffs"] = handoffs
    result["dual_ai_review"] = review
    result["graph_memory"] = graph.to_dict()
    result["status"] = finalize_status(policy_blocked, auth_ok, cases, contradictions, gaps)
    return result


def generate_report(result: Dict[str, Any]) -> str:
    lines = ["# AUTOMOTIVEINT Defensive Automotive Intelligence Report", ""]
    lines += [
        f"- Case ID: `{result.get('case_id')}`",
        f"- Task ID: `{result.get('task_id')}`",
        f"- Generated: `{result.get('generated_at')}`",
        f"- Version: `{result.get('version')}`",
        f"- Status: `{result.get('status')}`",
        "",
    ]

    if result.get("status") == "POLICY_BLOCKED":
        lines += ["## POLICY BLOCKED", "Violations:", *[f"- `{v}`" for v in result.get("violations", [])], ""]
        lines += ["No automotive intelligence was performed."]
        return "\n".join(lines)

    lines += ["## Objective", str(result.get("objective", "")), ""]
    lines += ["## Safety / Privacy / Authorization Boundaries",
              "- Passive/authorized evidence analysis only.",
              "- No live vehicle command, diagnostic bypass, key cloning, immobilizer/gateway bypass, firmware modification, safety-system tampering, private tracking, remote control, or exploitation.",
              "- VIN masked; no owner/driver inference.",
              "- CAN ID ≠ command semantics without DBC/mapping.",
              "- CVE ≠ vehicle vulnerability; vulnerability ≠ exploitation; PoC/research ≠ field exploitation.",
              "- Backend event ≠ vehicle execution.",
              "- Recall ≠ cyber vulnerability.",
              "- Safety-critical functions are analysis-only and require qualified human review.",
              ""]

    lines += ["## Vehicles / Identity"]
    for case in result.get("vehicles", [])[:200]:
        v = case.get("vehicle", {})
        ident = case.get("identity_resolution", {})
        lines.append(f"### `{v.get('vehicle_id')}`")
        lines.append(f"- Make/brand/model/year: `{v.get('make')}` / `{v.get('brand')}` / `{v.get('model')}` / `{v.get('model_year')}`")
        lines.append(f"- Generation/platform/trim/variant/region: `{v.get('generation')}` / `{v.get('platform')}` / `{v.get('trim')}` / `{v.get('variant')}` / `{v.get('region')}`")
        lines.append(f"- Powertrain: `{v.get('powertrain')}`")
        lines.append(f"- VIN reference: `{v.get('vin_masked')}` hash=`{mask_value(v.get('vin_hash'), 6, 4)}`")
        lines.append(f"- Identity states: model=`{ident.get('model_state')}` year=`{ident.get('model_year_state')}` variant=`{ident.get('variant_state')}` platform=`{ident.get('platform_state')}`")
        lines.append(f"- Source independence: `{ident.get('source_assessment', {}).get('state')}` max reliability: `{ident.get('source_assessment', {}).get('max_reliability')}`")
        lines.append("")

    lines += ["## ECUs / Components / Suppliers"]
    for e in result.get("ecus", [])[:500]:
        ass = e.get("assessment", {})
        lines.append(
            f"- ECU `{e.get('ecu_id')}` vehicle=`{e.get('vehicle_id')}` type=`{e.get('ecu_type')}` "
            f"manufacturer=`{e.get('manufacturer')}` supplier=`{e.get('supplier')}` "
            f"part={e.get('oem_part_number')}/{e.get('supplier_part_number')} "
            f"hw={e.get('hardware_version')} sw={e.get('software_version')} fw={e.get('firmware_version')} "
            f"safety_critical={e.get('safety_critical')}"
        )
        lines.append(
            f"  - states: part=`{ass.get('part_number_state')}` hw=`{ass.get('hardware_version_state')}` "
            f"sw=`{ass.get('software_version_state')}` fw=`{ass.get('firmware_version_state')}` supplier=`{ass.get('supplier_state')}`"
        )
    for s in result.get("suppliers", [])[:300]:
        lines.append(f"- Supplier `{s.get('role')}` `{s.get('name')}` ecu=`{s.get('ecu_id')}`")
    lines.append("")

    lines += ["## Network Architecture / CAN Context"]
    for n in result.get("network_buses", [])[:300]:
        lines.append(f"- Network `{n.get('record_id')}` vehicle=`{n.get('vehicle_id')}` type=`{n.get('network_type')}` bus=`{n.get('bus_name')}` segment=`{n.get('segment')}`")
    for c in result.get("can_context", [])[:200]:
        lines.append(
            f"- CAN `{c.get('vehicle_id')}` frames={c.get('frame_count')} unknown_ids={c.get('unknown_can_ids', [])[:20]} "
            f"dbc_coverage=`{c.get('dbc_coverage')}` anomalies={len(c.get('anomalies', []))}"
        )
        for a in c.get("anomalies", [])[:20]:
            lines.append(f"  - anomaly `{a.get('record_id')}` can_id={a.get('can_id')} bus=`{a.get('bus')}` status=`{a.get('status')}` maintenance=`{a.get('maintenance_context')}`")
    lines.append("")

    lines += ["## DTC / Diagnostic Context"]
    for d in result.get("dtcs", [])[:300]:
        lines.append(
            f"- DTC `{d.get('record_id')}` vehicle=`{d.get('vehicle_id')}` ecu=`{d.get('ecu_id')}` "
            f"code=`{d.get('code')}` module=`{d.get('module')}` status=`{d.get('normalized_status')}` "
            f"first={iso(d.get('first_seen'))} cleared={iso(d.get('cleared_at'))}"
        )
    lines.append("")

    lines += ["## Recalls / TSBs / Service Campaigns"]
    for r in result.get("recalls", [])[:300]:
        lines.append(
            f"- Recall `{r.get('record_id')}` vehicle=`{r.get('vehicle_id')}` authority=`{r.get('authority')}` "
            f"oem=`{r.get('oem')}` status=`{r.get('status')}` applicability=`{r.get('applicability_state')}` "
            f"issue=`{r.get('issue')}` remedy=`{r.get('remedy')}`"
        )
    for t in result.get("tsbs", [])[:300]:
        lines.append(f"- TSB `{t.get('record_id')}` vehicle=`{t.get('vehicle_id')}` applicability=`{t.get('applicability_state')}` title=`{t.get('title')}`")
    for s in result.get("service_campaigns", [])[:300]:
        lines.append(f"- Service campaign `{s.get('record_id')}` vehicle=`{s.get('vehicle_id')}` title=`{s.get('title')}` status=`{s.get('status')}`")
    lines.append("")

    lines += ["## Vulnerabilities / CVE Applicability / Exploit Context"]
    for v in result.get("vulnerabilities", [])[:500]:
        lines.append(
            f"- Vuln `{v.get('vulnerability_id')}` cve=`{v.get('cve')}` vehicle=`{v.get('vehicle_id')}` "
            f"ecu=`{v.get('ecu_id')}` applicability=`{v.get('applicability_state')}` "
            f"safety=`{v.get('safety_impact')}` remote=`{v.get('remote_exploitability')}` "
            f"exploit_avail=`{v.get('exploit_availability')}` known_exploitation={v.get('known_exploitation_reported')}"
        )
        lines.append(f"  - reason: {v.get('applicability_reason')}")
        if v.get("mitigations"):
            lines.append(f"  - mitigations: {', '.join(str(x) for x in v.get('mitigations', [])[:10])}")
    lines.append("")

    lines += ["## OTA / Patch State"]
    for o in result.get("ota_updates", [])[:300]:
        lines.append(
            f"- OTA `{o.get('record_id')}` vehicle=`{o.get('vehicle_id')}` ecu=`{o.get('ecu_id')}` "
            f"campaign=`{o.get('campaign')}` target=`{o.get('target_version')}` state=`{o.get('ota_state')}` "
            f"installed={o.get('installed')} verified={o.get('installation_verified')}"
        )
    lines.append("")

    lines += ["## Connectivity / Telematics / Mobile / Backend / Cloud"]
    for t in result.get("telematics_context", [])[:300]:
        lines.append(f"- Telematics `{t.get('record_id')}` vehicle=`{t.get('vehicle_id')}` provider=`{t.get('provider')}` service=`{t.get('service')}` capabilities={t.get('capabilities', [])[:10]}")
    for a in result.get("mobile_apps", [])[:300]:
        lines.append(f"- Mobile app `{a.get('record_id')}` vehicle=`{a.get('vehicle_id')}` name=`{a.get('name')}` platform=`{a.get('platform')}` package=`{a.get('package')}` version=`{a.get('version')}`")
    for b in result.get("backend_services", [])[:300]:
        lines.append(f"- Backend `{b.get('record_id')}` vehicle=`{b.get('vehicle_id')}` service=`{b.get('service')}` provider=`{b.get('provider')}` role=`{b.get('role')}` endpoint=`{mask_value(b.get('endpoint'),4,2)}`")
    for c in result.get("cloud_dependencies", [])[:300]:
        lines.append(f"- Cloud `{c.get('record_id')}` vehicle=`{c.get('vehicle_id')}` provider=`{c.get('provider')}` service=`{c.get('service')}` role=`{c.get('role')}` endpoint=`{mask_value(c.get('endpoint'),4,2)}`")
    lines.append("")

    lines += ["## Certificates / SBOM / Secure Context"]
    for c in result.get("certificates", [])[:300]:
        lines.append(f"- Certificate `{c.get('record_id')}` vehicle=`{c.get('vehicle_id')}` role=`{c.get('role')}` subject=`{c.get('subject')}` issuer=`{c.get('issuer')}` fp=`{mask_value(c.get('fingerprint'),6,4)}`")
    for s in result.get("sboms", [])[:300]:
        lines.append(f"- SBOM `{s.get('record_id')}` vehicle=`{s.get('vehicle_id')}` format=`{s.get('format')}` generated=`{iso(s.get('generated_at'))}` components={len(s.get('components', []))}")
    lines.append("")

    lines += ["## Incidents / Safety Impact / Risk Dimensions"]
    for i in result.get("incident_context", [])[:300]:
        lines.append(
            f"- Incident `{i.get('record_id')}` vehicle=`{i.get('vehicle_id')}` type=`{i.get('incident_type')}` "
            f"state=`{i.get('incident_state')}` occurred=`{iso(i.get('occurred_at'))}` maintenance=`{i.get('maintenance_context')}` "
            f"safety=`{i.get('safety_impact')}` backend_not_executed={i.get('backend_event_not_vehicle_execution')}"
        )
    for s in result.get("safety_impact", [])[:200]:
        lines.append(f"- Safety `{s.get('vehicle_id')}` flags={s.get('safety_flags', [])}")
        lines.append(f"  - risk dimensions: `{json.dumps(json_safe(s.get('risk_dimensions', {})), ensure_ascii=False, default=str)}`")
    lines.append("")

    lines += ["## Source Independence / Reliability / Bias"]
    for si in result.get("source_independence", [])[:300]:
        lines.append(f"- Vehicle `{si.get('vehicle_id')}` source independence=`{si.get('state')}` max_reliability=`{si.get('max_reliability')}`")
    for sr in result.get("source_reliability", [])[:300]:
        lines.append(f"- Source `{sr.get('source_id')}` type=`{sr.get('source_type')}` reliability={sr.get('reliability')}")
    for sb in result.get("source_bias", [])[:300]:
        lines.append(f"- Source `{sb.get('source_id')}` type=`{sb.get('source_type')}` bias={sb.get('potential_bias', [])} limitations={sb.get('limitations', [])[:5]}")
    lines.append("")

    lines += ["## Contradictions"]
    for c in result.get("contradictions", [])[:300]:
        lines.append(f"- `{c.get('contradiction_id')}` [{c.get('severity')}] {c.get('type')}: {c.get('detail')}")
        if c.get("possible_causes"):
            lines.append(f"  - possible causes: {'; '.join(str(x) for x in c.get('possible_causes', [])[:10])}")
    lines.append("")

    lines += ["## Competing Hypotheses / Falsification"]
    for h in result.get("hypotheses", [])[:500]:
        lines.append(f"- `{h.get('hypothesis_id')}` [{h.get('category')}] {h.get('subject_type')} `{h.get('subject_id')}`: {h.get('statement')}")
        if h.get("falsification_conditions"):
            lines.append(f"  - falsify if: {'; '.join(str(x) for x in h.get('falsification_conditions', [])[:5])}")
    lines.append("")

    lines += ["## Knowledge Gaps"]
    for g in result.get("knowledge_gaps", [])[:500]:
        lines.append(f"- `{g.get('gap_id')}` [{g.get('importance')}] {g.get('type')}: {g.get('recommended_source')}")
    lines.append("")

    lines += ["## Recommended Safe Next Actions"]
    for a in result.get("recommended_next_actions", [])[:500]:
        lines.append(f"- [{a.get('priority')}] {a.get('action')}")
        if a.get("prohibited_alternatives"):
            lines.append(f"  - prohibited: {'; '.join(str(x) for x in a.get('prohibited_alternatives', [])[:5])}")
    lines.append("")

    lines += ["## Specialist Handoffs"]
    for h in result.get("specialist_handoffs", []):
        lines.append(f"- {h.get('specialist')}: {h.get('reason')}")
        lines.append(f"  - payload: `{json.dumps(json_safe(h.get('payload', {})), ensure_ascii=False, default=str)}`"[:1000])
    lines.append("")

    lines += ["## Dual-AI Review Stub"]
    dr = result.get("dual_ai_review", {})
    lines.append(f"- Status: `{dr.get('status')}`")
    lines.append(f"- Comparison: `{dr.get('comparison')}`")
    for n in dr.get("notes", []):
        lines.append(f"- {n}")
    for c in dr.get("primary_conclusions", [])[:50]:
        lines.append(f"- Primary: {c}")
    for c in dr.get("skeptic_challenges", [])[:50]:
        lines.append(f"- Skeptic: {c}")
    lines.append("")

    lines += ["## Limitations"]
    for lim in result.get("limitations", []):
        lines.append(f"- {lim}")
    lines.append("")

    lines += [
        "## Non-Negotiable Boundary",
        "- Resolve the vehicle.",
        "- Resolve the variant.",
        "- Resolve the component.",
        "- Resolve the exact version.",
        "- Verify the supplier.",
        "- Verify the interface.",
        "- Check the recall range.",
        "- Check the patch state.",
        "- Separate lab research from field exploitation.",
        "- Separate cyber impact from safety impact.",
        "- Test only in authorized safe environments.",
        "- Never turn vehicle intelligence into vehicle takeover guidance.",
    ]

    return "\n".join(lines)


# --------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="TRACEATLAS AUTOMOTIVEINT safe defensive starter")
    parser.add_argument("--manifest", required=True, help="Path to AUTOMOTIVEINT manifest JSON")
    parser.add_argument("--output", default="automotiveint_result.json", help="Output JSON path")
    parser.add_argument("--report", default="automotiveint_report.md", help="Output Markdown report path")
    args = parser.parse_args()

    try:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"ERROR reading manifest: {exc}", file=sys.stderr)
        return 2

    result = analyze_automotiveint_manifest(manifest)

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

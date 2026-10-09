import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import json
import re
import csv
import hashlib
import uuid

from collections import defaultdict, Counter
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


APP_TITLE = "TraceAtlas AVIINT AI Employee — Lawful / Public-Authorized / Evidence-First / Safety-Aware Aviation Intelligence Panel"
APP_VERSION = "TraceAtlas AVIINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target_aircraft_or_flight", "Target Aircraft / Registration / Flight Context", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "AVIINT Questions", "text"),

    ("aircraft", "Aircraft (Reg/ICAO/Type)", "text"),
    ("operators", "Operators / Owners / Lessors", "text"),
    ("flights", "Flights / Callsigns / Routes", "text"),
    ("airports", "Airports / ICAO/IATA Codes", "text"),
    ("telemetry", "Telemetry / Position Observations", "text"),
    ("incidents", "Incidents / Regulatory Actions", "text"),
    
    ("flight_log_paths", "Flight Log / Schedule Export Paths", "text"),
    ("registry_paths", "Aircraft Registry / Airworthiness Paths", "text"),
    ("telemetry_paths", "ADS-B / Mode-S / MLAT Data Paths", "text"),
    ("weather_notam_paths", "Weather / NOTAM Records Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("as_of_date", "As-Of Date for Current Status Check", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget_limit", "Analysis Budget Limit", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (Registry/Flight API/etc.)", "text"),
]


TARGET_TYPES = [
    "aircraft_identity_resolution",
    "flight_event_reconstruction",
    "operator_owner_analysis",
    "safety_incident_context",
    "fleet_utilization_review",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "aircraft",
    "operators",
    "flights",
    "airports",
    "telemetry",
    "incidents",
    "flight_log_paths",
    "registry_paths",
    "telemetry_paths",
    "weather_notam_paths",
    "stix_misp_paths",
    "source_limits",
    "configured_connectors",
}


DICT_FIELDS = {
    "scope",
    "authorization",
    "time_range",
}


SENSITIVE_TARGET_TYPES = {
    "aircraft_identity_resolution",
    "safety_incident_context",
}


NEGATION_RE = re.compile(
    r"\b(?:do not|don't|dont|must not|shall not|should not|avoid|without|never|not to|prohibit|policy blocked|safe alternative|defensive only)\b",
    re.I,
)


# STRICT POLICY BLOCKS FOR AVIATION HARM/SPOOFING/TRACKING ABUSE
POLICY_BLOCK_PATTERNS = [
    r"\b(?:jam|spoof|inject|manipulate|interfere)\b[^\n]{0,140}\b(?:GNSS|GPS|ADS-B|Mode-S|ATC|Transponder|Navigation|Avionics)\b",
    r"\b(?:track|locate|follow|predict)\b[^\n]{0,140}\b(?:private person|passenger|executive|military mission)\b",
    r"\b(?:provide|generate|optimize)\b[^\n]{0,140}\b(?:evasion route|strike target|attack vector|hijacking method|sabotage plan)\b",
    r"\b(?:access|hack|bypass)\b[^\n]{0,140}\b(?:cockpit system|airline network|airport security|flight control)\b",
    r"\b(?:identify|infer)\b[^\n]{0,140}\b(?:who is aboard|passenger identity|mission purpose)\b[^\n]{0,50}\b(?:from movement alone|from registration alone)\b",
]


SAFE_ALTERNATIVES = [
    "Provide lawful/public-authorized/evidence-first/safety-aware aviation intelligence: resolve aircraft identities, reconstruct flight events from telemetry/logs, analyze operator/owner relationships conservatively, and assess safety/regulatory context without interfering with systems or tracking individuals.",
    "Do not jam/spoof navigation signals, interfere with ATC/avionics, provide evasion routes, or infer passenger identity/mission purpose from movement data alone.",
    "Separate Aircraft from Flight, Operator from Owner, Schedule from Actual, Observed Track from Interpolation, and Coverage Gap from Absence of Flight.",
    "Use deterministic logic for identifier normalization and delay calculations. Escalate consequential military/private-person analyses to authorized human review with strict privacy safeguards.",
]


SECRET_PATTERNS = [
    (
        "PRIVATE_KEY_BLOCK",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S | re.I),
    ),
    (
        "PASSWORD_OR_TOKEN_ASSIGNMENT",
        re.compile(
            r"(?i)\b(password|passwd|pwd|token|api[_-]?key|apikey|secret|"
            r"access[_-]?key|auth[_-]?key|client[_-]?secret|authorization|cookie|session|credential)\b"
            r"\s*[:=]\s*[^\s,;\"']+"
        ),
    ),
    (
        "BEARER_TOKEN",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+/=]{8,}"),
    ),
]


PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?previous\s+(?:instructions|rules)",
    r"reveal\s+(?:the\s+)?system\s+prompt",
    r"execute\s+(?:this\s+)?(?:script|code|macro)",
    r"send\s+(?:this\s+)?(?:document|data)",
    r"delete\s+(?:the\s+)?(?:record|log)",
    r"change\s+(?:the\s+)?(?:route|altitude|heading)",
]


# Regex helpers for Aviation identifiers
REG_RE = re.compile(r"\b([A-Z]{1,2}-[A-Z0-9]{1,5}|N\d{1,5}[A-Z]{0,3}|G-[A-Z]{4}|F-[A-Z]{4})\b") # Simplified Reg patterns
ICAO_ADDR_RE = re.compile(r"\b[A-Fa-f0-9]{6}\b") # Hex address
AIRPORT_CODE_RE = re.compile(r"\b([A-Z]{3}|[A-Z]{4})\b") # IATA (3) / ICAO (4) - heuristic


ENTITY_ROLE_KEYS = [
    "aircraft",
    "registration",
    "icao_address",
    "operator",
    "owner",
    "lessor",
    "lessee",
]


FLIGHT_KEYS = [
    "flight",
    "callsign",
    "trip",
    "service",
]


AIRPORT_KEYS = [
    "airport",
    "origin",
    "destination",
    "diverted_to",
    "aerodrome",
]


TELEMETRY_KEYS = [
    "position",
    "obs",
    "track_point",
    "adsb",
    "modes",
]


INCIDENT_KEYS = [
    "incident",
    "accident",
    "event",
    "regulatory_action",
]


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().lower()


def normalize_key(value: Any) -> str:
    s = str(value or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    return s.strip("_")


def parse_list(value: str) -> List[Any]:
    value = str(value or "").strip()
    if not value:
        return []

    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return [parsed]
    except Exception:
        pass

    normalized = value.replace(",", "\n")
    parts = [p.strip() for p in normalized.splitlines()]
    return [p for p in parts if p]


def parse_dict(value: str) -> Dict[str, Any]:
    value = str(value or "").strip()
    if not value:
        return {}

    try:
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    result: Dict[str, Any] = {}
    for line in value.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, val = line.split(":", 1)
        result[key.strip()] = val.strip()
    return result


def listify(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return [value]


def unique_preserve_order(items: List[Any]) -> List[Any]:
    seen = set()
    out = []
    for item in items:
        key = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str) if isinstance(item, (dict, list)) else str(item)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def truncate_list(items: List[Any], limit: int) -> Tuple[List[Any], bool]:
    if len(items) <= limit:
        return items, False
    return items[:limit], True


def sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def redact_secrets(text: str) -> Tuple[str, List[str]]:
    flags: List[str] = []
    if not text:
        return "", flags

    out = text
    for name, rx in SECRET_PATTERNS:
        if rx.search(out):
            flags.append(name)
            out = rx.sub("[REDACTED_SECRET]", out)

    return out, sorted(set(flags))


def detect_prompt_injection(text: str) -> List[str]:
    flags: List[str] = []
    low = normalize_text(text)
    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, low, re.I):
            flags.append(pattern)
    return sorted(set(flags))


def safe_str(value: Any, limit: int = 300) -> str:
    return redact_secrets(str(value or ""))[0].strip()[:limit]


def content_tokens(text: str) -> List[str]:
    redacted, _ = redact_secrets(str(text or ""))
    low = normalize_text(redacted)
    return re.findall(r"[a-z0-9]+", low)


def content_fingerprint(text: str) -> str:
    tokens = content_tokens(text)
    if not tokens:
        return ""
    return sha256_text(" ".join(sorted(set(tokens))))[:32]


def get_field(rec: Dict[str, Any], keys: List[str], as_list: bool = False) -> Any:
    if not isinstance(rec, dict):
        return [] if as_list else None

    lower = {normalize_key(k): v for k, v in rec.items()}
    for key in keys:
        nk = normalize_key(key)
        if nk in lower and lower[nk] not in (None, ""):
            val = lower[nk]
            if as_list:
                return listify(val)
            if isinstance(val, list):
                return val[0] if val else None
            return val
    return [] if as_list else None


def validate_registration(reg_str: str) -> bool:
    """Basic structural validation for aircraft registration."""
    if not reg_str:
        return False
    clean = reg_str.strip().upper().replace(" ", "")
    # Common patterns: US N..., UK G-..., FR F-..., DE D-..., etc.
    # This is a simplified check. Real validation requires registry lookup.
    if re.match(r"^N\d{1,5}[A-Z]{0,3}$", clean): # USA
        return True
    if re.match(r"^[A-Z]{1,2}-[A-Z0-9]{1,5}$", clean): # Generic Prefix-Dash-Suffix
        return True
    return False


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "aircraft": [],
        "registrations": [],
        "operators": [],
        "owners": [],
        "flights": [],
        "airports": [],
        "positions": [],
        "incidents": [],
        "observations": [],
        "notes": [],
        "contradictions": [],
        "hypotheses": [],
        "knowledge_gaps": [],
        "specialist_handoffs": [],
        "risk_dimensions": {},
    }


def add_note(parsed: Dict[str, Any], note_type: str, **kwargs: Any) -> None:
    if len(parsed.get("notes", [])) >= 200000:
        return
    note = {"type": note_type}
    note.update(kwargs)
    parsed["notes"].append(note)


def add_observation(parsed: Dict[str, Any], statement: str, source_id: str, evidence_id: str, context: str = "") -> None:
    if len(parsed.get("observations", [])) >= 200000:
        return

    redacted, secret_flags = redact_secrets(str(statement or "")[:1000])
    injection_flags = detect_prompt_injection(str(statement or ""))

    parsed["observations"].append({
        "observation_id": f"OBS-{uuid.uuid4()}",
        "statement": redacted,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": context[:200],
        "state": "SOURCE_OBSERVED",
        "secret_flags": secret_flags,
        "prompt_injection_flags": injection_flags,
        "content_hash": sha256_text(str(statement or "")),
        "limitations": [
            "Observation records what was reported/logged, not necessarily its verified operational truth.",
            "Telemetry data can have coverage gaps, latency, or metadata errors.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Embedded instructions in aviation docs are ignored.")


def add_source(
    parsed: Dict[str, Any],
    source_id: str,
    evidence_id: str,
    filename: str = "",
    file_hash: str = "",
    publisher: str = "",
    title: str = "",
    source_type: str = "",
    markings: str = "",
    content_fp: str = "",
) -> None:
    for s in parsed["sources"]:
        if s.get("source_id") == source_id:
            if file_hash and not s.get("file_hash"):
                s["file_hash"] = file_hash
            if publisher and not s.get("publisher"):
                s["publisher"] = publisher
            if title and not s.get("title"):
                s["title"] = title
            if content_fp and not s.get("content_fingerprint"):
                s["content_fingerprint"] = content_fp
            return

    parsed["sources"].append({
        "source_id": source_id,
        "evidence_id": evidence_id,
        "filename": filename,
        "file_hash": file_hash,
        "publisher": publisher,
        "title": title,
        "source_type": source_type or "UNKNOWN",
        "markings": markings,
        "content_fingerprint": content_fp,
        "retrieved_at": now_utc(),
        "state": "SOURCE_REGISTERED",
        "source_independence_state": "UNKNOWN",
        "limitations": [
            "Source registration is local provenance metadata.",
            "Multiple tracker sites using same upstream ADS-B feed are not independent sources.",
        ],
    })


def add_aircraft(
    parsed: Dict[str, Any],
    reg: Any,
    icao_addr: Any,
    ac_type: Any,
    manufacturer: Any,
    serial: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    r = safe_str(reg, 50)
    ia = safe_str(icao_addr, 20)
    
    if not r and not ia:
        return None
        
    aid = f"AC-{uuid.uuid4()}"
    
    reg_valid = validate_registration(r) if r else False
    
    parsed["aircraft"].append({
        "aircraft_id": aid,
        "registration": r,
        "registration_valid_structural": reg_valid,
        "icao_address": ia,
        "aircraft_type_model": safe_str(ac_type, 100),
        "manufacturer": safe_str(manufacturer, 100),
        "serial_number": safe_str(serial, 50),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "AIRCRAFT_PARSED",
        "limitations": [
            "Registration changes over time. Era matters.",
            "ICAO Address may persist across operator changes.",
        ],
    })
    return aid


def add_operator(
    parsed: Dict[str, Any],
    name: Any,
    role: Any, # OPERATOR/OWNER/LESSOR
    iata_code: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None
        
    oid = f"OP-{uuid.uuid4()}"
    
    parsed["operators"].append({
        "operator_id": oid,
        "name": n,
        "role": safe_str(role, 50).upper() or "OPERATOR",
        "iata_code": safe_str(iata_code, 5),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "OPERATOR_PARSED",
        "limitations": [
            "Marketing Carrier != Operating Carrier.",
            "Owner != Operator.",
        ],
    })
    return oid


def add_flight(
    parsed: Dict[str, Any],
    fl_num: Any,
    callsign: Any,
    origin_ap: Any,
    dest_ap: Any,
    sched_dep: Any,
    actual_dep: Any,
    sched_arr: Any,
    actual_arr: Any,
    status: Any,
    aircraft_ref: Any,
    operator_ref: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    fid = f"FLT-{uuid.uuid4()}"
    
    stat_norm = normalize_text(status).upper()
    canonical_stat = "UNKNOWN"
    if "DEPARTED" in stat_norm or "AIRBORNE" in stat_norm:
        canonical_stat = "DEPARTED"
    elif "ARRIVED" in stat_norm or "LANDED" in stat_norm:
        canonical_stat = "ARRIVED"
    elif "DIVERTED" in stat_norm:
        canonical_stat = "DIVERTED"
    elif "CANCELLED" in stat_norm:
        canonical_stat = "CANCELLED"
        
    parsed["flights"].append({
        "flight_id": fid,
        "flight_number": safe_str(fl_num, 20),
        "callsign": safe_str(callsign, 20),
        "origin_airport_ref": origin_ap,
        "dest_airport_ref": dest_ap,
        "scheduled_departure": safe_str(sched_dep, 100),
        "actual_departure": safe_str(actual_dep, 100),
        "scheduled_arrival": safe_str(sched_arr, 100),
        "actual_arrival": safe_str(actual_arr, 100),
        "status": canonical_stat,
        "aircraft_ref": aircraft_ref,
        "operator_ref": operator_ref,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "FLIGHT_PARSED",
        "limitations": [
            "One physical flight may have multiple commercial numbers (codeshare).",
            "Scheduled time is not observed time.",
        ],
    })


def add_position(
    parsed: Dict[str, Any],
    aircraft_ref: Any,
    lat: Any,
    lon: Any,
    alt_ft: Any,
    gs_kt: Any,
    track_deg: Any,
    timestamp: Any,
    source_type: Any, # ADSB/MODES/MLAT/RADAR
    quality: Any, # DIRECT/DERIVED/INTERPOLATED
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    pid = f"POS-{uuid.uuid4()}"
    
    qual_norm = normalize_text(quality).upper()
    canonical_qual = "DIRECT"
    if "INTERPOLATED" in qual_norm:
        canonical_qual = "INTERPOLATED"
    elif "DERIVED" in qual_norm or "MLAT" in qual_norm:
        canonical_qual = "DERIVED"
        
    parsed["positions"].append({
        "position_id": pid,
        "aircraft_ref": aircraft_ref,
        "latitude": lat,
        "longitude": lon,
        "altitude_feet": alt_ft,
        "ground_speed_knots": gs_kt,
        "track_degrees": track_deg,
        "timestamp": safe_str(timestamp, 100),
        "source_type": safe_str(source_type, 50).upper() or "UNKNOWN",
        "telemetry_quality": canonical_qual,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "POSITION_PARSED",
        "limitations": [
            "Position observation does not prove intent or destination.",
            "Interpolated points are estimates, not observations.",
        ],
    })


def process_json_record(
    rec: Dict[str, Any],
    source_id: str,
    evidence_id: str,
    parsed: Dict[str, Any],
    context: str = "",
) -> None:
    if not isinstance(rec, dict):
        return

    rec_ctx = context or "json_record"

    text_blob = json.dumps(rec, ensure_ascii=False, default=str)[:12000]
    process_text_block(text_blob, source_id, evidence_id, parsed, context=rec_ctx)

    # Resolve Aircraft
    ac_refs = []
    for key in ["aircraft", "registration", "tail"]:
        vals = get_field(rec, [key], as_list=True)
        for val in vals:
            if isinstance(val, dict):
                areg = val.get("registration") or val.get("tail") or val.get("id")
                aica = val.get("icao_address") or val.get("hex")
                atype = val.get("type") or val.get("model")
                aman = val.get("manufacturer")
                aser = val.get("serial")
            else:
                areg = str(val)
                aica = ""
                atype = ""
                aman = ""
                aser = ""
            
            aref = add_aircraft(parsed, areg, aica, atype, aman, aser, source_id, evidence_id, f"{rec_ctx}/{key}")
            if aref:
                ac_refs.append(aref)
                
    primary_ac_ref = ac_refs[0] if ac_refs else None

    # Resolve Operators/Owners
    op_refs = {}
    for key in ["operator", "owner", "lessor", "carrier"]:
        vals = get_field(rec, [key], as_list=True)
        for val in vals:
            if isinstance(val, dict):
                oname = val.get("name") or val.get("id")
                orole = val.get("role") or key.upper()
                oiata = val.get("iata") or val.get("code")
            else:
                oname = str(val)
                orole = key.upper()
                oiata = ""
            
            oref = add_operator(parsed, oname, orole, oiata, source_id, evidence_id, f"{rec_ctx}/{key}")
            if oref:
                op_refs[normalize_text(oname)] = oref
                
    primary_op_ref = list(op_refs.values())[0] if op_refs else None

    # Resolve Flights
    flt_items = get_field(rec, FLIGHT_KEYS, as_list=True)
    for item in flt_items:
        if isinstance(item, dict):
            add_flight(
                parsed,
                item.get("number") or item.get("flight_no"),
                item.get("callsign"),
                item.get("origin") or item.get("dep_airport"),
                item.get("destination") or item.get("arr_airport"),
                item.get("sched_dep") or item.get("std"),
                item.get("actual_dep") or item.get("atd"),
                item.get("sched_arr") or item.get("sta"),
                item.get("actual_arr") or item.get("ata"),
                item.get("status"),
                item.get("aircraft") or primary_ac_ref,
                item.get("operator") or primary_op_ref,
                source_id,
                evidence_id,
                f"{rec_ctx}/flight"
            )

    # Resolve Positions
    pos_items = get_field(rec, TELEMETRY_KEYS, as_list=True)
    for item in pos_items:
        if isinstance(item, dict):
            add_position(
                parsed,
                item.get("aircraft") or primary_ac_ref,
                item.get("lat") or item.get("latitude"),
                item.get("lon") or item.get("longitude"),
                item.get("alt") or item.get("altitude"),
                item.get("gs") or item.get("speed"),
                item.get("track") or item.get("hdg"),
                item.get("time") or item.get("timestamp"),
                item.get("source") or item.get("type"),
                item.get("quality") or "DIRECT",
                source_id,
                evidence_id,
                f"{rec_ctx}/position"
            )


def process_text_block(
    text: str,
    source_id: str,
    evidence_id: str,
    parsed: Dict[str, Any],
    context: str = "",
) -> None:
    raw = str(text or "")
    if not raw.strip():
        return

    redacted, secret_flags = redact_secrets(raw)
    injection_flags = detect_prompt_injection(raw)

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Aviation texts are untrusted data.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    low = normalize_text(redacted)
    signals = []

    if any(k in low for k in ["takeoff", "departure", "lift off"]):
        signals.append("DEPARTURE_EVENT")
    if any(k in low for k in ["landing", "touchdown", "arrival"]):
        signals.append("ARRIVAL_EVENT")
    if any(k in low for k in ["diversion", "return", "turnback"]):
        signals.append("DISRUPTION_EVENT")
    if any(k in low for k in ["adsb", "mode-s", "radar", "mlat"]):
        signals.append("TELEMETRY_CONTEXT")
    if any(k in low for k in ["accident", "incident", "bird strike", "mechanical"]):
        signals.append("SAFETY_INCIDENT_CONTEXT")

    if signals:
        add_note(parsed, "AV_SIGNAL", signals=unique_preserve_order(signals), source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Signals indicate analytical attention, not verified facts.")


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY_AV_DATA"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:30000].lower()
    fname = normalize_text(filename)

    if "flight" in fname or "schedule" in fname or "ops" in fname:
        return "FLIGHT_SCHEDULE_LOG"
    if "registry" in fname or "aircraft" in fname or "detail" in fname:
        return "AIRCRAFT_REGISTRY_DETAIL"
    if "pos" in fname or "track" in fname or "adsb" in fname:
        return "TELEMETRY_POSITION_DATA"
    if "incident" in fname or "report" in fname:
        return "SAFETY_INCIDENT_REPORT"

    return "GENERIC_AV_EVIDENCE"


def walk_json(
    data: Any,
    source_id: str,
    evidence_id: str,
    parsed: Dict[str, Any],
    depth: int = 0,
    path: str = "",
) -> None:
    if depth > 14 or len(parsed.get("observations", [])) > 200000:
        return

    if isinstance(data, dict):
        process_json_record(data, source_id, evidence_id, parsed, context=path or "json")
        for k, v in data.items():
            new_path = f"{path}.{k}" if path else str(k)
            walk_json(v, source_id, evidence_id, parsed, depth + 1, new_path)
    elif isinstance(data, list):
        for item in data[:100000]:
            walk_json(item, source_id, evidence_id, parsed, depth + 1, path)
    elif isinstance(data, str):
        process_text_block(data, source_id, evidence_id, parsed, context=path or "json_string")


def process_json_file(path: Path, source_id: str, evidence_id: str) -> Tuple[str, Dict[str, Any]]:
    parsed = empty_parsed()
    raw = path.read_text(encoding="utf-8", errors="replace")[:30_000_000]
    redacted_raw, _ = redact_secrets(raw)
    fp = content_fingerprint(redacted_raw)
    data = json.loads(raw)
    kind = classify_json_payload(data, path.name)

    add_source(
        parsed,
        source_id,
        evidence_id,
        filename=path.name,
        file_hash=sha256_file(path),
        source_type=kind,
        content_fp=fp,
    )

    walk_json(data, source_id, evidence_id, parsed)
    return kind, parsed


def process_csv_file(path: Path, source_id: str, evidence_id: str) -> Tuple[str, Dict[str, Any]]:
    parsed = empty_parsed()
    raw = path.read_text(encoding="utf-8", errors="replace")[:30_000_000]
    redacted_raw, _ = redact_secrets(raw)
    fp = content_fingerprint(redacted_raw)
    kind = "CSV_AV_DATA"

    add_source(
        parsed,
        source_id,
        evidence_id,
        filename=path.name,
        file_hash=sha256_file(path),
        source_type=kind,
        content_fp=fp,
    )

    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        sample = f.read(1_000_000)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t| ")
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(f, dialect=dialect)
        for idx, row in enumerate(reader):
            if idx >= 200000:
                break
            process_json_record(row, source_id, evidence_id, parsed, context=f"csv_row_{idx}")

    return kind, parsed


def process_text_file(path: Path, source_id: str, evidence_id: str) -> Tuple[str, Dict[str, Any]]:
    parsed = empty_parsed()
    raw = path.read_text(encoding="utf-8", errors="replace")[:10_000_000]
    redacted_raw, _ = redact_secrets(raw)
    fp = content_fingerprint(redacted_raw)

    low = redacted_raw.lower()[:30000]
    if "flight" in low or "schedule" in low:
        kind = "TEXT_FLIGHT_LOG"
    elif "registry" in low or "aircraft" in low:
        kind = "TEXT_AIRCRAFT_RECORD"
    elif "incident" in low or "report" in low:
        kind = "TEXT_SAFETY_REPORT"
    else:
        kind = "TEXT_GENERIC_AV_DOC"

    add_source(
        parsed,
        source_id,
        evidence_id,
        filename=path.name,
        file_hash=sha256_file(path),
        source_type=kind,
        content_fp=fp,
    )

    for line_no, line in enumerate(raw.splitlines()[:200000]):
        if line.strip():
            process_text_block(line, source_id, evidence_id, parsed, context=f"text_line_{line_no}")

    return kind, parsed


def detect_format(path: Path) -> Dict[str, str]:
    suffix = path.suffix.lower()

    try:
        with path.open("rb") as f:
            head = f.read(256)
    except Exception as exc:
        return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream", "format_error": str(exc)}

    binary_suffixes = {
        ".exe", ".dll", ".sys", ".elf", ".so", ".dylib", ".bin", ".fw", ".img",
        ".iso", ".apk", ".jar", ".class", ".zip", ".gz", ".tar", ".7z", ".rar",
        ".pcap", ".pcapng", ".cap", ".msi", ".cab", ".pdf", ".docx", ".xlsx",
        ".pptx", ".mp3", ".wav", ".mp4", ".avi",
    }

    if suffix in binary_suffixes:
        return {"format_detected": "BINARY_ARTIFACT", "mime_type": "application/octet-stream"}

    stripped = head.lstrip()

    if suffix == ".json" or stripped.startswith(b"{") or stripped.startswith(b"["):
        return {"format_detected": "JSON", "mime_type": "application/json"}

    if suffix in {".csv", ".tsv"}:
        return {"format_detected": "CSV", "mime_type": "text/csv"}

    if b"," in head and b"\n" in head and all(b in b"\x09\x0a\x0d\x20" or 32 <= b <= 126 for b in head[:64]):
        return {"format_detected": "CSV", "mime_type": "text/csv"}

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".snapshot", ".eml", ".msg", ".av", ".flight"}:
        return {"format_detected": "TEXT", "mime_type": "text/plain"}

    try:
        probe = head.decode("utf-8", errors="strict")
        if probe.strip():
            return {"format_detected": "TEXT", "mime_type": "text/plain"}
    except Exception:
        pass

    return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream"}


def analyze_av_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
    path = Path(path_str).expanduser()
    source_id = f"SRC-{uuid.uuid4()}"
    evidence_id = f"EVD-{uuid.uuid4()}"

    file_evidence: Dict[str, Any] = {
        "evidence_id": evidence_id,
        "source_id": source_id,
        "case_id": case_id,
        "task_id": task_id,
        "path": str(path),
        "filename": path.name,
        "retrieved_at": now_utc(),
        "acquisition_method": "local_authorized_or_public_file_access",
        "status": "PENDING",
        "limitations": [
            "No aircraft interference, no GNSS/ADS-B spoofing, no private tracking.",
            "Binary artifacts are hash/metadata preserved only.",
            "Aviation documents are untrusted data, not instruction.",
            "Exposed secrets were redacted and not used.",
            "Schedule != Actual. Gap != Absence.",
        ],
    }

    parsed = empty_parsed()

    if not path.exists():
        file_evidence["status"] = "FAILED_FILE_NOT_FOUND"
        return file_evidence, parsed

    try:
        st = path.stat()
        file_evidence["size_bytes"] = st.st_size
        file_evidence["filesystem_modified_at"] = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
    except Exception as exc:
        file_evidence["status"] = "FAILED_STAT"
        file_evidence["error"] = str(exc)
        return file_evidence, parsed

    try:
        file_evidence["sha256"] = sha256_file(path)
    except Exception as exc:
        file_evidence["sha256_error"] = str(exc)

    fmt = detect_format(path)
    file_evidence.update(fmt)
    format_detected = file_evidence.get("format_detected", "UNKNOWN")

    try:
        if format_detected == "JSON":
            kind, parsed = process_json_file(path, source_id, evidence_id)
            file_evidence["content_kind"] = kind
            file_evidence["status"] = "SUCCEEDED"
        elif format_detected == "CSV":
            kind, parsed = process_csv_file(path, source_id, evidence_id)
            file_evidence["content_kind"] = kind
            file_evidence["status"] = "SUCCEEDED"
        elif format_detected == "TEXT":
            kind, parsed = process_text_file(path, source_id, evidence_id)
            file_evidence["content_kind"] = kind
            file_evidence["status"] = "SUCCEEDED"
        elif format_detected == "BINARY_ARTIFACT":
            file_evidence["content_kind"] = "BINARY_AV_DOC_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary aviation document detected. This planning panel preserves hash/metadata only. "
                "It does not execute macros, parse PDF/DOCX deeply, or access restricted systems."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_ac_count"] = len(parsed.get("aircraft", []))
    file_evidence["parsed_fl_count"] = len(parsed.get("flights", []))
    file_evidence["parsed_pos_count"] = len(parsed.get("positions", []))

    return file_evidence, parsed


def aggregate_parsed(parsed_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    agg = empty_parsed()
    for p in parsed_list:
        for key in agg.keys():
            if isinstance(agg[key], list) and isinstance(p.get(key), list):
                agg[key].extend(p[key])
        for key in agg.keys():
            if isinstance(agg[key], list):
                agg[key] = unique_preserve_order(agg[key])[:200000]
    return agg


def build_source_independence(parsed: Dict[str, Any]) -> None:
    sources = parsed.get("sources", [])
    hash_groups: Dict[str, List[str]] = defaultdict(list)
    fp_groups: Dict[str, List[str]] = defaultdict(list)
    publisher_groups: Dict[str, List[str]] = defaultdict(list)

    for s in sources:
        sid = s.get("source_id")
        fh = s.get("file_hash")
        fp = s.get("content_fingerprint")
        pub = normalize_text(s.get("publisher") or "")
        if fh:
            hash_groups[fh].append(sid)
        if fp:
            fp_groups[fp].append(sid)
        if pub:
            publisher_groups[pub].append(sid)

    for s in sources:
        fh = s.get("file_hash")
        fp = s.get("content_fingerprint")
        pub = normalize_text(s.get("publisher") or "")

        if fh and len(hash_groups.get(fh, [])) > 1:
            s["source_independence_state"] = "DEPENDENT_COPIES"
            s["source_family_count"] = 1
        elif fp and len(fp_groups.get(fp, [])) > 1:
            s["source_independence_state"] = "DEPENDENT_CONTENT_FAMILY"
            s["source_family_count"] = 1
        elif pub and len(publisher_groups.get(pub, [])) > 1:
            s["source_independence_state"] = "PARTIALLY_DEPENDENT_PENDING_REVIEW"
            s["source_family_count"] = 1
        elif len(sources) > 1:
            s["source_independence_state"] = "UNKNOWN_POTENTIALLY_INDEPENDENT"
            s["source_family_count"] = len(sources)
        else:
            s["source_independence_state"] = "SINGLE_SOURCE"
            s["source_family_count"] = 1


def analyze_telemetry_quality(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """
    Checks for interpolation markers and coverage gaps.
    """
    positions = parsed.get("positions", [])
    interp_count = sum(1 for p in positions if p.get("telemetry_quality") == "INTERPOLATED")
    direct_count = sum(1 for p in positions if p.get("telemetry_quality") == "DIRECT")
    
    return {
        "total_positions": len(positions),
        "direct_observations": direct_count,
        "interpolated_points": interp_count,
        "derived_mlats": sum(1 for p in positions if p.get("telemetry_quality") == "DERIVED"),
        "note": "Interpolated points are estimates. Do not treat as observed evidence.",
        "limitations": [
            "Coverage gaps exist where no position was received.",
            "Gap does not imply non-flight or intentional shutdown without corroboration.",
        ]
    }


def detect_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []
    
    # Check for conflicting Operator for same Registration (if temporal overlap suspected)
    # Simplified: Just flag if different operators listed for same AC ref in short window
    # In real app, need precise timeline analysis
    
    ac_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for f in parsed.get("flights", []):
        ar = f.get("aircraft_ref")
        opr = f.get("operator_ref")
        if ar and opr:
            ac_map[ar].append({"op": opr, "time": f.get("actual_departure") or f.get("scheduled_departure")})
            
    for ar, entries in ac_map.items():
        ops = {e["op"] for e in entries}
        if len(ops) > 1:
            contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "OPERATOR_CONFLICT_FOR_AIRCRAFT",
                "subject": ar,
                "values": list(ops),
                "possible_explanations": [
                    "Wet lease / ACMI arrangement",
                    "Code-share operation",
                    "Data error",
                    "Temporal change in operator",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Verify lease agreements and codeshare contracts.",
            })
            
    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    tq = parsed.get("risk_dimensions", {}).get("telemetry_quality", {})
    gaps = tq.get("total_positions", 0) - tq.get("direct_observations", 0)
    
    if gaps > 0:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Track discontinuities may be due to receiver coverage limitations OR transponder configuration.",
            "supporting_facts": [f"{gaps} non-direct/missing interval indicators."],
            "opposing_facts": ["Commercial feeds often filter or interpolate."],
            "unknowns": ["exact cause of gap"],
            "falsification_conditions": ["Independent radar contact confirms continuous flight during gap."],
            "next_test": "Cross-reference with another ADS-B provider or official airport log.",
            "status": "ANALYTICAL",
        })

    if not hyps:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "No significant telemetry anomalies or operator conflicts detected in parsed dataset.",
            "supporting_facts": ["Clean direct observation data."],
            "opposing_facts": [],
            "unknowns": ["future movements"],
            "next_test": "Continue monitoring.",
            "status": "BASELINE",
        })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    flights = parsed.get("flights", [])
    
    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What lawful/authorized aviation evidence exists?",
            "missing_evidence": "No local AVIINT artifact supplied.",
            "likely_source": "Flight Schedule Export, Registry Extract, ADS-B Log.",
            "specialist_owner": "AVIINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables baseline aircraft/flight analysis.",
            "safety_boundary": "No interference, no tracking abuse.",
        })

    if flights and not any(f.get("actual_arrival") for f in flights):
         gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Did the flight actually arrive at destination?",
            "missing_evidence": "Arrival confirmation missing.",
            "likely_source": "Airport Arrival Record, Ground Telemetry, Official Ops Report.",
            "specialist_owner": "AVIINT / OPS",
            "priority": "HIGH",
            "expected_information_value": "Prevents assuming scheduled arrival equals actual.",
            "safety_boundary": "Do not infer landing from last airborne point.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    incidents = parsed.get("incidents", [])
    owners = parsed.get("owners", []) # Note: Owners are parsed into 'operators' table with role OWNER usually
    
    if incidents:
        handoffs.append({
            "specialist": "INCIDENTINT / SAFETY_BOARD",
            "reason": "Safety incidents detected.",
            "expected_output": "Root cause analysis, preliminary/final report retrieval.",
            "question": "What caused the incident and what is the official classification?",
        })
        
    if any(o.get("role") == "LESSOR" for o in parsed.get("operators", [])):
        handoffs.append({
            "specialist": "FININT / CORPINT",
            "reason": "Lease/Lessor relationships detected.",
            "expected_output": "Financial ownership verification, corporate structure resolution.",
            "question": "Who is the beneficial owner behind the lessor entity?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "AVIINT Manager",
            "reason": "Standard analysis completed.",
            "expected_output": "Review findings, approve closure or deep dive.",
            "question": "Is current aviation awareness sufficient for decision support?",
        })

    return handoffs


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    payload = payload or {}
    build_source_independence(parsed)
    parsed["risk_dimensions"]["telemetry_quality"] = analyze_telemetry_quality(parsed)
    parsed["contradictions"] = detect_contradictions(parsed)
    parsed["hypotheses"] = build_hypotheses(parsed)
    parsed["knowledge_gaps"] = build_knowledge_gaps(payload, files or [], parsed)
    parsed["specialist_handoffs"] = build_specialist_handoffs(parsed)
    return parsed


def build_next_best_action(
    payload: Dict[str, Any],
    policy: Dict[str, Any],
    files: List[Dict[str, Any]],
    parsed: Dict[str, Any],
) -> Dict[str, str]:
    tq = parsed.get("risk_dimensions", {}).get("telemetry_quality", {})
    gaps = tq.get("total_positions", 0) - tq.get("direct_observations", 0)
    
    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited interference, spoofing, or tracking behavior.",
            "reason": "AVIINT is defensive intelligence, not an attack/enabler tool.",
            "owner": "AVIINT Manager",
            "expected_output": "Policy-compliant defensive scope.",
        }

    if not files:
        return {
            "action": "Attach lawful/authorized Flight/Registry/Telemetry exports before analysis.",
            "reason": "No AVIINT evidence artifact available.",
            "owner": "AVIINT AI Employee",
            "expected_output": "Evidence inventory.",
        }

    if gaps > 0:
        return {
            "action": "Seek independent telemetry source or airport ground record to verify continuity.",
            "reason": "Track discontinuity detected. Cause unknown (coverage vs config).",
            "owner": "AVIINT Analyst",
            "expected_output": "Verified continuous track or confirmed gap reason.",
        }

    return {
        "action": "Monitor fleet utilization. Verify schedule adherence against actuals.",
        "reason": "Track data appears consistent.",
        "owner": "AVIINT Analyst",
        "expected_output": "Updated operational picture.",
    }


def build_collection_plan(
    payload: Dict[str, Any],
    questions: List[Any],
    files: List[Dict[str, Any]],
    parsed: Dict[str, Any],
) -> List[Dict[str, Any]]:
    plan = []
    priority = 1
    questions_limited, _ = truncate_list([str(q) for q in questions], 8)

    has_files = bool(files)
    has_ac = bool(parsed.get("aircraft"))
    has_pos = bool(parsed.get("positions"))

    def add(operation: str, tool: str, purpose: str, status: str, expected_output: str, safety_risk: str = "LOW") -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General AVIINT planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": "Lawful / public-authorized / evidence-first / safety-aware aviation intelligence only.",
            "authorization_status": "ALLOWED_DEFENSIVE_AUTHORIZED",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "define_aviation_questions_scope",
        "AVIINT Manager",
        "Convert objective into aviation questions, allowed sources, and safety boundaries.",
        "COMPLETED_LOCAL" if payload.get("questions") else "REQUIRED_BEFORE_COLLECTION",
        "Requirement-driven collection plan.",
    )

    add(
        "preserve_original_aviation_records",
        "local evidence store",
        "Store original logs/registries and hashes without modification.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "AvEvidenceObject with SHA256.",
    )

    add(
        "parse_aircraft_flight_telemetry_metadata",
        "local deterministic parser",
        "Parse JSON/CSV/TXT aviation metadata safely.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized aircraft/flights/positions.",
    )

    add(
        "validate_identifiers_and_registrations",
        "local analyzer",
        "Check registration structures and ICAO formats. Flag conflicts.",
        "COMPLETED_LOCAL" if has_ac else "PLANNED_ANALYTIC",
        "Identifier Validation Report.",
        safety_risk="HIGH_IF_IDENTITY_ERROR",
    )

    add(
        "assess_telemetry_coverage_quality",
        "AVIINT Analyst",
        "Identify interpolation/gaps and propose benign explanations.",
        "COMPLETED_LOCAL" if has_pos else "PLANNED_ANALYTIC",
        "Telemetry Quality Assessment.",
        safety_risk="HIGH_IF_GAP_CALLED_ABSENCE",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_fields = [
        "objective",
        "target_aircraft_or_flight",
        "questions",
        "aircraft",
        "operators",
        "flights",
    ]

    parts: List[str] = []
    for key in scanned_fields:
        val = payload.get(key)
        if isinstance(val, list):
            parts.extend(str(x) for x in val)
        elif isinstance(val, dict):
            parts.append(json.dumps(val, ensure_ascii=False, default=str))
        else:
            parts.append(str(val or ""))

    scanned = " \n ".join(parts).lower()

    blocked_reasons: List[str] = []
    for pat in POLICY_BLOCK_PATTERNS:
        rx = re.compile(pat, re.I)
        for m in rx.finditer(scanned):
            start = max(0, m.start() - 180)
            prefix = scanned[start:m.start()]
            if NEGATION_RE.search(prefix):
                continue
            blocked_reasons.append(pat)
            break

    human_review_required = False
    safety_notes: List[str] = []

    if payload.get("target_type") in SENSITIVE_TARGET_TYPES:
        human_review_required = True
        safety_notes.append(
            "Sensitive aviation context detected. Analysis must remain lawful, evidence-first, and safety-aware. "
            "No interference, no spoofing, no private tracking."
        )

    if payload.get("incidents") or "incident" in scanned:
        human_review_required = True
        safety_notes.append(
            "Incident context detected. Correlate impact carefully. Do not assign fault without official investigation."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to require illegal interference, spoofing, or tracking abuse."
            ),
            "safe_alternatives": SAFE_ALTERNATIVES,
        }

    if human_review_required:
        return {
            "status": "HUMAN_REVIEW_REQUIRED",
            "reasons": [],
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "No obvious hard policy violation detected, but sensitive aviation/incident context applies. "
                "Conclusions must remain defensive, evidence-linked, and human-reviewed before consequential action."
            ),
            "safe_alternatives": SAFE_ALTERNATIVES,
        }

    return {
        "status": "ALLOWED_DEFENSIVE_AUTHORIZED",
        "reasons": [],
        "human_review_required": False,
        "safety_notes": [],
        "explanation": (
            "No obvious policy violation detected. Execution remains planning-only unless authorized/lawful aviation evidence is configured."
        ),
        "safe_alternatives": [],
    }


def validate_payload(payload: Dict[str, Any]) -> List[str]:
    warnings: List[str] = []

    required = ["case_id", "task_id", "objective", "target_aircraft_or_flight", "target_type"]
    for field in required:
        if not payload.get(field):
            warnings.append(f"Missing required field: {field}")

    if not payload.get("questions"):
        warnings.append("No AVIINT questions provided. Default questions will be inferred.")

    evidence_keys = [
        "flight_log_paths",
        "registry_paths",
        "telemetry_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No aviation evidence provided. Output remains planning-only.")

    if not payload.get("as_of_date"):
        warnings.append("No As-Of Date provided. Aviation status is highly temporal.")

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "Which aircraft is being referenced?",
        "What is its current/historical registration and ICAO address?",
        "Who is the operator vs the owner/lessor?",
        "What flight/route events are supported by telemetry?",
        "Are there coverage gaps or interpolation issues?",
        "Was the scheduled departure/arrival actually observed?",
        "How reliable and independent are the sources?",
        "Are we confusing marketing carrier with operating carrier?",
        "What remains unknown regarding intent or passengers?",
        "What is the safest next investigative step?",
    ]


class TraceAtlasAVIINTPanel(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1380x940")
        self.minsize(1100, 760)

        self.entries: Dict[str, Any] = {}
        self.last_result: Dict[str, Any] = {}

        self.analyzed_files: List[Dict[str, Any]] = []
        self.parsed: Dict[str, Any] = empty_parsed()

        self._configure_style()
        self._build_ui()
        self._set_defaults()

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        self.configure(bg="#0b0f19")
        style.configure("TFrame", background="#0b0f19")
        style.configure("TLabel", background="#0b0f19", foreground="#e5e7eb", font=("Segoe UI", 10))
        style.configure("Header.TLabel", background="#0b0f19", foreground="#8b5cf6", font=("Segoe UI", 17, "bold")) # Purple/Violet accent for Sky/Aviation
        style.configure("Subheader.TLabel", background="#0b0f19", foreground="#94a3b8", font=("Segoe UI", 9))
        style.configure("TNotebook", background="#0b0f19", borderwidth=0)
        style.configure("TNotebook.Tab", padding=[14, 7], font=("Segoe UI", 10, "bold"))
        style.configure("TEntry", fieldbackground="#111827", foreground="#e5e7eb", insertcolor="#ffffff", bordercolor="#334155")
        style.configure("TCombobox", fieldbackground="#111827", foreground="#e5e7eb", arrowcolor="#e5e7eb", bordercolor="#334155")
        style.configure("TButton", padding=7, font=("Segoe UI", 10, "bold"), background="#1f2937", foreground="#e5e7eb", bordercolor="#475569")
        style.map("TButton", background=[("active", "#334155")], foreground=[("active", "#ffffff")])
        style.configure("Vertical.TScrollbar", background="#1f2937", troughcolor="#0b0f19", arrowcolor="#e5e7eb")

    def _build_ui(self) -> None:
        header = ttk.Frame(self)
        header.pack(fill="x", padx=16, pady=(14, 8))
        ttk.Label(header, text="TraceAtlas AVIINT AI Employee", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text=(
                "Lawful / public-authorized / evidence-first / safety-aware aviation intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT aircraft/flight/telemetry parsing only • "
                "No interference / No spoofing / No ATC manipulation / No private tracking • "
                "Aircraft != Flight • Operator != Owner • Schedule != Actual"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="AVIINT Task Input")
        self.notebook.add(self.output_tab, text="Output / Av Plan / Evidence")

        self._build_input_tab()
        self._build_output_tab()

    def _build_input_tab(self) -> None:
        container = ttk.Frame(self.input_tab)
        container.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(container, bg="#0b0f19", highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.canvas.yview)
        self.form = ttk.Frame(self.canvas)

        self.form.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas_window = self.canvas.create_window((0, 0), window=self.form, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        row = 0
        for key, label, kind in FIELDS:
            ttk.Label(self.form, text=label).grid(row=row, column=0, sticky="nw", padx=10, pady=6)
            if kind == "entry":
                widget = ttk.Entry(self.form, width=102)
            elif kind == "combo":
                widget = ttk.Combobox(self.form, values=TARGET_TYPES if key == "target_type" else [], width=100, state="readonly")
            else:
                widget = tk.Text(self.form, height=3, width=102, bg="#111827", fg="#e5e7eb", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground="#334155", font=("Segoe UI", 10), wrap="word")
            widget.grid(row=row, column=1, sticky="ew", padx=10, pady=6)
            self.entries[key] = widget
            row += 1

        self.form.columnconfigure(1, weight=1)

        buttons1 = ttk.Frame(self.input_tab)
        buttons1.pack(fill="x", padx=10, pady=(12, 4))
        buttons2 = ttk.Frame(self.input_tab)
        buttons2.pack(fill="x", padx=10, pady=(0, 12))

        ttk.Button(buttons1, text="Add Flight Logs / Schedules", command=self.add_flights).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Registry / Airworthiness", command=self.add_registry).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Telemetry / ADS-B Data", command=self.add_telemetry).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Weather / NOTAMs", command=self.add_weather).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add STIX / MISP", command=self.add_stix_misp).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Analyze Local AVIINT Evidence", command=self.analyze_local_av).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate Av Plan", command=self.generate_plan).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Export JSON", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Clear Form", command=self.clear_form).pack(side="left", padx=4)

    def _build_output_tab(self) -> None:
        container = ttk.Frame(self.output_tab)
        container.pack(fill="both", expand=True)
        self.output = tk.Text(container, wrap="word", bg="#020617", fg="#ddd6fe", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground="#334155", font=("Consolas", 11))
        output_scroll = ttk.Scrollbar(container, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=output_scroll.set)
        self.output.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")

    def _set_defaults(self) -> None:
        self.set_widget_value("case_id", "AV-CASE-001")
        self.set_widget_value("task_id", "AV-TASK-001")
        self.set_widget_value("objective", "Analyze lawful/public-authorized/safety-aware aviation intelligence using evidence-first methods.")
        self.set_widget_value("target_aircraft_or_flight", "Illustrative Example Aircraft N123AB / Flight XY123")
        self.set_widget_value("target_type", "aircraft_identity_resolution")
        self.set_widget_value("questions", "\n".join(default_questions({"target_aircraft_or_flight": "Illustrative Example Aircraft N123AB"})))
        
        for field in LIST_FIELDS.union(DICT_FIELDS):
            if field not in ["questions", "scope", "authorization", "time_range"]:
                 self.set_widget_value(field, "")
                 
        self.set_widget_value("time_range", json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2))
        self.set_widget_value("as_of_date", now_utc()[:10])
        self.set_widget_value("scope", json.dumps({"allowed_sources": ["public_registry", "authorized_adsb_feed"], "prohibited_actions": ["spoof_adsb", "track_passenger"]}, indent=2))
        self.set_widget_value("authorization", json.dumps({"basis": "internal_commercial_review"}, indent=2))
        self.set_widget_value("configured_connectors", "None configured.")

    def get_widget_value(self, key: str) -> str:
        widget = self.entries.get(key)
        if widget is None: return ""
        if isinstance(widget, tk.Text): return widget.get("1.0", "end-1c").strip()
        if isinstance(widget, ttk.Combobox): return widget.get().strip()
        if isinstance(widget, ttk.Entry): return widget.get().strip()
        return ""

    def set_widget_value(self, key: str, value: str) -> None:
        widget = self.entries.get(key)
        if widget is None: return
        if isinstance(widget, tk.Text):
            widget.delete("1.0", "end")
            widget.insert("1.0", value)
        elif isinstance(widget, ttk.Combobox):
            widget.set(value)
        elif isinstance(widget, ttk.Entry):
            widget.delete(0, "end")
            widget.insert(0, value)

    def collect_payload(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        for key, _, _ in FIELDS:
            raw = self.get_widget_value(key)
            if key in LIST_FIELDS: payload[key] = parse_list(raw)
            elif key in DICT_FIELDS: payload[key] = parse_dict(raw)
            else: payload[key] = raw
        payload["generated_at"] = now_utc()
        payload["panel_version"] = APP_VERSION
        payload["operating_mode"] = "PLANNING_ONLY_LAWFUL_SAFETY_AWARE_AVIATION"
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths: return
        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added.")

    def add_flights(self): self._append_paths("flight_log_paths", filedialog.askopenfilenames(title="Select Flight Logs", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_registry(self): self._append_paths("registry_paths", filedialog.askopenfilenames(title="Select Registry Records", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_telemetry(self): self._append_paths("telemetry_paths", filedialog.askopenfilenames(title="Select Telemetry Data", filetypes=[("Data", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_weather(self): self._append_paths("weather_notam_paths", filedialog.askopenfilenames(title="Select Weather/NOTAM", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_stix_misp(self): self._append_paths("stix_misp_paths", filedialog.askopenfilenames(title="Select STIX/MISP", filetypes=[("Intel", "*.json *.xml"), ("All", "*.*")]), "Added")

    def run_policy_screen(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)
        result = {"mode": "POLICY_SCREEN_ONLY", "policy_screen": policy}
        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Policy Blocked.")
        elif policy["status"] == "HUMAN_REVIEW_REQUIRED":
            messagebox.showwarning("Review", "Human Review Required.")
        else:
            messagebox.showinfo("OK", "Allowed.")

    def analyze_local_av(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Analysis blocked.")
            return

        path_fields = ["flight_log_paths", "registry_paths", "telemetry_paths", "weather_notam_paths", "stix_misp_paths"]
        all_paths = []
        seen = set()
        for field in path_fields:
            for p in payload.get(field, []):
                sp = str(p).strip()
                if sp and sp not in seen:
                    seen.add(sp)
                    all_paths.append(sp)

        if not all_paths:
            messagebox.showwarning("No Evidence", "Add files first.")
            return

        self.output.delete("1.0", "end")
        self.output.insert("1.0", "Analyzing...\n")
        self.notebook.select(self.output_tab)
        self.update()

        files = []
        parsed_list = []
        for p in all_paths[:30]:
            f, parsed = analyze_av_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
            files.append(f)
            parsed_list.append(parsed)

        aggregated = finalize_parsed(aggregate_parsed(parsed_list), payload, files)
        self.analyzed_files = files
        self.parsed = aggregated

        report = self._build_local_analysis_report(files, aggregated, payload, policy)
        self.last_result = report
        self._write_output(report)
        
        messagebox.showinfo("Done", f"Parsed {len(files)} files.\nAircraft: {len(aggregated['aircraft'])}\nPositions: {len(aggregated['positions'])}")

    def generate_plan(self) -> None:
        payload = self.collect_payload()
        warnings = validate_payload(payload)
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Plan blocked.")
            return

        questions = payload.get("questions") or default_questions(payload)
        if not self.parsed.get("aircraft") and not self.parsed.get("positions"):
            self.parsed = finalize_parsed(empty_parsed(), payload, self.analyzed_files)

        next_action = build_next_best_action(payload, policy, self.analyzed_files, self.parsed)
        collection_plan = build_collection_plan(payload, questions, self.analyzed_files, self.parsed)

        result = {
            "mode": "PLANNING_PLUS_LOCAL_DETERMINISTIC_EVIDENCE" if self.analyzed_files else "PLANNING_ONLY",
            "policy_screen": policy,
            "warnings": warnings,
            "payload": payload,
            "evidence_inventory": self.analyzed_files,
            "aircraft_preview": self.parsed.get("aircraft", [])[:100],
            "operators_preview": self.parsed.get("operators", [])[:100],
            "flights_preview": self.parsed.get("flights", [])[:100],
            "positions_preview": self.parsed.get("positions", [])[:100],
            "risk_dimensions": self.parsed.get("risk_dimensions", {}),
            "hypotheses": self.parsed.get("hypotheses", []),
            "knowledge_gaps": self.parsed.get("knowledge_gaps", []),
            "specialist_handoffs": self.parsed.get("specialist_handoffs", []),
            "next_best_action": next_action,
            "collection_plan": collection_plan,
        }
        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

    def _build_local_analysis_report(self, files, parsed, payload, policy) -> Dict[str, Any]:
        return {
            "mode": "LOCAL_DETERMINISTIC_AVIINT_ANALYSIS",
            "policy_screen": policy,
            "evidence_inventory": files,
            "aircraft": parsed.get("aircraft", [])[:300],
            "operators": parsed.get("operators", [])[:300],
            "flights": parsed.get("flights", [])[:300],
            "positions": parsed.get("positions", [])[:300],
            "risk_dimensions": parsed.get("risk_dimensions", {}),
            "hypotheses": parsed.get("hypotheses", []),
            "contradictions": parsed.get("contradictions", []),
            "limitations": [
                "Only local deterministic checks performed.",
                "No network access.",
                "No interference, no spoofing, no private tracking.",
                "Schedule != Actual.",
                "Gap != Absence.",
            ],
        }

    def _write_output(self, result: Dict[str, Any]) -> None:
        self.output.delete("1.0", "end")
        self.output.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2, default=str))

    def export_json(self) -> None:
        if not self.last_result: self.generate_plan()
        data = self.last_result
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
            messagebox.showinfo("Saved", path)

    def copy_output(self) -> None:
        text = self.output.get("1.0", "end-1c").strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            messagebox.showinfo("Copied", "Output copied.")

    def clear_form(self) -> None:
        if messagebox.askyesno("Confirm", "Clear all?"):
            self._set_defaults()
            self.output.delete("1.0", "end")
            self.last_result = {}
            self.analyzed_files = []
            self.parsed = empty_parsed()


if __name__ == "__main__":
    try:
        app = TraceAtlasAVIINTPanel()
        app.mainloop()
    except tk.TclError as exc:
        print(f"GUI Error: {exc}")
        print("Logic usable as library.")
#!/usr/bin/env python3
"""
TRACEATLAS ADSBINT main.py
==========================

Safe, passive-first, historical-first ADS-B / aircraft movement intelligence scaffold.

This module:
- Does NOT connect to live ADS-B feeds.
- Does NOT perform real-time tactical tracking.
- Does NOT jam, spoof, inject, modify transponders, interfere with ATC/TCAS/GNSS.
- Does NOT infer passengers, pilots, occupants, or flight purpose.
- Does NOT invent trackpoints, landings, routes, operators, owners, or identities.

It consumes deterministic aviation observations supplied by authorized/public sources:
- ADS-B trackpoints
- MLAT-derived trackpoints
- provider-derived / interpolated positions, clearly labeled
- aircraft registry / identifier history
- airport metadata
- operator / owner / lessor context
- scheduled flight context
- source pedigree / independence metadata

It produces an evidence-linked ADSBINTResult with:
- aircraft / identifier resolution
- registration/operator era awareness
- track deduplication
- flight segmentation
- departure/arrival assessment
- ADS-B vs MLAT separation
- observed vs interpolated separation
- track-gap analysis without evasion claims
- source independence / contradiction / fact gate
- competing hypotheses and falsification
- dual-AI style skeptic review
- privacy / safety flags
- graphical memory scaffold
- analyst summary and report-ready result object
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

VERSION = "0.1.0"

ALLOWED_POSITION_SOURCES = {
    "ADS_B",
    "MLAT",
    "RADAR_AUTHORIZED",
    "PROVIDER_DERIVED",
    "ESTIMATED",
    "INTERPOLATED",
    "UNKNOWN",
}

EMERGENCY_SQUAWKS = {"7700", "7600", "7500"}

BLOCK_PHRASES = [
    "intercept aircraft",
    "target aircraft",
    "weapons targeting",
    "weapon targeting",
    "fire control",
    "engagement priority",
    "stalk",
    "stalking",
    "harass",
    "harm occupants",
    "harm passengers",
    "locate protected individual",
    "locate protected person",
    "physical approach aircraft",
    "board aircraft without authorization",
    "disable transponder",
    "modify transponder",
    "manipulate transponder",
    "spoof ads-b",
    "ads-b spoofing",
    "jam ads-b",
    "ads-b jamming",
    "gnss jamming",
    "tcas interference",
    "atc interference",
    "impersonate atc",
    "impersonate pilot",
    "evade law enforcement",
    "evasion of surveillance",
    "military targeting",
    "hostile live tracking",
    "real-time targeting",
    "tactical live tracking",
    "passenger manifest exploitation",
    "occupant targeting",
]


# -----------------------------------------------------------------------------
# Small helpers
# -----------------------------------------------------------------------------

def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except Exception:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def to_float(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    try:
        f = float(value)
        if math.isnan(f) or math.isinf(f):
            return None
        return f
    except Exception:
        return None


def public_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if not str(k).startswith("_")}


def ensure_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def iso_or_none(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if isinstance(dt, datetime) else None


def numeric_summary(values: List[Any]) -> Dict[str, Any]:
    arr: List[float] = []
    for v in values:
        f = to_float(v)
        if f is not None:
            arr.append(f)
    if not arr:
        return {"count": 0, "min": None, "max": None, "median": None}
    return {
        "count": len(arr),
        "min": min(arr),
        "max": max(arr),
        "median": statistics.median(arr),
    }


def haversine_km(lat1: Optional[float], lon1: Optional[float], lat2: Optional[float], lon2: Optional[float]) -> Optional[float]:
    if None in (lat1, lon1, lat2, lon2):
        return None
    try:
        lat1_f = float(lat1)
        lon1_f = float(lon1)
        lat2_f = float(lat2)
        lon2_f = float(lon2)
    except Exception:
        return None

    r = 6371.0
    phi1 = math.radians(lat1_f)
    phi2 = math.radians(lat2_f)
    dphi = math.radians(lat2_f - lat1_f)
    dlmb = math.radians(lon2_f - lon1_f)

    a = math.sin(dphi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlmb / 2.0) ** 2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return r * c


def speed_kt(distance_km: Optional[float], duration_seconds: Optional[float]) -> Optional[float]:
    if distance_km is None or duration_seconds is None or duration_seconds <= 0:
        return None
    return (distance_km / 1.852) * (3600.0 / duration_seconds)


def normalize_icao24(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip().lower()
    s = s.replace(" ", "").replace("-", "").replace("/", "")
    return s or None


def normalize_registration(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip().upper()
    s = s.replace(" ", "").replace("-", "").replace(".", "").replace("/", "")
    return s or None


def normalize_callsign(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).replace("\x00", " ")
    s = " ".join(s.split()).strip().upper()
    return s or None


def normalize_flight_number(value: Any) -> Optional[str]:
    return normalize_callsign(value)


def valid_range_contains(valid_from: Optional[datetime], valid_to: Optional[datetime], ts: Optional[datetime]) -> bool:
    if valid_from is None and valid_to is None:
        return True
    if ts is None:
        return True
    if valid_from is not None and ts < valid_from:
        return False
    if valid_to is not None and ts > valid_to:
        return False
    return True


# -----------------------------------------------------------------------------
# Policy gate
# -----------------------------------------------------------------------------

def policy_block_reasons(case: Dict[str, Any]) -> List[str]:
    reasons: List[str] = []
    text = json.dumps(case, ensure_ascii=False, default=str).lower()

    for phrase in BLOCK_PHRASES:
        if phrase in text:
            reasons.append(f"Forbidden aviation action/request detected: '{phrase}'")

    scope = case.get("scope") if isinstance(case.get("scope"), dict) else {}
    if scope.get("authorized_only") is not True:
        reasons.append("scope.authorized_only must be true")
    if scope.get("passive_only") is False:
        reasons.append("scope.passive_only must be true")
    if scope.get("historical_first") is False:
        reasons.append("scope.historical_first must be true")
    if scope.get("realtime_targeting") is True:
        reasons.append("scope.realtime_targeting is prohibited")
    if scope.get("tactical_live_tracking") is True:
        reasons.append("scope.tactical_live_tracking is prohibited")

    auth = case.get("authorization") if isinstance(case.get("authorization"), dict) else {}
    if not auth.get("lawful_basis"):
        reasons.append("authorization.lawful_basis is missing")
    if not auth.get("purpose"):
        reasons.append("authorization.purpose is missing")

    return reasons


def blocked_result(case: Dict[str, Any], reasons: List[str], started: str, input_path: Optional[str], input_hash: Optional[str]) -> Dict[str, Any]:
    return {
        "case_id": case.get("case_id"),
        "task_id": case.get("task_id"),
        "objective": case.get("objective"),
        "status": "POLICY_BLOCKED",
        "policy_block_reasons": reasons,
        "mode": case.get("model_mode", "LOCAL_ONLY"),
        "safety_flags": [
            "NO_REALTIME_TARGETING",
            "NO_INTERCEPTION",
            "NO_JAMMING",
            "NO_SPOOFING",
            "NO_TRANSPONDER_MANIPULATION",
            "NO_ATC_INTERFERENCE",
            "NO_TCAS_INTERFERENCE",
            "NO_GNSS_JAMMING_OR_SPOOFING",
            "NO_WEAPONS_TARGETING",
            "NO_STALKING",
        ],
        "privacy_flags": [
            "NO_PASSENGER_INFERENCE",
            "NO_PRIVATE_PERSON_DOSSIER",
            "PROTECTED_PERSON_RESTRAINT",
            "HISTORICAL_FIRST",
        ],
        "recommended_next_actions": [
            "Restate objective as historical/public aviation research",
            "Use authorized or public historical ADS-B/MLAT datasets",
            "Resolve aircraft identity and registration/operator eras",
            "Analyze route/airport patterns without occupant or purpose inference",
            "Escalate safety concerns to authorized aviation investigation channels",
        ],
        "limitations": [
            "Requested or detected use crosses ADSBINT defensive boundary.",
            "No live tactical tracking, interception, targeting, jamming, spoofing, or transponder manipulation support is provided.",
        ],
        "replay_manifest": {
            "generated_at": started,
            "finished_at": utcnow_iso(),
            "code_version": VERSION,
            "input_path": input_path,
            "input_sha256": input_hash,
        },
    }


# -----------------------------------------------------------------------------
# Validation and normalization
# -----------------------------------------------------------------------------

def resolve_aircraft(
    obs: Dict[str, Any],
    aircraft: Dict[str, Dict[str, Any]],
    icao24_map: Dict[str, set],
    reg_map: Dict[str, set],
    history: List[Dict[str, Any]],
) -> Tuple[Optional[str], str, str]:
    aid = obs.get("aircraft_id")
    if aid and aid in aircraft:
        return aid, "DIRECT_AIRCRAFT_ID", "HIGH"

    ts = obs.get("_timestamp")
    candidates: set = set()
    bases: List[str] = []

    icao = obs.get("_icao24")
    if icao:
        for h in history:
            if h.get("_field") == "icao24" and h.get("_value") == icao:
                if valid_range_contains(h.get("_valid_from"), h.get("_valid_to"), ts):
                    hid = h.get("aircraft_id")
                    if hid in aircraft:
                        candidates.add(hid)
                        bases.append("HISTORY_ICAO24")

        if not candidates:
            mapped = icao24_map.get(icao, set())
            if len(mapped) == 1:
                candidates.update(mapped)
                bases.append("CURRENT_ICAO24")
            elif len(mapped) > 1:
                return None, "IDENTIFIER_CONFLICT", "LOW"

    reg = obs.get("_registration")
    if not candidates and reg:
        for h in history:
            if h.get("_field") == "registration" and h.get("_value") == reg:
                if valid_range_contains(h.get("_valid_from"), h.get("_valid_to"), ts):
                    hid = h.get("aircraft_id")
                    if hid in aircraft:
                        candidates.add(hid)
                        bases.append("HISTORY_REGISTRATION")

        if not candidates:
            mapped = reg_map.get(reg, set())
            if len(mapped) == 1:
                candidates.update(mapped)
                bases.append("CURRENT_REGISTRATION")
            elif len(mapped) > 1:
                return None, "IDENTIFIER_CONFLICT", "LOW"

    if len(candidates) == 1:
        resolved = next(iter(candidates))
        basis = bases[0] if bases else "IDENTIFIER_MAP"
        confidence = "HIGH" if basis.startswith("HISTORY") or basis == "DIRECT_AIRCRAFT_ID" else "MODERATE"
        return resolved, basis, confidence

    if len(candidates) > 1:
        return None, "IDENTIFIER_CONFLICT", "LOW"

    return None, "UNRESOLVED", "UNKNOWN"


def validate_case(case: Dict[str, Any]) -> Tuple[
    Dict[str, Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    Dict[str, Dict[str, Any]],
    List[Dict[str, Any]],
    List[str],
    List[str],
    List[Dict[str, Any]],
]:
    issues: List[str] = []
    warnings: List[str] = []
    initial_contradictions: List[Dict[str, Any]] = []

    scope = case.get("scope") if isinstance(case.get("scope"), dict) else {}
    auth = case.get("authorization") if isinstance(case.get("authorization"), dict) else {}

    if scope.get("authorized_only") is not True:
        issues.append("scope.authorized_only must be true")
    if scope.get("passive_only") is False:
        issues.append("scope.passive_only must be true")
    if scope.get("historical_first") is False:
        issues.append("scope.historical_first must be true")
    if not auth.get("lawful_basis"):
        issues.append("authorization.lawful_basis missing")
    if not auth.get("purpose"):
        issues.append("authorization.purpose missing")

    aircraft: Dict[str, Dict[str, Any]] = {}
    icao24_map: Dict[str, set] = defaultdict(set)
    reg_map: Dict[str, set] = defaultdict(set)

    for idx, a in enumerate(case.get("aircraft") or []):
        if not isinstance(a, dict):
            issues.append(f"aircraft[{idx}] is not an object")
            continue
        aid = a.get("aircraft_id") or f"AIR-{idx + 1}"
        a["aircraft_id"] = aid
        a["_valid_from"] = parse_dt(a.get("valid_from"))
        a["_valid_to"] = parse_dt(a.get("valid_to"))
        aircraft[aid] = a

        icao = normalize_icao24(a.get("icao24"))
        if icao:
            icao24_map[icao].add(aid)

        reg = normalize_registration(a.get("registration"))
        if reg:
            reg_map[reg].add(aid)

    history: List[Dict[str, Any]] = []
    for h in case.get("identifier_history") or []:
        if not isinstance(h, dict):
            continue
        field = str(h.get("field", "")).strip().lower()
        if field in {"icao", "icao24", "hex_id"}:
            field = "icao24"
            value = normalize_icao24(h.get("value"))
        elif field in {"registration", "reg", "tail"}:
            field = "registration"
            value = normalize_registration(h.get("value"))
        elif field in {"callsign", "call_sign"}:
            field = "callsign"
            value = normalize_callsign(h.get("value"))
        elif field in {"operator", "owner", "lessor"}:
            value = str(h.get("value", "")).strip().upper() or None
        else:
            value = str(h.get("value", "")).strip() or None

        h["_field"] = field
        h["_value"] = value
        h["_valid_from"] = parse_dt(h.get("valid_from"))
        h["_valid_to"] = parse_dt(h.get("valid_to"))

        if h.get("aircraft_id") and h["aircraft_id"] not in aircraft:
            warnings.append(f"identifier_history references unknown aircraft_id={h.get('aircraft_id')}")

        history.append(h)

    sources: Dict[str, Dict[str, Any]] = {}
    for idx, s in enumerate(case.get("sources") or []):
        if not isinstance(s, dict):
            issues.append(f"sources[{idx}] is not an object")
            continue
        sid = s.get("source_id") or f"SRC-{idx + 1}"
        s["source_id"] = sid
        s["_independence_group"] = str(s.get("independence_group") or s.get("provider") or sid).strip().upper()
        sources[sid] = s

    observations: List[Dict[str, Any]] = []
    for idx, o in enumerate(case.get("observations") or []):
        if not isinstance(o, dict):
            issues.append(f"observations[{idx}] is not an object")
            continue

        oid = o.get("observation_id") or f"OBS-{idx + 1}"
        o["observation_id"] = oid

        ts = parse_dt(o.get("timestamp"))
        if ts is None:
            issues.append(f"observation {oid} has missing/unparseable timestamp")
            continue
        o["_timestamp"] = ts

        lat = to_float(o.get("latitude"))
        lon = to_float(o.get("longitude"))

        if lat is not None and not (-90.0 <= lat <= 90.0):
            issues.append(f"observation {oid} latitude out of range")
            lat = None
        if lon is not None and not (-180.0 <= lon <= 180.0):
            issues.append(f"observation {oid} longitude out of range")
            lon = None

        o["_lat"] = lat
        o["_lon"] = lon

        ps = str(o.get("position_source", "UNKNOWN")).strip().upper().replace("-", "_")
        if ps not in ALLOWED_POSITION_SOURCES:
            warnings.append(f"observation {oid} unknown position_source={ps}; set to UNKNOWN")
            ps = "UNKNOWN"
        o["_position_source"] = ps

        o["_icao24"] = normalize_icao24(o.get("icao24"))
        o["_registration"] = normalize_registration(o.get("registration"))
        o["_callsign"] = normalize_callsign(o.get("callsign"))
        o["_flight_number"] = normalize_flight_number(o.get("flight_number"))

        o["_altitude_ft"] = to_float(o.get("altitude_ft") if o.get("altitude_ft") is not None else o.get("altitude"))
        o["_ground_speed_kt"] = to_float(o.get("ground_speed_kt") if o.get("ground_speed_kt") is not None else o.get("speed_kt"))
        o["_vertical_rate_fpm"] = to_float(o.get("vertical_rate_fpm") if o.get("vertical_rate_fpm") is not None else o.get("vertical_rate"))
        o["_heading_deg"] = to_float(o.get("heading_deg") if o.get("heading_deg") is not None else o.get("heading"))
        o["_track_deg"] = to_float(o.get("track_deg") if o.get("track_deg") is not None else o.get("track"))

        sq = o.get("squawk")
        o["_squawk"] = str(sq).strip() if sq is not None else None

        og = o.get("on_ground")
        if isinstance(og, str):
            og = og.strip().lower() in {"true", "1", "yes", "y"}
        o["_on_ground"] = bool(og)

        sid = o.get("source_id")
        o["_source_ids"] = [sid] if sid else []
        if sid and sid not in sources:
            warnings.append(f"observation {oid} references unknown source_id={sid}")

        observations.append(o)

    for o in observations:
        aid, basis, conf = resolve_aircraft(o, aircraft, icao24_map, reg_map, history)
        o["_aircraft_id"] = aid
        o["_resolution_basis"] = basis
        o["_resolution_confidence"] = conf

        if aid:
            o["_group_key"] = aid
        elif o.get("_icao24"):
            o["_group_key"] = f"ICAO24:{o['_icao24']}"
        elif o.get("_registration"):
            o["_group_key"] = f"REG:{o['_registration']}"
        else:
            o["_group_key"] = f"OBS:{o['observation_id']}"

        if basis == "IDENTIFIER_CONFLICT":
            initial_contradictions.append(
                {
                    "type": "identifier_conflict",
                    "group_key": o.get("_group_key"),
                    "observation_id": o.get("observation_id"),
                    "icao24": o.get("_icao24"),
                    "registration": o.get("_registration"),
                    "timestamp": iso_or_none(o.get("_timestamp")),
                    "note": "Preserve conflict. Consider stale registry, historical reassignment, misconfiguration, data error, or spoofing candidate only with corroboration.",
                }
            )

    airports: List[Dict[str, Any]] = []
    for idx, ap in enumerate(case.get("airports") or []):
        if not isinstance(ap, dict):
            issues.append(f"airports[{idx}] is not an object")
            continue
        lat = to_float(ap.get("latitude"))
        lon = to_float(ap.get("longitude"))
        if lat is None or lon is None:
            issues.append(f"airport {ap.get('airport_id') or idx} missing valid latitude/longitude")
            continue
        ap["_lat"] = lat
        ap["_lon"] = lon
        ap["_icao_code"] = str(ap.get("icao_code", "")).strip().upper() or None
        ap["_iata_code"] = str(ap.get("iata_code", "")).strip().upper() or None
        airports.append(ap)

    return aircraft, observations, airports, sources, history, issues, warnings, initial_contradictions


# -----------------------------------------------------------------------------
# Deduplication, segmentation, flight building
# -----------------------------------------------------------------------------

def deduplicate_observations(observations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    ordered: List[Dict[str, Any]] = []

    for o in observations:
        ts = o.get("_timestamp")
        key = (
            o.get("_group_key"),
            ts.isoformat() if isinstance(ts, datetime) else None,
            round(o.get("_lat"), 5) if o.get("_lat") is not None else None,
            round(o.get("_lon"), 5) if o.get("_lon") is not None else None,
            o.get("_position_source"),
        )

        if key in groups:
            rep = groups[key]
            for sid in o.get("_source_ids") or []:
                if sid not in rep["_source_ids"]:
                    rep["_source_ids"].append(sid)
            rep["_duplicate_count"] = rep.get("_duplicate_count", 1) + 1

            # If representative lacks position but duplicate has it, upgrade representative position fields.
            if rep.get("_lat") is None and o.get("_lat") is not None:
                for f in [
                    "_lat",
                    "_lon",
                    "_altitude_ft",
                    "_ground_speed_kt",
                    "_vertical_rate_fpm",
                    "_heading_deg",
                    "_track_deg",
                    "_squawk",
                    "_on_ground",
                ]:
                    rep[f] = o.get(f)
        else:
            o["_source_ids"] = list(o.get("_source_ids") or [])
            o["_duplicate_count"] = 1
            groups[key] = o
            ordered.append(o)

    return ordered


def segment_flights(
    points: List[Dict[str, Any]],
    max_gap_minutes: float,
    min_ground_minutes: float,
) -> List[List[Dict[str, Any]]]:
    pts = sorted(points, key=lambda x: x.get("_timestamp") or datetime.min.replace(tzinfo=timezone.utc))
    segments: List[List[Dict[str, Any]]] = []
    current: List[Dict[str, Any]] = []

    state: Optional[str] = None
    ground_start: Optional[datetime] = None
    had_airborne = False

    for o in pts:
        if not current:
            current = [o]
            state = "GROUND" if o.get("_on_ground") else "AIRBORNE"
            had_airborne = not o.get("_on_ground")
            ground_start = o.get("_timestamp") if o.get("_on_ground") else None
            continue

        prev = current[-1]
        prev_ts = prev.get("_timestamp")
        cur_ts = o.get("_timestamp")
        gap_min = None
        if isinstance(prev_ts, datetime) and isinstance(cur_ts, datetime):
            gap_min = (cur_ts - prev_ts).total_seconds() / 60.0

        if gap_min is not None and gap_min > max_gap_minutes:
            segments.append(current)
            current = [o]
            state = "GROUND" if o.get("_on_ground") else "AIRBORNE"
            had_airborne = not o.get("_on_ground")
            ground_start = o.get("_timestamp") if o.get("_on_ground") else None
            continue

        on_ground = bool(o.get("_on_ground"))

        # Arrival transition: airborne -> ground
        if state == "AIRBORNE" and on_ground:
            ground_start = o.get("_timestamp")

        # Takeoff transition after a meaningful ground period: ground -> airborne
        if state == "GROUND" and not on_ground:
            if had_airborne and ground_start and isinstance(o.get("_timestamp"), datetime):
                ground_duration_min = (o["_timestamp"] - ground_start).total_seconds() / 60.0
                if ground_duration_min >= min_ground_minutes:
                    segments.append(current)
                    current = [o]
                    state = "AIRBORNE"
                    had_airborne = True
                    ground_start = None
                    continue
            had_airborne = True
            ground_start = None

        if on_ground and ground_start is None:
            ground_start = o.get("_timestamp")

        current.append(o)
        state = "GROUND" if on_ground else "AIRBORNE"

    if current:
        segments.append(current)

    return segments


def public_airport(ap: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "airport_id": ap.get("airport_id"),
        "icao_code": ap.get("_icao_code") or ap.get("icao_code"),
        "iata_code": ap.get("_iata_code") or ap.get("iata_code"),
        "name": ap.get("name"),
        "country": ap.get("country"),
        "latitude": ap.get("_lat") if ap.get("_lat") is not None else ap.get("latitude"),
        "longitude": ap.get("_lon") if ap.get("_lon") is not None else ap.get("longitude"),
        "elevation_ft": ap.get("elevation_ft"),
        "runways": ap.get("runways") or [],
    }


def nearest_airport(
    lat: Optional[float],
    lon: Optional[float],
    airports: List[Dict[str, Any]],
    max_km: float,
) -> Tuple[Optional[Dict[str, Any]], Optional[float]]:
    if lat is None or lon is None or not airports:
        return None, None

    best_ap = None
    best_d = None
    for ap in airports:
        d = haversine_km(lat, lon, ap.get("_lat"), ap.get("_lon"))
        if d is None:
            continue
        if best_d is None or d < best_d:
            best_d = d
            best_ap = ap

    if best_ap is not None and best_d is not None and best_d <= max_km:
        return best_ap, best_d
    return None, best_d


def find_airport_by_code(airports: List[Dict[str, Any]], code: Optional[str]) -> Optional[Dict[str, Any]]:
    if not code:
        return None
    c = str(code).strip().upper()
    for ap in airports:
        if ap.get("_icao_code") == c or ap.get("_iata_code") == c:
            return ap
    return None


def endpoint_assessment(
    point: Dict[str, Any],
    airports: List[Dict[str, Any]],
    role: str,
    radius_km: float,
) -> Dict[str, Any]:
    res = {
        "role": role,
        "state": "UNKNOWN",
        "airport": None,
        "distance_km": None,
        "note": "Endpoint assessment is movement-derived, not occupant/purpose evidence.",
    }

    lat = point.get("_lat")
    lon = point.get("_lon")
    if lat is None or lon is None:
        return res

    ap, dist = nearest_airport(lat, lon, airports, radius_km)
    if ap is None:
        res["distance_km"] = dist
        return res

    res["airport"] = public_airport(ap)
    res["distance_km"] = dist

    if point.get("_on_ground"):
        res["state"] = "OBSERVED_DEPARTURE" if role == "departure" else "OBSERVED_ARRIVAL"
    else:
        alt = point.get("_altitude_ft")
        vr = point.get("_vertical_rate_fpm")
        if alt is not None and alt < 5000 and (vr is None or vr < 1000):
            res["state"] = "INFERRED"
        else:
            res["state"] = "PASSED_NEAR"

    return res


def apply_provider_endpoint(
    endpoint: Dict[str, Any],
    code: Optional[str],
    airports: List[Dict[str, Any]],
) -> None:
    if not code:
        return
    if endpoint.get("state") in ("UNKNOWN", "PASSED_NEAR"):
        ap = find_airport_by_code(airports, code)
        endpoint["state"] = "PROVIDER_REPORTED"
        endpoint["airport"] = public_airport(ap) if ap else {"icao_code": str(code).upper()}
        endpoint["note"] = "Provider-reported airport association; not directly observed unless track evidence supports it."


def route_metrics(points: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not points:
        return None

    first = next((p for p in points if p.get("_lat") is not None and p.get("_lon") is not None), None)
    last = next((p for p in reversed(points) if p.get("_lat") is not None and p.get("_lon") is not None), None)

    if not first or not last:
        return None

    dist = haversine_km(first.get("_lat"), first.get("_lon"), last.get("_lat"), last.get("_lon"))
    start = first.get("_timestamp")
    end = last.get("_timestamp")
    duration_s = None
    if isinstance(start, datetime) and isinstance(end, datetime):
        duration_s = (end - start).total_seconds()

    avg_speed = speed_kt(dist, duration_s)

    return {
        "start_lat": first.get("_lat"),
        "start_lon": first.get("_lon"),
        "end_lat": last.get("_lat"),
        "end_lon": last.get("_lon"),
        "great_circle_distance_km": dist,
        "duration_seconds": duration_s,
        "average_ground_speed_kt": avg_speed,
        "limitation": "Great-circle endpoint distance is not filed route and not actual flown track length.",
    }


def find_track_gaps(points: List[Dict[str, Any]], threshold_minutes: float) -> List[Dict[str, Any]]:
    gaps = []
    for prev, curr in zip(points, points[1:]):
        pt = prev.get("_timestamp")
        ct = curr.get("_timestamp")
        if not isinstance(pt, datetime) or not isinstance(ct, datetime):
            continue
        gap_min = (ct - pt).total_seconds() / 60.0
        if gap_min > threshold_minutes:
            gaps.append(
                {
                    "from_time": pt.isoformat(),
                    "to_time": ct.isoformat(),
                    "gap_minutes": gap_min,
                    "from_observation_id": prev.get("observation_id"),
                    "to_observation_id": curr.get("observation_id"),
                    "interpretation": "TRACK_GAP_OBSERVED. Possible coverage/feed/terrain/altitude/filtering causes. Does not establish transponder shutdown or evasion.",
                }
            )
    return gaps


def detect_data_quality(points: List[Dict[str, Any]], max_speed_kt: float) -> List[Dict[str, Any]]:
    flags = []
    for prev, curr in zip(points, points[1:]):
        pt = prev.get("_timestamp")
        ct = curr.get("_timestamp")
        if not isinstance(pt, datetime) or not isinstance(ct, datetime):
            continue
        dt = (ct - pt).total_seconds()
        dist = haversine_km(prev.get("_lat"), prev.get("_lon"), curr.get("_lat"), curr.get("_lon"))
        spd = speed_kt(dist, dt)

        if spd is not None and spd > max_speed_kt:
            flags.append(
                {
                    "type": "IMPOSSIBLE_SPEED_CANDIDATE",
                    "from_observation_id": prev.get("observation_id"),
                    "to_observation_id": curr.get("observation_id"),
                    "computed_ground_speed_kt": spd,
                    "threshold_kt": max_speed_kt,
                    "note": "Data-quality candidate only. Do not infer spoofing from one segment.",
                }
            )

        alt1 = prev.get("_altitude_ft")
        alt2 = curr.get("_altitude_ft")
        if alt1 is not None and alt2 is not None and dt > 0 and dt < 120 and abs(alt2 - alt1) > 10000:
            flags.append(
                {
                    "type": "ALTITUDE_JUMP_CANDIDATE",
                    "from_observation_id": prev.get("observation_id"),
                    "to_observation_id": curr.get("observation_id"),
                    "altitude_delta_ft": abs(alt2 - alt1),
                    "delta_seconds": dt,
                    "note": "Data-quality candidate only. Could be source error, timestamp issue, or merged identity.",
                }
            )

    return flags


def estimate_flight_phase(point: Dict[str, Any]) -> str:
    if point.get("_on_ground"):
        return "GROUND"

    alt = point.get("_altitude_ft")
    vr = point.get("_vertical_rate_fpm")

    if alt is None:
        return "UNKNOWN"

    if alt < 1000:
        if vr is not None and vr > 500:
            return "TAKEOFF_CANDIDATE"
        if vr is not None and vr < -500:
            return "LANDING_CANDIDATE"

    if alt < 3000 and vr is not None and vr < -200:
        return "APPROACH_CANDIDATE"

    if 1000 <= alt < 10000:
        if vr is not None and vr > 300:
            return "CLIMB"
        if vr is not None and vr < -300:
            return "DESCENT"
        return "UNKNOWN"

    if alt >= 10000:
        if vr is not None and abs(vr) < 300:
            return "CRUISE"
        if vr is not None and vr > 300:
            return "CLIMB"
        if vr is not None and vr < -300:
            return "DESCENT"

    return "UNKNOWN"


def squawk_flags(points: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    flags = []
    for p in points:
        sq = p.get("_squawk")
        if sq in EMERGENCY_SQUAWKS:
            flags.append(
                {
                    "observation_id": p.get("observation_id"),
                    "squawk": sq,
                    "state": "EMERGENCY_CODE_OBSERVED",
                    "note": "Squawk observation is not verified incident cause. Requires official/public safety corroboration.",
                }
            )
    return flags


def assess_independence(source_ids: List[str], sources: Dict[str, Dict[str, Any]]) -> str:
    groups = set()
    unknown = False

    for sid in source_ids:
        s = sources.get(sid)
        if not s:
            unknown = True
            continue
        groups.add(str(s.get("_independence_group") or s.get("provider") or sid).upper())

    if unknown and not groups:
        return "UNKNOWN"
    if len(groups) > 1:
        return "INDEPENDENT"
    if len(groups) == 1:
        return "SINGLE_SOURCE"
    return "UNKNOWN"


def estimate_feed_coverage(flight: Dict[str, Any]) -> Dict[str, Any]:
    point_count = len(flight.get("trackpoint_ids") or [])
    duration_s = flight.get("duration_seconds")
    gaps = flight.get("track_gaps") or []
    independence = flight.get("source_independence")

    density = None
    if duration_s and duration_s > 0:
        density = point_count / (duration_s / 3600.0)

    if point_count == 0:
        coverage = "UNKNOWN"
    elif independence == "INDEPENDENT" and (density or 0) >= 6 and not gaps:
        coverage = "HIGH"
    elif (density or 0) >= 2 and len(gaps) <= 1:
        coverage = "MEDIUM"
    elif point_count > 0:
        coverage = "LOW"
    else:
        coverage = "UNKNOWN"

    return {
        "flight_id": flight.get("flight_id"),
        "coverage_state": coverage,
        "point_count": point_count,
        "points_per_hour": density,
        "track_gap_count": len(gaps),
        "source_independence": independence,
        "limitation": "Coverage estimate depends on supplied source metadata and observation density.",
    }


def find_provider_flight(flight: Dict[str, Any], provider_flights: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for pf in provider_flights or []:
        if not isinstance(pf, dict):
            continue

        if pf.get("aircraft_id") and pf.get("aircraft_id") == flight.get("aircraft_id"):
            return pf

        pf_callsign = normalize_callsign(pf.get("callsign"))
        pf_flight_number = normalize_flight_number(pf.get("flight_number"))

        if pf_callsign and pf_callsign in set(flight.get("callsigns") or []):
            return pf
        if pf_flight_number and pf_flight_number in set(flight.get("flight_numbers") or []):
            return pf

    return None


def build_flight(
    flight_index: int,
    group_key: str,
    points: List[Dict[str, Any]],
    airports: List[Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
    provider_flights: List[Dict[str, Any]],
    settings: Dict[str, float],
) -> Dict[str, Any]:
    fid = f"FLT-{flight_index}"
    for p in points:
        p["_flight_id"] = fid
        p["_flight_phase"] = estimate_flight_phase(p)

    callsigns = sorted({p.get("_callsign") for p in points if p.get("_callsign")})
    flight_numbers = sorted({p.get("_flight_number") for p in points if p.get("_flight_number")})
    source_ids = sorted({sid for p in points for sid in (p.get("_source_ids") or [])})
    independence = assess_independence(source_ids, sources)

    dep = endpoint_assessment(points[0], airports, "departure", settings["airport_radius_km"])
    arr = endpoint_assessment(points[-1], airports, "arrival", settings["airport_radius_km"])

    pf = find_provider_flight(
        {
            "aircraft_id": points[0].get("_aircraft_id"),
            "callsigns": callsigns,
            "flight_numbers": flight_numbers,
        },
        provider_flights,
    )

    provider_context = None
    diversion_candidate = False
    if pf:
        provider_context = public_dict(pf)
        apply_provider_endpoint(dep, pf.get("departure_airport"), airports)
        apply_provider_endpoint(arr, pf.get("arrival_airport"), airports)

        obs_dep_code = (dep.get("airport") or {}).get("icao_code") or (dep.get("airport") or {}).get("iata_code")
        obs_arr_code = (arr.get("airport") or {}).get("icao_code") or (arr.get("airport") or {}).get("iata_code")
        prov_arr_code = str(pf.get("arrival_airport", "")).strip().upper() or None

        if prov_arr_code and obs_arr_code and prov_arr_code != obs_arr_code:
            diversion_candidate = True

    route = route_metrics(points)
    gaps = find_track_gaps(points, settings["report_gap_minutes"])
    dq = detect_data_quality(points, settings["max_speed_kt"])
    sq = squawk_flags(points)

    phase_counts = Counter(p.get("_flight_phase") for p in points if p.get("_flight_phase"))
    dominant_phase = phase_counts.most_common(1)[0][0] if phase_counts else "UNKNOWN"

    if dep.get("state") == "OBSERVED_DEPARTURE" and arr.get("state") == "OBSERVED_ARRIVAL" and independence == "INDEPENDENT" and not gaps and not dq:
        segmentation_confidence = "SUPPORTED"
    elif dep.get("state") in ("OBSERVED_DEPARTURE", "PROVIDER_REPORTED") and arr.get("state") in ("OBSERVED_ARRIVAL", "PROVIDER_REPORTED"):
        segmentation_confidence = "PROBABLE"
    elif dep.get("state") != "UNKNOWN" or arr.get("state") != "UNKNOWN":
        segmentation_confidence = "POSSIBLE"
    else:
        segmentation_confidence = "UNKNOWN"

    start_ts = points[0].get("_timestamp")
    end_ts = points[-1].get("_timestamp")
    duration_s = None
    if isinstance(start_ts, datetime) and isinstance(end_ts, datetime):
        duration_s = (end_ts - start_ts).total_seconds()

    return {
        "flight_id": fid,
        "group_key": group_key,
        "aircraft_id": points[0].get("_aircraft_id"),
        "callsigns": callsigns,
        "flight_numbers": flight_numbers,
        "start_time": iso_or_none(start_ts),
        "end_time": iso_or_none(end_ts),
        "duration_seconds": duration_s,
        "departure": dep,
        "arrival": arr,
        "observed_route": route,
        "position_source_counts": dict(Counter(p.get("_position_source") for p in points)),
        "source_ids": source_ids,
        "source_independence": independence,
        "trackpoint_ids": [p.get("observation_id") for p in points],
        "track_gaps": gaps,
        "data_quality_flags": dq,
        "squawk_flags": sq,
        "flight_phase_counts": dict(phase_counts),
        "dominant_flight_phase": dominant_phase,
        "segmentation_confidence": segmentation_confidence,
        "provider_flight": provider_context,
        "diversion_candidate": diversion_candidate,
        "feed_coverage": estimate_feed_coverage(
            {
                "flight_id": fid,
                "trackpoint_ids": [p.get("observation_id") for p in points],
                "duration_seconds": duration_s,
                "track_gaps": gaps,
                "source_independence": independence,
            }
        ),
        "limitations": [
            "Flight segmentation is provisional unless corroborated by independent sources or official records.",
            "Departure/arrival states distinguish observed, provider-reported, inferred, and passed-near cases.",
            "Track gaps are not evidence of transponder shutdown or evasion.",
            "No passenger, pilot, owner presence, or flight purpose is inferred.",
        ],
    }


# -----------------------------------------------------------------------------
# Contradictions, facts, hypotheses, dual review
# -----------------------------------------------------------------------------

def detect_contradictions(
    deduped: List[Dict[str, Any]],
    flights: List[Dict[str, Any]],
    initial: List[Dict[str, Any]],
    settings: Dict[str, float],
) -> List[Dict[str, Any]]:
    contradictions = list(initial)

    by_ts: Dict[Tuple[Any, str], List[Dict[str, Any]]] = defaultdict(list)
    for o in deduped:
        if o.get("_lat") is not None and o.get("_lon") is not None and isinstance(o.get("_timestamp"), datetime):
            by_ts[(o.get("_group_key"), o["_timestamp"].isoformat())].append(o)

    for (group_key, ts), lst in by_ts.items():
        if len(lst) < 2:
            continue
        max_dist = 0.0
        for i in range(len(lst)):
            for j in range(i + 1, len(lst)):
                d = haversine_km(lst[i].get("_lat"), lst[i].get("_lon"), lst[j].get("_lat"), lst[j].get("_lon"))
                if d is not None and d > max_dist:
                    max_dist = d
        if max_dist > settings["position_conflict_km"]:
            contradictions.append(
                {
                    "type": "feed_position_conflict",
                    "group_key": group_key,
                    "timestamp": ts,
                    "max_separation_km": max_dist,
                    "observation_ids": [x.get("observation_id") for x in lst],
                    "note": "Possible source mismatch, MLAT/ADS-B difference, timestamp error, aggregation bug, or different aircraft merged. Preserve contradiction.",
                }
            )

    for f in flights:
        for flag in f.get("data_quality_flags") or []:
            contradictions.append(
                {
                    "type": flag.get("type", "DATA_QUALITY_CANDIDATE"),
                    "flight_id": f.get("flight_id"),
                    "details": flag,
                    "note": "Data-quality contradiction candidate. Do not infer malicious spoofing from one segment.",
                }
            )

    return contradictions


def build_facts(
    deduped: List[Dict[str, Any]],
    flights: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    supported: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    partial: List[Dict[str, Any]] = []
    disputed: List[Dict[str, Any]] = []

    not_facts = [
        "No passenger or occupant identity is inferred.",
        "No pilot identity is inferred.",
        "No flight purpose is inferred.",
        "Track gap is not evidence of transponder shutdown.",
        "Near-airport position is not landing confirmation.",
        "Scheduled route is not observed route.",
        "MLAT position is not aircraft-reported ADS-B position.",
        "Interpolated position is not direct observation.",
        "Current registration/operator is not automatically historical registration/operator.",
        "AI agreement is not independent aviation corroboration.",
    ]

    for o in deduped:
        src = ", ".join(o.get("_source_ids") or ["UNKNOWN_SOURCE"])
        ident = o.get("_aircraft_id") or o.get("_icao24") or o.get("_registration") or o.get("_group_key")
        ts = iso_or_none(o.get("_timestamp"))

        if o.get("_lat") is not None and o.get("_lon") is not None:
            stmt = f"{src} observed {ident} at ({o['_lat']}, {o['_lon']}) at {ts}."
        else:
            stmt = f"{src} observed metadata for {ident} at {ts}."

        item = {
            "fact_id": f"FCT-{len(supported) + len(candidates) + len(partial) + 1}",
            "statement": stmt,
            "observation_id": o.get("observation_id"),
            "source_ids": o.get("_source_ids"),
            "confidence": o.get("_resolution_confidence", "UNKNOWN"),
        }

        if o.get("_resolution_basis") in ("DIRECT_AIRCRAFT_ID", "HISTORY_ICAO24", "HISTORY_REGISTRATION"):
            supported.append(item)
        elif o.get("_resolution_basis") in ("CURRENT_ICAO24", "CURRENT_REGISTRATION", "IDENTIFIER_MAP"):
            candidates.append(item)
        else:
            partial.append(item)

    for f in flights:
        dep = f.get("departure") or {}
        arr = f.get("arrival") or {}
        dep_ap = (dep.get("airport") or {}).get("icao_code") or (dep.get("airport") or {}).get("iata_code")
        arr_ap = (arr.get("airport") or {}).get("icao_code") or (arr.get("airport") or {}).get("iata_code")

        if dep.get("state") == "OBSERVED_DEPARTURE" and arr.get("state") == "OBSERVED_ARRIVAL" and dep_ap and arr_ap:
            supported.append(
                {
                    "fact_id": f"FCT-FLT-{f.get('flight_id')}",
                    "statement": f"Aircraft group {f.get('group_key')} was observed moving from {dep_ap} to {arr_ap} during {f.get('start_time')} to {f.get('end_time')}.",
                    "flight_id": f.get("flight_id"),
                    "confidence": f.get("segmentation_confidence"),
                }
            )
        elif dep_ap or arr_ap:
            partial.append(
                {
                    "fact_id": f"FCT-FLT-{f.get('flight_id')}",
                    "statement": f"Aircraft group {f.get('group_key')} has partial endpoint evidence: departure={dep.get('state')} {dep_ap}, arrival={arr.get('state')} {arr_ap}.",
                    "flight_id": f.get("flight_id"),
                    "confidence": f.get("segmentation_confidence"),
                }
            )
        else:
            candidates.append(
                {
                    "fact_id": f"FCT-FLT-{f.get('flight_id')}",
                    "statement": f"Aircraft group {f.get('group_key')} has a segmented movement candidate without resolved airport endpoints.",
                    "flight_id": f.get("flight_id"),
                    "confidence": f.get("segmentation_confidence"),
                }
            )

    for c in contradictions:
        disputed.append(
            {
                "disputed_id": f"DIS-{len(disputed) + 1}",
                "type": c.get("type"),
                "statement": "Material contradiction present; do not silently resolve.",
                "details": c,
            }
        )

    return supported, candidates, partial, disputed, not_facts


def build_hypotheses(
    flights: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    issues: List[str],
) -> List[Dict[str, Any]]:
    hypotheses: List[Dict[str, Any]] = []

    for f in flights:
        fid = f.get("flight_id")
        gaps = f.get("track_gaps") or []
        dq = f.get("data_quality_flags") or []
        dep = f.get("departure") or {}
        arr = f.get("arrival") or {}

        hypotheses.append(
            {
                "hypothesis_id": f"H-{fid}-OBSERVED-MOVEMENT",
                "statement": "The segmented track represents one observed movement episode for the aircraft group.",
                "support": [
                    "Continuous or near-continuous trackpoints exist." if not gaps else "Some trackpoints exist but gaps are present.",
                    f"Endpoint states: departure={dep.get('state')}, arrival={arr.get('state')}.",
                ],
                "opposition": [
                    "Track gaps weaken continuity." if gaps else "No major gap objection recorded.",
                    "Data-quality flags present." if dq else "No data-quality flags recorded.",
                ],
                "unknowns": ["Flight purpose", "occupants", "filed route", "ATC clearance"],
                "falsification_conditions": [
                    "Independent source shows different aircraft identity for same track.",
                    "Timestamp normalization reveals merged non-contiguous observations.",
                    "Airport movement records contradict observed departure/arrival.",
                ],
            }
        )

        if dep.get("state") in ("PASSED_NEAR", "INFERRED", "UNKNOWN") or arr.get("state") in ("PASSED_NEAR", "INFERRED", "UNKNOWN"):
            hypotheses.append(
                {
                    "hypothesis_id": f"H-{fid}-NEAR-AIRPORT-WITHOUT-LANDING",
                    "statement": "The aircraft may have passed near an airport without landing.",
                    "support": ["Endpoint state is not OBSERVED_ARRIVAL/OBSERVED_DEPARTURE."],
                    "opposition": ["On-ground track evidence would weaken this hypothesis." if dep.get("state") == "OBSERVED_DEPARTURE" or arr.get("state") == "OBSERVED_ARRIVAL" else "No strong on-ground contradiction recorded."],
                    "unknowns": ["Actual landing location", "airport surface movement quality"],
                    "falsification_conditions": [
                        "Sustained ground taxi track at airport surface.",
                        "Official airport movement record confirms landing.",
                    ],
                }
            )

        if gaps:
            hypotheses.append(
                {
                    "hypothesis_id": f"H-{fid}-TRACK-GAP-COVERAGE",
                    "statement": "Track gaps may reflect feed coverage, receiver outage, terrain, altitude, filtering, or data latency.",
                    "support": [f"{len(gaps)} observed gap(s)."],
                    "opposition": ["Independent dense coverage across the gap would weaken coverage explanation." if f.get("source_independence") == "INDEPENDENT" else "No independent dense coverage recorded."],
                    "unknowns": ["Receiver coverage logs", "feed outage records"],
                    "falsification_conditions": [
                        "Independent receiver shows continuous coverage during gap.",
                        "Aircraft identity changes across gap.",
                    ],
                    "restriction": "Do not conclude deliberate transponder shutdown from gap alone.",
                }
            )

        if f.get("provider_flight"):
            hypotheses.append(
                {
                    "hypothesis_id": f"H-{fid}-PROVIDER-ASSOCIATION-ERROR",
                    "statement": "Provider airport/flight association may be incorrect or enriched from schedule rather than observation.",
                    "support": ["Provider flight context exists."],
                    "opposition": ["Observed ground endpoints weaken provider-error hypothesis." if dep.get("state") == "OBSERVED_DEPARTURE" and arr.get("state") == "OBSERVED_ARRIVAL" else "Observed endpoints are not fully conclusive."],
                    "unknowns": ["Provider enrichment method", "schedule-to-observation mapping"],
                    "falsification_conditions": [
                        "Independent airport movement record matches provider association.",
                        "Raw track clearly shows surface movement at provider airport.",
                    ],
                }
            )

        if dq:
            hypotheses.append(
                {
                    "hypothesis_id": f"H-{fid}-DATA-QUALITY",
                    "statement": "Some segments may be caused by data corruption, timestamp error, source mismatch, or merged identity.",
                    "support": [f"{len(dq)} data-quality flag(s)."],
                    "opposition": ["Consistent independent sources would weaken data-quality hypothesis." if f.get("source_independence") == "INDEPENDENT" else "No strong independent corroboration recorded."],
                    "unknowns": ["Source clock accuracy", "provider processing pipeline"],
                    "falsification_conditions": [
                        "Corrected source export removes impossible segment.",
                        "Independent receiver reproduces same physical movement within uncertainty.",
                    ],
                    "restriction": "Do not infer spoofing solely from one impossible segment.",
                }
            )

    for c in contradictions:
        if c.get("type") == "identifier_conflict":
            cid = c.get("group_key") or c.get("observation_id")
            hypotheses.append(
                {
                    "hypothesis_id": f"H-ID-{cid}-STALE-REGISTRY",
                    "statement": "Identifier conflict may be caused by stale registry or outdated mapping.",
                    "support": ["Conflicting identifier mapping supplied."],
                    "opposition": ["Time-bounded registry history would weaken stale-mapping hypothesis."],
                    "falsification_conditions": ["Authoritative registry history confirms single valid mapping for timestamp."],
                }
            )
            hypotheses.append(
                {
                    "hypothesis_id": f"H-ID-{cid}-HISTORICAL-REASSIGNMENT",
                    "statement": "ICAO24/registration may have been reassigned historically.",
                    "support": ["Identifier conflict present."],
                    "opposition": ["Valid-from/valid-to records resolve era."],
                    "falsification_conditions": ["Registry era records show no reassignment at observation time."],
                }
            )
            hypotheses.append(
                {
                    "hypothesis_id": f"H-ID-{cid}-MISCONFIGURED-TRANSPONDER",
                    "statement": "Transponder/configuration error may produce inconsistent identifiers.",
                    "support": ["Conflict exists without clear era resolution."],
                    "opposition": ["Maintenance/operational records may explain configuration."],
                    "falsification_conditions": ["Authorized maintenance/config record confirms correct identifier emission."],
                }
            )
            hypotheses.append(
                {
                    "hypothesis_id": f"H-ID-{cid}-SPOOFING-CANDIDATE",
                    "statement": "Deceptive identifier emission is possible in principle and may be considered only as a last-resort hypothesis.",
                    "support": ["Unresolved identifier conflict."],
                    "opposition": ["Data error, stale registry, reassignment, MLAT mismatch, aggregation bug are simpler explanations."],
                    "falsification_conditions": [
                        "Independent raw ADS-B/Mode S records show inconsistent identity with no data-error explanation.",
                        "Authorized investigation confirms deceptive emission.",
                    ],
                    "restriction": "This scaffold does not provide spoofing methods and does not conclude spoofing without corroboration.",
                }
            )

    if issues:
        hypotheses.append(
            {
                "hypothesis_id": "H-GLOBAL-VALIDATION-WEAKNESS",
                "statement": "Validation issues materially weaken all movement conclusions.",
                "support": issues[:10],
                "opposition": ["No independent clean source supplied yet."],
                "falsification_conditions": ["Resolve validation issues and rerun deterministic ingestion."],
            }
        )

    return hypotheses


def dual_ai_review(
    deduped: List[Dict[str, Any]],
    flights: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    issues: List[str],
) -> Dict[str, Any]:
    primary = {
        "role": "Primary Aviation Analyst",
        "assessment": (
            "Observed movement candidates exist."
            if flights
            else "No segmented flights could be built from supplied observations."
        ),
        "classification": "Identity, route, and endpoint conclusions remain evidence-bounded.",
    }

    if not deduped:
        skeptic = {
            "role": "Independent Aviation Skeptic",
            "verdict": "INSUFFICIENT_EVIDENCE",
            "reason": "No usable observations were supplied. Do not infer movement from narrative.",
        }
    elif issues:
        skeptic = {
            "role": "Independent Aviation Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Validation issues require downgraded confidence.",
        }
    elif contradictions:
        skeptic = {
            "role": "Independent Aviation Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Contradictions must be preserved; do not silently resolve identity/track conflicts.",
        }
    elif flights and any(f.get("source_independence") == "INDEPENDENT" and f.get("segmentation_confidence") in ("SUPPORTED", "PROBABLE") for f in flights):
        skeptic = {
            "role": "Independent Aviation Skeptic",
            "verdict": "AGREE_ON_MOVEMENT_ONLY",
            "reason": "Independent source corroboration supports movement assessment only, not occupant/purpose attribution.",
        }
    else:
        skeptic = {
            "role": "Independent Aviation Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Single-source or incomplete evidence supports candidate movement only.",
        }

    return {
        "primary": primary,
        "skeptic": skeptic,
        "comparison": skeptic.get("verdict", "INSUFFICIENT_EVIDENCE"),
        "note": "Rule-based dual-review scaffold. AI agreement is not independent aviation evidence. Human review required for consequential conclusions.",
    }


# -----------------------------------------------------------------------------
# Graphical memory scaffold
# -----------------------------------------------------------------------------

def build_graph(
    aircraft: Dict[str, Dict[str, Any]],
    deduped: List[Dict[str, Any]],
    flights: List[Dict[str, Any]],
    airports: List[Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
    facts: List[Dict[str, Any]],
    hypotheses: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    def add_node(node_id: str, node_type: str, props: Dict[str, Any]) -> None:
        if any(n.get("id") == node_id for n in nodes):
            return
        nodes.append({"id": node_id, "type": node_type, "properties": props})

    def add_edge(src: str, dst: str, rel: str, props: Dict[str, Any]) -> None:
        edges.append({"from": src, "to": dst, "type": rel, "properties": props})

    for aid, a in aircraft.items():
        add_node(aid, "Aircraft", public_dict(a))

    for o in deduped:
        oid = o.get("observation_id")
        add_node(
            oid,
            "ADSBObservation" if o.get("_position_source") == "ADS_B" else "MLATObservation" if o.get("_position_source") == "MLAT" else "Observation",
            {
                "group_key": o.get("_group_key"),
                "aircraft_id": o.get("_aircraft_id"),
                "icao24": o.get("_icao24"),
                "registration": o.get("_registration"),
                "callsign": o.get("_callsign"),
                "flight_number": o.get("_flight_number"),
                "timestamp": iso_or_none(o.get("_timestamp")),
                "latitude": o.get("_lat"),
                "longitude": o.get("_lon"),
                "altitude_ft": o.get("_altitude_ft"),
                "ground_speed_kt": o.get("_ground_speed_kt"),
                "vertical_rate_fpm": o.get("_vertical_rate_fpm"),
                "position_source": o.get("_position_source"),
                "source_ids": o.get("_source_ids"),
                "resolution_basis": o.get("_resolution_basis"),
            },
        )

        if o.get("_aircraft_id"):
            add_edge(oid, o["_aircraft_id"], "IDENTIFIED_BY", {"observation_id": oid})
        if o.get("_icao24"):
            iid = f"ICAO24:{o['_icao24']}"
            add_node(iid, "ICAO24Identifier", {"value": o["_icao24"]})
            add_edge(oid, iid, "OBSERVED_WITH_IDENTIFIER", {"observation_id": oid})
        if o.get("_registration"):
            rid = f"REG:{o['_registration']}"
            add_node(rid, "Registration", {"value": o["_registration"]})
            add_edge(oid, rid, "OBSERVED_WITH_IDENTIFIER", {"observation_id": oid})
        if o.get("_callsign"):
            csid = f"CALLSIGN:{o['_callsign']}"
            add_node(csid, "Callsign", {"value": o["_callsign"]})
            add_edge(oid, csid, "USED_CALLSIGN", {"observation_id": oid})
        for sid in o.get("_source_ids") or []:
            add_node(sid, "Source", public_dict(sources.get(sid, {"source_id": sid})))
            add_edge(oid, sid, "OBSERVED_BY", {"observation_id": oid, "source_id": sid})

    for f in flights:
        fid = f.get("flight_id")
        add_node(
            fid,
            "Flight",
            {
                "group_key": f.get("group_key"),
                "aircraft_id": f.get("aircraft_id"),
                "start_time": f.get("start_time"),
                "end_time": f.get("end_time"),
                "departure": f.get("departure"),
                "arrival": f.get("arrival"),
                "segmentation_confidence": f.get("segmentation_confidence"),
            },
        )
        for oid in f.get("trackpoint_ids") or []:
            add_edge(fid, oid, "HAS_TRACKPOINT", {"flight_id": fid})
        dep_ap = (f.get("departure") or {}).get("airport") or {}
        arr_ap = (f.get("arrival") or {}).get("airport") or {}
        if dep_ap.get("airport_id"):
            add_node(dep_ap["airport_id"], "Airport", dep_ap)
            add_edge(fid, dep_ap["airport_id"], "DEPARTED_FROM", {"flight_id": fid, "state": (f.get("departure") or {}).get("state")})
        if arr_ap.get("airport_id"):
            add_node(arr_ap["airport_id"], "Airport", arr_ap)
            add_edge(fid, arr_ap["airport_id"], "ARRIVED_AT", {"flight_id": fid, "state": (f.get("arrival") or {}).get("state")})

    for ap in airports:
        apid = ap.get("airport_id")
        if apid:
            add_node(apid, "Airport", public_airport(ap))

    for fac in facts:
        fid = fac.get("fact_id")
        add_node(fid, "Fact", fac)
        if fac.get("observation_id"):
            add_edge(fid, fac["observation_id"], "SUPPORTED_BY", {"fact_id": fid})
        if fac.get("flight_id"):
            add_edge(fid, fac["flight_id"], "SUPPORTED_BY", {"fact_id": fid})

    for h in hypotheses:
        add_node(h.get("hypothesis_id"), "Hypothesis", h)

    for c in contradictions:
        cid = f"CONTRA-{len([x for x in nodes if x.get('type') == 'Contradiction']) + 1}"
        add_node(cid, "Contradiction", c)

    for g in gaps:
        gid = g.get("gap_id") or f"GAP-{len(gaps)}"
        add_node(gid, "Gap", g)

    return {"nodes": nodes, "edges": edges, "version": VERSION}


# -----------------------------------------------------------------------------
# Gaps, actions, handoffs, summary
# -----------------------------------------------------------------------------

def build_knowledge_gaps(
    deduped: List[Dict[str, Any]],
    flights: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    issues: List[str],
    history: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    gaps: List[Dict[str, Any]] = []

    if not deduped:
        gaps.append(
            {
                "gap_id": "GAP-NO-OBSERVATIONS",
                "gap": "No usable aviation observations supplied",
                "importance": "HIGH",
                "recommended_source": "Authorized/public historical ADS-B or MLAT export",
                "expected_information_value": "Establishes whether any movement is measurable",
            }
        )

    if issues:
        gaps.append(
            {
                "gap_id": "GAP-VALIDATION-ISSUES",
                "gap": "Input validation issues present",
                "importance": "HIGH",
                "recommended_source": "Corrected source export, registry record, airport metadata",
                "expected_information_value": "Improves identity/track trust",
            }
        )

    unresolved = [o for o in deduped if o.get("_resolution_basis") == "UNRESOLVED"]
    if unresolved:
        gaps.append(
            {
                "gap_id": "GAP-AIRCRAFT-IDENTITY",
                "gap": "Some observations could not be resolved to an aircraft airframe",
                "importance": "HIGH",
                "recommended_source": "Official aircraft registry, ICAO24 allocation history, operator fleet records",
                "expected_information_value": "Reduces false aircraft attribution",
            }
        )

    if not any(h.get("_field") == "registration" for h in history):
        gaps.append(
            {
                "gap_id": "GAP-REGISTRATION-HISTORY",
                "gap": "Registration era history missing",
                "importance": "MODERATE",
                "recommended_source": "Registry history / authorized aircraft records",
                "expected_information_value": "Prevents historical-to-current contamination",
            }
        )

    if not any(h.get("_field") == "operator" for h in history):
        gaps.append(
            {
                "gap_id": "GAP-OPERATOR-HISTORY",
                "gap": "Operator era history missing",
                "importance": "MODERATE",
                "recommended_source": "Operator fleet records / corporate records",
                "expected_information_value": "Prevents false operator attribution",
            }
        )

    for f in flights:
        if f.get("track_gaps"):
            gaps.append(
                {
                    "gap_id": f"GAP-TRACK-{f.get('flight_id')}",
                    "gap": f"Track gap(s) in {f.get('flight_id')}",
                    "importance": "MODERATE",
                    "recommended_source": "Independent receiver coverage logs, alternate historical feed",
                    "expected_information_value": "Distinguishes coverage loss from actual missing movement",
                }
            )

        if f.get("feed_coverage", {}).get("coverage_state") in ("LOW", "UNKNOWN"):
            gaps.append(
                {
                    "gap_id": f"GAP-COVERAGE-{f.get('flight_id')}",
                    "gap": f"Feed coverage low/unknown for {f.get('flight_id')}",
                    "importance": "MODERATE",
                    "recommended_source": "Coverage metadata, alternate feed",
                    "expected_information_value": "Calibrates non-detection risk",
                }
            )

    if contradictions:
        gaps.append(
            {
                "gap_id": "GAP-CONTRADICTIONS",
                "gap": "Material contradictions present",
                "importance": "HIGH",
                "recommended_source": "Raw source records, registry history, independent feed",
                "expected_information_value": "Prevents silent false resolution",
            }
        )

    gaps.append(
        {
            "gap_id": "GAP-OCCUPANTS",
            "gap": "Passengers/occupants unknown by design",
            "importance": "CONTEXTUAL",
            "recommended_source": "Only independent lawful evidence if separately authorized",
            "expected_information_value": "ADS-B alone cannot establish occupants",
        }
    )

    gaps.append(
        {
            "gap_id": "GAP-PURPOSE",
            "gap": "Flight purpose unknown by design",
            "importance": "CONTEXTUAL",
            "recommended_source": "Operator records, official filings, authorized investigation evidence",
            "expected_information_value": "Movement alone does not establish purpose",
        }
    )

    return gaps


def build_next_actions(
    deduped: List[Dict[str, Any]],
    flights: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
) -> List[str]:
    actions: List[str] = []

    if not deduped:
        actions.append("Supply deterministic public/authorized historical ADS-B or MLAT trackpoint exports")

    if any(g["gap_id"] == "GAP-AIRCRAFT-IDENTITY" for g in gaps):
        actions.append("Check official aircraft registry and ICAO24/registration allocation history")

    if any(g["gap_id"] == "GAP-REGISTRATION-HISTORY" for g in gaps):
        actions.append("Resolve registration era valid_from/valid_to before attributing historical flights")

    if any(g["gap_id"] == "GAP-OPERATOR-HISTORY" for g in gaps):
        actions.append("Resolve operator era using fleet records or authorized corporate records")

    if contradictions:
        actions.append("Preserve contradictions and compare raw independent sources before resolving identity/track conflicts")

    if flights:
        actions.append("Compare observed track with an independent historical aviation source")
        actions.append("Retrieve airport movement records where available to confirm departure/arrival")
        actions.append("Compare scheduled vs observed flight only as context, not proof")

    if any(f.get("track_gaps") for f in flights):
        actions.append("Check feed/receiver coverage metadata before interpreting track gaps")

    actions.append("Maintain historical-first posture; no live tactical tracking, interception, targeting, stalking, jamming, spoofing, or transponder manipulation")

    return actions


def build_specialist_handoffs(
    flights: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    aircraft: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    handoffs: List[Dict[str, Any]] = []

    if flights:
        handoffs.append(
            {
                "to": "TRANSPORTINT",
                "reason": "Broader multi-modal transport context may be required",
                "restrictions": ["No live targeting", "No occupant inference"],
            }
        )
        handoffs.append(
            {
                "to": "GEOINT",
                "reason": "Airport geography, terrain, airspace, and spatial corroboration may be required",
                "restrictions": ["No precise private-person location", "No actionable live tracking"],
            }
        )

    if any(not a.get("operator") or not a.get("owner_candidate") for a in aircraft.values()) or contradictions:
        handoffs.append(
            {
                "to": "CORPINT / OWNERSHIPINT",
                "reason": "Owner/operator/lessor resolution exceeds ADS-B movement evidence",
                "restrictions": ["No private-person profiling", "Use lawful/public corporate records only"],
            }
        )

    if any(c.get("type") in {"identifier_conflict", "feed_position_conflict"} for c in contradictions):
        handoffs.append(
            {
                "to": "SIGINT",
                "reason": "Raw RF/Mode S/ADS-B signal-level questions may require authorized signal analysis",
                "restrictions": ["No jamming", "No spoofing", "No transponder manipulation"],
            }
        )

    return handoffs


def analyst_summary(r: Dict[str, Any]) -> str:
    def fmt_list(lst: Any) -> str:
        if not lst:
            return "NONE"
        if isinstance(lst, list):
            return ", ".join(str(x) for x in lst)
        return str(lst)

    flights = r.get("flights") or []
    first_flight = flights[0] if flights else {}

    lines = [
        "AIRCRAFT: " + fmt_list([a.get("aircraft_id") for a in (r.get("aircraft") or [])]),
        "ICAO24: " + fmt_list(r.get("icao24_identifiers")),
        "REGISTRATION: " + fmt_list(r.get("registrations")),
        "REGISTRATION ERA: " + fmt_list([f"{h.get('value')}:{h.get('valid_from')}->{h.get('valid_to')}" for h in (r.get("registration_history") or [])]),
        "AIRCRAFT TYPE: " + fmt_list(r.get("aircraft_types")),
        "OPERATOR: " + fmt_list(r.get("operators")),
        "OWNER / LESSOR CONTEXT: " + fmt_list([f"owner={x}" for x in r.get("owner_candidates") or []] + [f"lessor={x}" for x in r.get("lessors") or []]),
        "CALLSIGN: " + fmt_list(r.get("callsigns")),
        "FLIGHT NUMBER: " + fmt_list(r.get("flight_numbers")),
        "FLIGHT DATE: " + fmt_list([f.get("start_time") for f in flights]),
        "DEPARTURE: " + fmt_list([f"{(f.get('departure') or {}).get('state')} {(f.get('departure') or {}).get('airport', {}).get('icao_code')}" for f in flights]),
        "ARRIVAL: " + fmt_list([f"{(f.get('arrival') or {}).get('state')} {(f.get('arrival') or {}).get('airport', {}).get('icao_code')}" for f in flights]),
        "OBSERVED ROUTE: " + fmt_list([f.get("observed_route", {}).get("great_circle_distance_km") for f in flights if f.get("observed_route")]),
        "SCHEDULED ROUTE: " + fmt_list(r.get("scheduled_routes")),
        "POSITION SOURCE: " + fmt_list([f"{k}={v}" for k, v in (r.get("position_sources") or {}).items()]),
        "TRACK COMPLETENESS: " + fmt_list([f"{f.get('flight_id')} points={len(f.get('trackpoint_ids') or [])} gaps={len(f.get('track_gaps') or [])}" for f in flights]),
        "ALTITUDE / SPEED CONTEXT: " + json.dumps(r.get("altitudes") or {}, default=str) + " | " + json.dumps(r.get("ground_speeds") or {}, default=str),
        "SQUAWK CONTEXT: " + fmt_list([sq.get("squawk") for f in flights for sq in (f.get("squawk_flags") or [])]),
        "TRACK GAPS: " + str(sum(len(f.get("track_gaps") or []) for f in flights)),
        "AIRPORT FREQUENCY: " + fmt_list([f"{k}={v}" for k, v in (r.get("airport_frequency") or {}).items()]),
        "ROUTE FREQUENCY: " + fmt_list([f"{k}={v}" for k, v in (r.get("route_frequency") or {}).items()]),
        "MOVEMENT PATTERN: " + fmt_list(r.get("movement_patterns")),
        "SOURCE RELIABILITY: " + fmt_list([f"{s.get('source_id')}={s.get('reliability')}" for s in (r.get("source_reliability") or [])]),
        "SOURCE INDEPENDENCE: " + str(r.get("source_independence")),
        "CONTRADICTIONS: " + str(len(r.get("contradictions") or [])),
        "PRIVACY / SAFETY LIMITATIONS: " + fmt_list((r.get("privacy_flags") or []) + (r.get("safety_flags") or [])),
        "UNKNOWN: " + fmt_list(r.get("unknowns")),
        "NEXT ACTION: " + ((r.get("recommended_next_actions") or ["NONE"])[0]),
    ]

    if first_flight:
        lines.insert(0, f"PRIMARY FLIGHT ASSESSMENT: {first_flight.get('flight_id')} confidence={first_flight.get('segmentation_confidence')}")

    return "\n".join(lines)


# -----------------------------------------------------------------------------
# Main analysis
# -----------------------------------------------------------------------------

def analyze(case: Dict[str, Any], input_path: Optional[str] = None, input_hash: Optional[str] = None) -> Dict[str, Any]:
    started = utcnow_iso()

    block_reasons = policy_block_reasons(case)
    if block_reasons:
        return blocked_result(case, block_reasons, started, input_path, input_hash)

    aircraft, observations, airports, sources, history, issues, warnings, initial_contradictions = validate_case(case)

    settings_raw = case.get("analysis_settings") or {}

    def setting_float(name: str, default: float) -> float:
        try:
            return float(settings_raw.get(name, default))
        except Exception:
            return default

    settings = {
        "max_gap_minutes": setting_float("max_gap_minutes", 30.0),
        "min_ground_minutes": setting_float("min_ground_minutes", 10.0),
        "report_gap_minutes": setting_float("report_gap_minutes", 10.0),
        "airport_radius_km": setting_float("airport_radius_km", 15.0),
        "max_speed_kt": setting_float("max_speed_kt", 1000.0),
        "position_conflict_km": setting_float("position_conflict_km", 5.0),
    }

    deduped = deduplicate_observations(observations)
    deduped.sort(key=lambda x: (x.get("_group_key") or "", x.get("_timestamp") or datetime.min.replace(tzinfo=timezone.utc)))

    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for o in deduped:
        grouped[o.get("_group_key") or "UNKNOWN"].append(o)

    flights: List[Dict[str, Any]] = []
    flight_index = 1
    provider_flights = case.get("flights") or []

    for group_key, points in grouped.items():
        segments = segment_flights(points, settings["max_gap_minutes"], settings["min_ground_minutes"])
        for seg in segments:
            if not seg:
                continue
            flights.append(build_flight(flight_index, group_key, seg, airports, sources, provider_flights, settings))
            flight_index += 1

    contradictions = detect_contradictions(deduped, flights, initial_contradictions, settings)
    supported_facts, candidate_facts, partial_facts, disputed_facts, not_facts = build_facts(deduped, flights, contradictions)
    hypotheses = build_hypotheses(flights, contradictions, issues)
    dual = dual_ai_review(deduped, flights, contradictions, issues)
    gaps = build_knowledge_gaps(deduped, flights, contradictions, issues, history)
    next_actions = build_next_actions(deduped, flights, gaps, contradictions)
    handoffs = build_specialist_handoffs(flights, contradictions, aircraft)
    graph = build_graph(aircraft, deduped, flights, airports, sources, supported_facts + candidate_facts + partial_facts, hypotheses, contradictions, gaps)

    # Collect summaries
    icao24_identifiers = sorted({o.get("_icao24") for o in deduped if o.get("_icao24")})
    registrations = sorted({o.get("_registration") for o in deduped if o.get("_registration")})
    callsigns = sorted({o.get("_callsign") for o in deduped if o.get("_callsign")})
    flight_numbers = sorted({o.get("_flight_number") for o in deduped if o.get("_flight_number")})

    operators = sorted({a.get("operator") for a in aircraft.values() if a.get("operator")})
    owner_candidates = sorted({a.get("owner_candidate") for a in aircraft.values() if a.get("owner_candidate")})
    lessors = sorted({a.get("lessor") for a in aircraft.values() if a.get("lessor")})
    aircraft_types = sorted({a.get("aircraft_type") for a in aircraft.values() if a.get("aircraft_type")})

    registration_history = [
        {
            "field": h.get("_field"),
            "value": h.get("_value"),
            "aircraft_id": h.get("aircraft_id"),
            "valid_from": iso_or_none(h.get("_valid_from")),
            "valid_to": iso_or_none(h.get("_valid_to")),
            "source_id": h.get("source_id"),
        }
        for h in history
        if h.get("_field") == "registration"
    ]
    operator_history = [
        {
            "field": h.get("_field"),
            "value": h.get("_value"),
            "aircraft_id": h.get("aircraft_id"),
            "valid_from": iso_or_none(h.get("_valid_from")),
            "valid_to": iso_or_none(h.get("_valid_to")),
            "source_id": h.get("source_id"),
        }
        for h in history
        if h.get("_field") == "operator"
    ]
    callsign_history = [
        {
            "field": h.get("_field"),
            "value": h.get("_value"),
            "aircraft_id": h.get("aircraft_id"),
            "valid_from": iso_or_none(h.get("_valid_from")),
            "valid_to": iso_or_none(h.get("_valid_to")),
            "source_id": h.get("source_id"),
        }
        for h in history
        if h.get("_field") == "callsign"
    ]

    position_sources = dict(Counter(o.get("_position_source") for o in deduped))
    mlat_count = position_sources.get("MLAT", 0)
    adsb_count = position_sources.get("ADS_B", 0)

    airports_used = {}
    for f in flights:
        for role in ("departure", "arrival"):
            ap = (f.get(role) or {}).get("airport") or {}
            code = ap.get("icao_code") or ap.get("iata_code")
            if code:
                airports_used[code] = ap

    route_counter: Counter = Counter()
    airport_counter: Counter = Counter()
    for f in flights:
        dep_code = ((f.get("departure") or {}).get("airport") or {}).get("icao_code") or ((f.get("departure") or {}).get("airport") or {}).get("iata_code")
        arr_code = ((f.get("arrival") or {}).get("airport") or {}).get("icao_code") or ((f.get("arrival") or {}).get("airport") or {}).get("iata_code")
        if dep_code:
            airport_counter[dep_code] += 1
        if arr_code:
            airport_counter[arr_code] += 1
        if dep_code and arr_code:
            route_counter[f"{dep_code}->{arr_code}"] += 1

    movement_patterns = []
    if route_counter:
        movement_patterns.append("top_routes=" + ", ".join(f"{k}:{v}" for k, v in route_counter.most_common(5)))
    if airport_counter:
        movement_patterns.append("top_airports=" + ", ".join(f"{k}:{v}" for k, v in airport_counter.most_common(5)))

    aviation_events: List[Dict[str, Any]] = []
    for f in flights:
        for sq in f.get("squawk_flags") or []:
            aviation_events.append(
                {
                    "event_type": "SQUAWK_EMERGENCY_CODE_OBSERVED",
                    "flight_id": f.get("flight_id"),
                    "details": sq,
                    "caution": "Do not sensationalize. Requires official/public corroboration.",
                }
            )
        if f.get("diversion_candidate"):
            aviation_events.append(
                {
                    "event_type": "DIVERSION_CANDIDATE",
                    "flight_id": f.get("flight_id"),
                    "details": {
                        "provider_arrival": (f.get("provider_flight") or {}).get("arrival_airport"),
                        "observed_arrival": ((f.get("arrival") or {}).get("airport") or {}).get("icao_code"),
                    },
                    "caution": "Cause unresolved. Could be ATC, weather, technical, operational, or data error.",
                }
            )

    timeline_updates = sorted(
        [
            {
                "flight_id": f.get("flight_id"),
                "group_key": f.get("group_key"),
                "start_time": f.get("start_time"),
                "end_time": f.get("end_time"),
                "departure": f.get("departure"),
                "arrival": f.get("arrival"),
            }
            for f in flights
        ],
        key=lambda x: x.get("start_time") or "",
    )

    def source_reliability_label(s: Dict[str, Any]) -> str:
        stype = str(s.get("source_type", "")).upper()
        if stype in {"OFFICIAL_REGISTRY", "AUTHORIZED_RECEIVER", "AIRPORT_RECORD", "AUTHORIZED_AVIATION_TELEMETRY"}:
            return "HIGH"
        if stype in {"ADS_B", "MLAT", "MODE_S", "PUBLIC_ADSB_FEED"}:
            return "MODERATE"
        if stype in {"AGGREGATOR", "PROVIDER_DERIVED", "COMMERCIAL_DATABASE", "MEDIA_REPORT"}:
            return "LOW"
        return "UNKNOWN"

    source_reliability = [
        {
            "source_id": s.get("source_id"),
            "provider": s.get("provider"),
            "source_type": s.get("source_type"),
            "reliability": source_reliability_label(s),
            "independence_group": s.get("_independence_group"),
            "upstream_feed": s.get("upstream_feed"),
            "limitations": s.get("limitations"),
        }
        for s in sources.values()
    ]

    source_pedigree = [
        {
            "source_id": s.get("source_id"),
            "provider": s.get("provider"),
            "source_type": s.get("source_type"),
            "upstream_feed": s.get("upstream_feed"),
            "independence_group": s.get("_independence_group"),
        }
        for s in sources.values()
    ]

    if any(f.get("source_independence") == "INDEPENDENT" for f in flights):
        source_independence = "INDEPENDENT_OBSERVATION_AVAILABLE"
    elif deduped:
        source_independence = "SINGLE_SOURCE_OR_UNKNOWN"
    else:
        source_independence = "NO_OBSERVATION"

    unknowns: List[str] = []
    if not deduped:
        unknowns.append("No measurable aviation activity supplied")
    if not flights:
        unknowns.append("Flight segmentation unresolved")
    if any(o.get("_resolution_basis") == "UNRESOLVED" for o in deduped):
        unknowns.append("Aircraft identity unresolved for some observations")
    if not registration_history:
        unknowns.append("Registration era uncertain")
    if not operator_history:
        unknowns.append("Operator era uncertain")
    unknowns.append("Passengers/occupants unknown by design")
    unknowns.append("Flight purpose unknown by design")

    if contradictions:
        status = "SOURCE_CONFLICT"
    elif issues:
        status = "PARTIAL"
    elif not deduped:
        status = "INCONCLUSIVE"
    elif flights and all(f.get("segmentation_confidence") in ("SUPPORTED", "PROBABLE") for f in flights):
        status = "SUCCEEDED"
    else:
        status = "PARTIAL"

    movement_anomaly = "NORMAL_OBSERVED_PATTERN"
    if any(f.get("data_quality_flags") for f in flights):
        movement_anomaly = "DATA_QUALITY_CANDIDATE"
    elif contradictions:
        movement_anomaly = "INCONCLUSIVE"
    elif aviation_events:
        movement_anomaly = "UNUSUAL"

    result: Dict[str, Any] = {
        "case_id": case.get("case_id"),
        "task_id": case.get("task_id"),
        "objective": case.get("objective"),
        "questions": case.get("questions") or [],
        "mode": case.get("model_mode", "LOCAL_ONLY"),
        "status": status,
        "movement_anomaly": movement_anomaly,
        "source_ids": list(sources.keys()),
        "evidence_ids": [o.get("observation_id") for o in deduped],
        "aircraft": [public_dict(a) for a in aircraft.values()],
        "airframes": [public_dict(a) for a in aircraft.values()],
        "icao24_identifiers": icao24_identifiers,
        "registrations": registrations,
        "registration_history": registration_history,
        "callsigns": callsigns,
        "callsign_history": callsign_history,
        "flight_numbers": flight_numbers,
        "operators": operators,
        "operator_history": operator_history,
        "owner_candidates": owner_candidates,
        "ownership_history": case.get("ownership_history") or [],
        "lessors": lessors,
        "aircraft_types": aircraft_types,
        "fleets": {
            op: sorted({aid for aid, a in aircraft.items() if a.get("operator") == op})
            for op in operators
        },
        "flights": flights,
        "trackpoints": [
            {
                "observation_id": o.get("observation_id"),
                "flight_id": o.get("_flight_id"),
                "group_key": o.get("_group_key"),
                "aircraft_id": o.get("_aircraft_id"),
                "icao24": o.get("_icao24"),
                "registration": o.get("_registration"),
                "callsign": o.get("_callsign"),
                "flight_number": o.get("_flight_number"),
                "timestamp": iso_or_none(o.get("_timestamp")),
                "latitude": o.get("_lat"),
                "longitude": o.get("_lon"),
                "altitude_ft": o.get("_altitude_ft"),
                "ground_speed_kt": o.get("_ground_speed_kt"),
                "vertical_rate_fpm": o.get("_vertical_rate_fpm"),
                "heading_deg": o.get("_heading_deg"),
                "track_deg": o.get("_track_deg"),
                "squawk": o.get("_squawk"),
                "on_ground": o.get("_on_ground"),
                "position_source": o.get("_position_source"),
                "source_ids": o.get("_source_ids"),
                "duplicate_count": o.get("_duplicate_count"),
                "resolution_basis": o.get("_resolution_basis"),
                "resolution_confidence": o.get("_resolution_confidence"),
                "flight_phase": o.get("_flight_phase"),
                "precision_m": o.get("precision_m"),
                "quality": o.get("quality"),
            }
            for o in deduped
        ],
        "track_segments": flights,
        "position_sources": position_sources,
        "mlat_context": {
            "mlat_observation_count": mlat_count,
            "adsb_observation_count": adsb_count,
            "note": "ADS-B and MLAT positions are kept separate. MLAT is not aircraft-reported ADS-B position.",
        },
        "airports": list(airports_used.values()),
        "runways": [
            {
                "airport_id": ap.get("airport_id"),
                "icao_code": ap.get("icao_code"),
                "runways": ap.get("runways") or [],
            }
            for ap in airports_used.values()
        ],
        "departure_assessments": [f.get("departure") for f in flights],
        "arrival_assessments": [f.get("arrival") for f in flights],
        "routes": [f.get("observed_route") for f in flights if f.get("observed_route")],
        "scheduled_routes": case.get("scheduled_routes") or [],
        "altitudes": numeric_summary([o.get("_altitude_ft") for o in deduped]),
        "ground_speeds": numeric_summary([o.get("_ground_speed_kt") for o in deduped]),
        "vertical_rates": numeric_summary([o.get("_vertical_rate_fpm") for o in deduped]),
        "tracks_headings": {
            "heading_summary": numeric_summary([o.get("_heading_deg") for o in deduped]),
            "track_summary": numeric_summary([o.get("_track_deg") for o in deduped]),
            "note": "Heading and track are kept separate unless source semantics support equivalence.",
        },
        "flight_phases": [
            {
                "flight_id": f.get("flight_id"),
                "phase_counts": f.get("flight_phase_counts"),
                "dominant_phase": f.get("dominant_flight_phase"),
                "note": "Flight phase is derived from movement and does not reveal mission purpose.",
            }
            for f in flights
        ],
        "squawk_context": [sq for f in flights for sq in (f.get("squawk_flags") or [])],
        "track_gaps": [gap for f in flights for gap in (f.get("track_gaps") or [])],
        "feed_coverage": [f.get("feed_coverage") for f in flights],
        "position_quality": {
            "precision_m_summary": numeric_summary([o.get("precision_m") for o in deduped]),
            "quality_counts": dict(Counter(o.get("quality") for o in deduped if o.get("quality"))),
            "note": "Do not claim meter-level accuracy unless source metadata supports it.",
        },
        "route_frequency": dict(route_counter),
        "airport_frequency": dict(airport_counter),
        "movement_patterns": movement_patterns,
        "fleet_context": {
            op: sorted({aid for aid, a in aircraft.items() if a.get("operator") == op})
            for op in operators
        },
        "aviation_events": aviation_events,
        "timeline_updates": timeline_updates,
        "observations": [
            {
                "observation_id": o.get("observation_id"),
                "group_key": o.get("_group_key"),
                "aircraft_id": o.get("_aircraft_id"),
                "icao24": o.get("_icao24"),
                "registration": o.get("_registration"),
                "callsign": o.get("_callsign"),
                "timestamp": iso_or_none(o.get("_timestamp")),
                "position_source": o.get("_position_source"),
                "source_ids": o.get("_source_ids"),
            }
            for o in deduped
        ],
        "candidate_facts": candidate_facts,
        "supported_facts": supported_facts,
        "partial_facts": partial_facts,
        "disputed_facts": disputed_facts,
        "source_reliability": source_reliability,
        "source_bias": case.get("source_bias") or [
            "Crowdsourced/public feeds may have uneven receiver density.",
            "Provider filtering or blocked-aircraft policies may create absence bias.",
            "Schedule enrichment may confuse scheduled and observed data.",
        ],
        "source_limitations": case.get("source_limitations") or [
            "Non-detection is not absence.",
            "Track gap is not transponder shutdown.",
            "Aggregated feeds may share upstream pedigree and are not independent.",
        ],
        "source_pedigree": source_pedigree,
        "source_independence": source_independence,
        "contradictions": contradictions,
        "hypotheses": hypotheses,
        "falsification_results": [
            {
                "hypothesis_id": h.get("hypothesis_id"),
                "status": "WEAKENED_BY_CONTRADICTIONS" if contradictions else "NOT_FALSIFIED_WITH_CURRENT_EVIDENCE",
                "required_additional_evidence": [
                    "Independent historical feed",
                    "Official registry / identifier era record",
                    "Airport movement record",
                    "Receiver coverage metadata",
                ],
            }
            for h in hypotheses
        ],
        "privacy_flags": [
            "NO_PASSENGER_INFERENCE",
            "NO_PRIVATE_PERSON_DOSSIER",
            "PROTECTED_PERSON_RESTRAINT",
            "HISTORICAL_FIRST",
            "METADATA_MINIMIZATION",
        ],
        "safety_flags": [
            "NO_REALTIME_TARGETING",
            "NO_INTERCEPTION",
            "NO_JAMMING",
            "NO_SPOOFING",
            "NO_TRANSPONDER_MANIPULATION",
            "NO_ATC_INTERFERENCE",
            "NO_TCAS_INTERFERENCE",
            "NO_GNSS_JAMMING_OR_SPOOFING",
            "NO_WEAPONS_TARGETING",
            "NO_STALKING",
        ],
        "unknowns": unknowns,
        "knowledge_gaps": gaps,
        "recommended_next_actions": next_actions,
        "specialist_handoffs": handoffs,
        "limitations": [
            "This scaffold does not fetch live ADS-B data.",
            "It consumes deterministic feature-level aviation records only.",
            "It does not invent trackpoints, landings, passengers, pilots, routes, operators, or purposes.",
            "It separates ADS-B, MLAT, provider-derived, estimated, and interpolated positions.",
            "It preserves registration/operator eras and does not apply current identity backward automatically.",
            "It treats track gaps as coverage/data limitations, not intentional evasion.",
            "It blocks real-time targeting, interception, stalking, jamming, spoofing, and transponder manipulation.",
        ],
        "dual_ai_review": dual,
        "not_facts": not_facts,
        "graphical_memory": graph,
        "validation_issues": issues,
        "validation_warnings": warnings,
        "analysis_settings": settings,
        "replay_manifest": {
            "generated_at": started,
            "finished_at": utcnow_iso(),
            "code_version": VERSION,
            "input_path": input_path,
            "input_sha256": input_hash,
            "deterministic_operations": [
                "identifier normalization",
                "time normalization",
                "track deduplication",
                "flight segmentation",
                "haversine distance",
                "ground speed derivation",
                "track gap detection",
                "position source classification",
                "source independence grouping",
                "contradiction detection",
                "fact gate",
            ],
            "note": "Replay requires raw source records, provider metadata, retrieval time, position source type, registry era evidence, and source pedigree.",
        },
    }

    result["required_analyst_summary"] = analyst_summary(result)
    return result


# -----------------------------------------------------------------------------
# Template
# -----------------------------------------------------------------------------

def template_case() -> Dict[str, Any]:
    return {
        "_template_note": "Placeholders only. Replace with deterministic public/authorized historical aviation records. Do not treat this template as real measurement.",
        "case_id": "CASE-ADSB-EXAMPLE",
        "task_id": "TASK-ADSB-EXAMPLE",
        "objective": "Historical/public analysis of one aircraft movement episode for safety and route research.",
        "questions": [
            "Which aircraft identity is supported for the observation period?",
            "What route segment is observed?",
            "Which positions are ADS-B vs MLAT vs provider-derived?",
            "What track gaps or contradictions exist?",
            "What remains uncertain?",
        ],
        "scope": {
            "authorized_only": True,
            "passive_only": True,
            "historical_first": True,
            "no_realtime_targeting": True,
            "privacy_minimization": True,
            "no_passenger_inference": True,
        },
        "authorization": {
            "lawful_basis": "PUBLIC_HISTORICAL_AVIATION_RESEARCH",
            "purpose": "SAFETY_AND_MOVEMENT_ANALYSIS",
            "approval_reference": "AUTH-ADSB-001",
            "data_retention": "MINIMUM_NECESSARY",
        },
        "model_mode": "LOCAL_ONLY",
        "time_range": {
            "start_time": "2025-01-01T10:00:00Z",
            "end_time": "2025-01-01T12:00:00Z",
        },
        "analysis_settings": {
            "max_gap_minutes": 30,
            "min_ground_minutes": 10,
            "report_gap_minutes": 10,
            "airport_radius_km": 15,
            "max_speed_kt": 1000,
            "position_conflict_km": 5,
        },
        "aircraft": [
            {
                "aircraft_id": "AIR-1",
                "icao24": "abc123",
                "registration": "N-EXAMPLE",
                "serial_number_if_available": "MSN-EXAMPLE",
                "aircraft_type": "EXAMPLE_TYPE",
                "manufacturer": "EXAMPLE_MANUFACTURER",
                "model": "EXAMPLE_MODEL",
                "variant": "EXAMPLE_VARIANT",
                "operator": "EXAMPLE_OPERATOR",
                "owner_candidate": "EXAMPLE_OWNER",
                "lessor": "EXAMPLE_LESSOR",
                "registration_country": "XX",
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_to": "2026-12-31T23:59:59Z",
                "source_ids": ["SRC-REG"],
                "confidence": "MODERATE",
            }
        ],
        "identifier_history": [
            {
                "aircraft_id": "AIR-1",
                "field": "registration",
                "value": "N-EXAMPLE",
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_to": "2026-12-31T23:59:59Z",
                "source_id": "SRC-REG",
            },
            {
                "aircraft_id": "AIR-1",
                "field": "icao24",
                "value": "abc123",
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_to": "2026-12-31T23:59:59Z",
                "source_id": "SRC-REG",
            },
        ],
        "sources": [
            {
                "source_id": "SRC-REG",
                "provider": "EXAMPLE_OFFICIAL_REGISTRY",
                "source_type": "OFFICIAL_REGISTRY",
                "upstream_feed": None,
                "independence_group": "REGISTRY",
                "limitations": ["Registry may lag operational changes."],
            },
            {
                "source_id": "SRC-ADS-1",
                "provider": "EXAMPLE_PUBLIC_ADSB_FEED",
                "source_type": "PUBLIC_ADSB_FEED",
                "upstream_feed": "FEED-A",
                "independence_group": "FEED-A",
                "limitations": ["Receiver coverage uneven."],
            },
            {
                "source_id": "SRC-MLAT-1",
                "provider": "EXAMPLE_MLAT_PROVIDER",
                "source_type": "MLAT",
                "upstream_feed": "FEED-B",
                "independence_group": "FEED-B",
                "limitations": ["MLAT position is derived from receiver timing, not aircraft-reported position."],
            },
        ],
        "airports": [
            {
                "airport_id": "AP-A",
                "icao_code": "KAAA",
                "iata_code": "AAA",
                "name": "Example Airport A",
                "country": "XX",
                "latitude": 0.0,
                "longitude": 0.0,
                "elevation_ft": 100,
                "runways": ["09/27"],
                "source": "EXAMPLE_AIRPORT_METADATA",
                "validity": "2025",
            },
            {
                "airport_id": "AP-B",
                "icao_code": "KBBB",
                "iata_code": "BBB",
                "name": "Example Airport B",
                "country": "YY",
                "latitude": 1.0,
                "longitude": 1.0,
                "elevation_ft": 200,
                "runways": ["18/36"],
                "source": "EXAMPLE_AIRPORT_METADATA",
                "validity": "2025",
            },
        ],
        "observations": [
            {
                "observation_id": "OBS-1",
                "source_id": "SRC-ADS-1",
                "timestamp": "2025-01-01T10:00:00Z",
                "icao24": "abc123",
                "registration": "N-EXAMPLE",
                "callsign": "EX123",
                "flight_number": "EX123",
                "latitude": 0.001,
                "longitude": 0.001,
                "altitude_ft": 0,
                "ground_speed_kt": 0,
                "vertical_rate_fpm": 0,
                "heading_deg": 90,
                "track_deg": 90,
                "squawk": "1200",
                "on_ground": True,
                "position_source": "ADS_B",
                "precision_m": 10,
                "quality": "GOOD",
            },
            {
                "observation_id": "OBS-2",
                "source_id": "SRC-ADS-1",
                "timestamp": "2025-01-01T10:05:00Z",
                "icao24": "abc123",
                "registration": "N-EXAMPLE",
                "callsign": "EX123",
                "flight_number": "EX123",
                "latitude": 0.05,
                "longitude": 0.05,
                "altitude_ft": 5000,
                "ground_speed_kt": 250,
                "vertical_rate_fpm": 1800,
                "heading_deg": 45,
                "track_deg": 45,
                "squawk": "1200",
                "on_ground": False,
                "position_source": "ADS_B",
                "precision_m": 10,
                "quality": "GOOD",
            },
            {
                "observation_id": "OBS-3",
                "source_id": "SRC-MLAT-1",
                "timestamp": "2025-01-01T11:00:00Z",
                "icao24": "abc123",
                "registration": "N-EXAMPLE",
                "callsign": "EX123",
                "flight_number": "EX123",
                "latitude": 0.5,
                "longitude": 0.5,
                "altitude_ft": 35000,
                "ground_speed_kt": 480,
                "vertical_rate_fpm": 0,
                "heading_deg": 45,
                "track_deg": 45,
                "squawk": "1200",
                "on_ground": False,
                "position_source": "MLAT",
                "precision_m": 100,
                "quality": "FAIR",
            },
            {
                "observation_id": "OBS-4",
                "source_id": "SRC-ADS-1",
                "timestamp": "2025-01-01T12:00:00Z",
                "icao24": "abc123",
                "registration": "N-EXAMPLE",
                "callsign": "EX123",
                "flight_number": "EX123",
                "latitude": 1.001,
                "longitude": 1.001,
                "altitude_ft": 0,
                "ground_speed_kt": 15,
                "vertical_rate_fpm": 0,
                "heading_deg": 180,
                "track_deg": 180,
                "squawk": "1200",
                "on_ground": True,
                "position_source": "ADS_B",
                "precision_m": 10,
                "quality": "GOOD",
            },
        ],
        "flights": [
            {
                "flight_id": "PF-EX123",
                "aircraft_id": "AIR-1",
                "callsign": "EX123",
                "flight_number": "EX123",
                "operator": "EXAMPLE_OPERATOR",
                "departure_airport": "KAAA",
                "arrival_airport": "KBBB",
                "scheduled_departure_time": "2025-01-01T10:00:00Z",
                "scheduled_arrival_time": "2025-01-01T12:00:00Z",
                "source_id": "SRC-SCHEDULE",
            }
        ],
        "scheduled_routes": [
            {
                "flight_number": "EX123",
                "departure": "KAAA",
                "arrival": "KBBB",
                "source": "EXAMPLE_SCHEDULE",
                "note": "Scheduled route is not observed route.",
            }
        ],
        "existing_facts": [],
        "existing_hypotheses": [],
        "existing_contradictions": [],
        "budget": "EXAMPLE",
        "deadline": "EXAMPLE",
    }


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TRACEATLAS ADSBINT passive-first, historical-first analysis scaffold. Consumes deterministic aviation records; does not fetch live feeds, jam, spoof, target, stalk, or infer passengers."
    )
    parser.add_argument("--input", "-i", help="Path to ADS-B input JSON")
    parser.add_argument("--output", "-o", default="adsbint_result.json", help="Output ADSBINTResult JSON path")
    parser.add_argument("--write-template", action="store_true", help="Print a safe input template and exit")
    args = parser.parse_args()

    if args.write_template:
        print(json.dumps(template_case(), indent=2, default=str))
        return

    if not args.input:
        parser.error("--input is required unless --write-template is used")

    path = Path(args.input)
    if not path.exists():
        raise SystemExit(f"Input file not found: {path}")

    raw = path.read_bytes()
    input_hash = sha256_bytes(raw)

    try:
        case = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise SystemExit(f"Failed to parse input JSON: {exc}")

    if not isinstance(case, dict):
        raise SystemExit("Input JSON must be an object")

    result = analyze(case, str(path), input_hash)

    out = Path(args.output)
    out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")

    print(
        json.dumps(
            {
                "status": result.get("status"),
                "movement_anomaly": result.get("movement_anomaly"),
                "output": str(out),
                "summary": result.get("required_analyst_summary"),
            },
            indent=2,
            default=str,
        )
    )


if __name__ == "__main__":
    main()
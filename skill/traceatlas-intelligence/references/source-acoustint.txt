#!/usr/bin/env python3
"""
TRACEATLAS ACOUSTINT main.py
============================

Authorized, passive-first, defensive acoustic intelligence scaffold.

This module:
- Does NOT activate microphones.
- Does NOT record private conversations.
- Does NOT perform voice biometrics or speaker-to-person identification.
- Does NOT track private persons by voice, footsteps, or acoustic signature.
- Does NOT design sonic weapons or harmful acoustic exposure.
- Does NOT provide weapon/shooter targeting.
- Does NOT provide submarine/military target localization.
- Does NOT provide sonar evasion, acoustic stealth, or detection avoidance.
- Does NOT jam or tamper with public-safety acoustic systems.
- Does NOT fetch live audio.
- Does NOT invent measurements, events, frequencies, dB values, or locations.

It consumes deterministic feature-level acoustic records supplied by authorized/public sources:
- sensor metadata
- recording metadata
- calibration / clock synchronization state
- signal quality flags
- acoustic event detections
- spectral/temporal feature exports
- DOA/TDOA observations or precomputed localization candidates
- environment / weather / propagation context
- reference signatures
- source pedigree / independence metadata

It produces an evidence-linked ACOUSTINTResult with:
- sensor/recording validation
- quality control
- event correlation
- conservative source-category classification
- signature similarity without identity claims
- multi-sensor independence checks
- localization uncertainty handling
- duplicate/provenance checks
- contradiction preservation
- competing hypotheses and falsification
- dual-AI style skeptic review
- privacy/safety flags
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

ALLOWED_CALIBRATION = {
    "CALIBRATED",
    "PARTIALLY_CALIBRATED",
    "UNCALIBRATED",
    "CALIBRATION_UNKNOWN",
}

ALLOWED_SYNC = {
    "SYNCHRONIZED",
    "OFFSET_CORRECTED",
    "APPROXIMATELY_ALIGNED",
    "UNSYNCHRONIZED",
    "UNKNOWN",
}

EVENT_TYPES = {
    "SPEECH_PRESENT",
    "MACHINERY",
    "ENGINE",
    "VEHICLE",
    "AIRCRAFT_LIKE",
    "RAIL_LIKE",
    "MARINE_VESSEL_LIKE",
    "HUMAN_ACTIVITY",
    "ANIMAL",
    "WEATHER",
    "WATER",
    "ALARM",
    "SIREN",
    "BELL",
    "GLASS_BREAK_LIKE",
    "IMPACT",
    "EXPLOSION_LIKE",
    "GUNSHOT_LIKE",
    "CONSTRUCTION",
    "ROTATING_MACHINE",
    "PUMP",
    "FAN",
    "MOTOR",
    "COMPRESSOR",
    "ELECTRICAL_BUZZ",
    "MECHANICAL_FAILURE_LIKE",
    "HYDROACOUSTIC_EVENT",
    "UNKNOWN_IMPULSIVE",
    "UNKNOWN_TONAL",
    "UNKNOWN_BROADBAND",
    "UNKNOWN",
}

SOURCE_CATEGORIES = {
    "environment",
    "machine",
    "vehicle",
    "infrastructure",
    "animal",
    "human_activity",
    "weather",
    "marine",
    "unknown",
}

CLASSIFICATION_STATES = {
    "VERIFIED_CATEGORY",
    "SUPPORTED_CATEGORY",
    "PROBABLE_CATEGORY",
    "POSSIBLE_CATEGORY",
    "UNRESOLVED",
    "DISPUTED",
}

LOCALIZATION_PRECISION = {
    "DIRECTION_ONLY",
    "AREA",
    "REGION",
    "SITE",
    "POINT_CANDIDATE",
    "EXACT_SUPPORTED",
    "UNKNOWN",
}

SENSITIVE_EVENT_TYPES = {
    "SPEECH_PRESENT",
    "HUMAN_ACTIVITY",
    "GUNSHOT_LIKE",
    "EXPLOSION_LIKE",
    "ALARM",
    "SIREN",
    "GLASS_BREAK_LIKE",
}

PERSON_RELATED_EVENT_TYPES = {
    "SPEECH_PRESENT",
    "HUMAN_ACTIVITY",
}

SEVERE_QUALITY_FLAGS = {
    "clipping",
    "saturation",
    "dropout",
    "clock_unsynchronized",
    "uncalibrated",
    "calibration_unknown",
    "low_snr",
    "agc_active",
    "generated_audio",
    "synthetic_candidate",
    "above_nyquist",
    "missing_event_time",
    "sensor_position_missing",
    "tdoa_sound_speed_missing",
    "doa_uncertainty_missing",
}

BLOCK_PHRASES = [
    # covert / privacy
    "covert listening",
    "hidden microphone",
    "secret microphone",
    "wiretap",
    "eavesdrop",
    "private conversation",
    "intercept private speech",
    "record private conversation",
    "deploy listening device",
    "surveillance microphone placement",
    "track private person",
    "person tracking",
    "stalk",
    "stalking",
    "harass",
    "private residence monitoring",

    # voice biometrics / sensitive inference
    "voiceprint",
    "voice print",
    "speaker identification",
    "speaker recognition",
    "speaker-to-name",
    "voice-to-name",
    "biometric voice",
    "identify person by voice",
    "voice stress",
    "lie detector",
    "truthfulness detection",
    "deception detection",
    "emotion-based deception",
    "infer guilt from voice",
    "infer ethnicity from voice",
    "infer religion from voice",
    "infer political belief from voice",
    "infer criminal propensity from voice",

    # weapons / harmful acoustics
    "sonic weapon",
    "ultrasonic harassment",
    "harmful acoustic exposure",
    "blast optimization",
    "weapon targeting",
    "shooter targeting",
    "shooter location",
    "weapon location after movement",
    "acoustic homing",
    "targeting solution",
    "fire control",
    "strike coordinate",

    # military / evasion
    "submarine detection",
    "submarine localization",
    "warship acoustic tracking",
    "torpedo localization",
    "sonar evasion",
    "acoustic stealth",
    "detection avoidance",
    "counter-detection tactic",
    "jam public-safety acoustic",
    "tamper public-safety acoustic",
]

FEATURE_KEYS = [
    "spectral_centroid_hz",
    "spectral_rolloff_hz",
    "spectral_flatness",
    "dominant_frequency_hz",
    "band_energy_total",
    "duration_s",
    "periodicity_interval_s",
    "impulsiveness",
    "snr_db",
    "rise_time_ms",
]

TYPE_TO_CATEGORY = {
    "MACHINERY": "machine",
    "ROTATING_MACHINE": "machine",
    "PUMP": "machine",
    "FAN": "machine",
    "MOTOR": "machine",
    "COMPRESSOR": "machine",
    "ELECTRICAL_BUZZ": "machine",
    "MECHANICAL_FAILURE_LIKE": "machine",
    "ENGINE": "vehicle",
    "VEHICLE": "vehicle",
    "AIRCRAFT_LIKE": "vehicle",
    "RAIL_LIKE": "vehicle",
    "MARINE_VESSEL_LIKE": "marine",
    "HYDROACOUSTIC_EVENT": "marine",
    "SPEECH_PRESENT": "human_activity",
    "HUMAN_ACTIVITY": "human_activity",
    "ANIMAL": "animal",
    "WEATHER": "weather",
    "WATER": "environment",
    "ALARM": "infrastructure",
    "SIREN": "infrastructure",
    "BELL": "infrastructure",
    "GLASS_BREAK_LIKE": "impact",
    "IMPACT": "impact",
    "EXPLOSION_LIKE": "impact",
    "GUNSHOT_LIKE": "impact",
    "CONSTRUCTION": "machine",
    "UNKNOWN_IMPULSIVE": "unknown",
    "UNKNOWN_TONAL": "unknown",
    "UNKNOWN_BROADBAND": "unknown",
    "UNKNOWN": "unknown",
}


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


def add_flag(obj: Dict[str, Any], flag: str) -> None:
    flags = obj.setdefault("_quality_flags", [])
    f = str(flag).strip().lower()
    if f and f not in flags:
        flags.append(f)


def safe_std(values: List[float]) -> Optional[float]:
    vals = [v for v in values if v is not None]
    if len(vals) < 2:
        return None
    try:
        return statistics.stdev(vals)
    except Exception:
        return None


def numeric_summary(values: List[Any]) -> Dict[str, Any]:
    arr: List[float] = []
    for v in values:
        f = to_float(v)
        if f is not None:
            arr.append(f)
    if not arr:
        return {"count": 0, "min": None, "max": None, "median": None, "mean": None, "std": None}
    return {
        "count": len(arr),
        "min": min(arr),
        "max": max(arr),
        "median": statistics.median(arr),
        "mean": statistics.fmean(arr),
        "std": safe_std(arr),
    }


def haversine_km(
    lat1: Optional[float],
    lon1: Optional[float],
    lat2: Optional[float],
    lon2: Optional[float],
) -> Optional[float]:
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


def haversine_m(
    lat1: Optional[float],
    lon1: Optional[float],
    lat2: Optional[float],
    lon2: Optional[float],
) -> Optional[float]:
    d = haversine_km(lat1, lon1, lat2, lon2)
    return None if d is None else d * 1000.0


def normalize_deg(value: Any) -> Optional[float]:
    v = to_float(value)
    if v is None:
        return None
    v = v % 360.0
    if v < 0:
        v += 360.0
    return v


def circular_mean_deg(values: List[Optional[float]]) -> Optional[float]:
    vals = [normalize_deg(v) for v in values if normalize_deg(v) is not None]
    if not vals:
        return None
    sin_sum = sum(math.sin(math.radians(v)) for v in vals)
    cos_sum = sum(math.cos(math.radians(v)) for v in vals)
    angle = math.degrees(math.atan2(sin_sum, cos_sum)) % 360.0
    return angle


def circular_std_deg(values: List[Optional[float]]) -> Optional[float]:
    vals = [normalize_deg(v) for v in values if normalize_deg(v) is not None]
    if not vals:
        return None
    n = len(vals)
    sin_sum = sum(math.sin(math.radians(v)) for v in vals) / n
    cos_sum = sum(math.cos(math.radians(v)) for v in vals) / n
    r = math.sqrt(sin_sum * sin_sum + cos_sum * cos_sum)
    if r <= 0:
        return 180.0
    if r >= 1:
        return 0.0
    return math.degrees(math.sqrt(-2.0 * math.log(r)))


def local_enu(lat: float, lon: float, lat0: float, lon0: float) -> Tuple[float, float]:
    r = 6371000.0
    x = math.radians(lon - lon0) * r * math.cos(math.radians(lat0))
    y = math.radians(lat - lat0) * r
    return x, y


def enu_to_latlon(x: float, y: float, lat0: float, lon0: float) -> Tuple[float, float]:
    r = 6371000.0
    lat = lat0 + math.degrees(y / r)
    lon = lon0 + math.degrees(x / (r * math.cos(math.radians(lat0))))
    return lat, lon


def bearing_vector_deg(bearing_deg: float) -> Tuple[float, float]:
    theta = math.radians(normalize_deg(bearing_deg) or 0.0)
    return math.sin(theta), math.cos(theta)  # east, north


def cross2(a: Tuple[float, float], b: Tuple[float, float]) -> float:
    return a[0] * b[1] - a[1] * b[0]


def line_intersection(
    p1: Tuple[float, float],
    d1: Tuple[float, float],
    p2: Tuple[float, float],
    d2: Tuple[float, float],
) -> Optional[Tuple[Tuple[float, float], float, float]]:
    denom = cross2(d1, d2)
    if abs(denom) < 1e-9:
        return None
    dp = (p2[0] - p1[0], p2[1] - p1[1])
    t = cross2(dp, d2) / denom
    u = cross2(dp, d1) / denom
    point = (p1[0] + t * d1[0], p1[1] + t * d1[1])
    return point, t, u


def cosine_similarity(a: List[float], b: List[float]) -> Optional[float]:
    if len(a) != len(b) or not a:
        return None
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return None
    return dot / (na * nb)


def l2_normalize(vec: List[float]) -> Optional[List[float]]:
    n = math.sqrt(sum(x * x for x in vec))
    if n == 0:
        return None
    return [x / n for x in vec]


def transform_feature_value(value: Optional[float]) -> float:
    if value is None:
        return 0.0
    if value > 0:
        return math.log1p(value)
    return value


def vector_from_mapping(mapping: Dict[str, Any]) -> Optional[List[float]]:
    raw = []
    for key in FEATURE_KEYS:
        raw.append(transform_feature_value(to_float(mapping.get(key))))
    vec = l2_normalize(raw)
    return vec


def extract_spectral_features_from_bands(bands: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(bands, list) or not bands:
        return None

    centers: List[float] = []
    powers: List[float] = []

    for b in bands:
        if not isinstance(b, dict):
            continue
        c = to_float(b.get("center_hz") or b.get("frequency_hz") or b.get("center"))
        p_lin = to_float(b.get("power_linear") or b.get("power"))
        p_db = to_float(
            b.get("power_db")
            or b.get("power_dbfs")
            or b.get("power_db spl")
            or b.get("power_dbm")
        )

        if c is None:
            continue
        if p_lin is None and p_db is not None:
            p_lin = 10.0 ** (p_db / 10.0)
        if p_lin is None:
            continue

        centers.append(c)
        powers.append(max(0.0, p_lin))

    if not centers or not powers:
        return None

    total = sum(powers)
    if total <= 0:
        return None

    centroid = sum(c * p for c, p in zip(centers, powers)) / total
    max_power = max(powers)
    max_idx = powers.index(max_power)

    sorted_pairs = sorted(zip(centers, powers), key=lambda x: x[0])
    cum = 0.0
    rolloff = sorted_pairs[-1][0]
    for c, p in sorted_pairs:
        cum += p
        if cum >= 0.85 * total:
            rolloff = c
            break

    # Spectral flatness: geometric mean / arithmetic mean, epsilon-guarded.
    eps = 1e-12
    log_sum = sum(math.log(p + eps) for _, p in sorted_pairs)
    geo_mean = math.exp(log_sum / len(sorted_pairs))
    arith_mean = total / len(sorted_pairs)
    flatness = geo_mean / arith_mean if arith_mean > 0 else None

    return {
        "band_count": len(centers),
        "total_power_linear": total,
        "max_power_linear": max_power,
        "dominant_frequency_hz": centers[max_idx],
        "spectral_centroid_hz": centroid,
        "spectral_rolloff_hz": rolloff,
        "spectral_flatness": flatness,
        "method": "deterministic_summary_from_supplied_bands",
        "limitation": "No FFT was performed by this script; features come only from supplied band data.",
    }


def get_event_metric(ev: Dict[str, Any], key: str) -> Optional[float]:
    sf = ev.get("_spectral_features") or {}

    direct_map = {
        "spectral_centroid_hz": sf.get("spectral_centroid_hz"),
        "spectral_rolloff_hz": sf.get("spectral_rolloff_hz"),
        "spectral_flatness": sf.get("spectral_flatness"),
        "dominant_frequency_hz": sf.get("dominant_frequency_hz") or ev.get("dominant_frequency_hz"),
        "band_energy_total": sf.get("total_power_linear"),
        "duration_s": ev.get("_duration_s") or ev.get("duration_s"),
        "periodicity_interval_s": (
            ev.get("periodicity_interval_s")
            or (ev.get("periodicity") or {}).get("interval_s")
        ),
        "impulsiveness": ev.get("impulsiveness"),
        "snr_db": ev.get("snr_db") or ev.get("_snr_db"),
        "rise_time_ms": ev.get("rise_time_ms"),
    }

    return to_float(direct_map.get(key))


def build_event_vector(ev: Dict[str, Any]) -> Optional[List[float]]:
    fv = ev.get("feature_vector")
    if isinstance(fv, list):
        nums = [to_float(x) for x in fv]
        nums = [x for x in nums if x is not None]
        if nums:
            transformed = [transform_feature_value(x) for x in nums]
            return l2_normalize(transformed)

    mapping = {key: get_event_metric(ev, key) for key in FEATURE_KEYS}
    return vector_from_mapping(mapping)


def build_reference_vector(ref: Dict[str, Any]) -> Optional[List[float]]:
    fv = ref.get("feature_vector")
    if isinstance(fv, list):
        nums = [to_float(x) for x in fv]
        nums = [x for x in nums if x is not None]
        if nums:
            transformed = [transform_feature_value(x) for x in nums]
            return l2_normalize(transformed)

    sf = ref.get("spectral_features") or extract_spectral_features_from_bands(ref.get("band_energy"))
    if not isinstance(sf, dict):
        sf = {}

    mapping = {
        "spectral_centroid_hz": sf.get("spectral_centroid_hz"),
        "spectral_rolloff_hz": sf.get("spectral_rolloff_hz"),
        "spectral_flatness": sf.get("spectral_flatness"),
        "dominant_frequency_hz": sf.get("dominant_frequency_hz") or ref.get("dominant_frequency_hz"),
        "band_energy_total": sf.get("total_power_linear"),
        "duration_s": ref.get("duration_s"),
        "periodicity_interval_s": (
            ref.get("periodicity_interval_s")
            or (ref.get("periodicity") or {}).get("interval_s")
        ),
        "impulsiveness": ref.get("impulsiveness"),
        "snr_db": ref.get("snr_db"),
        "rise_time_ms": ref.get("rise_time_ms"),
    }

    return vector_from_mapping(mapping)


def average_vectors(vectors: List[List[float]]) -> Optional[List[float]]:
    vectors = [v for v in vectors if v]
    if not vectors:
        return None
    dim = len(vectors[0])
    vectors = [v for v in vectors if len(v) == dim]
    if not vectors:
        return None
    avg = [statistics.fmean([v[i] for v in vectors]) for i in range(dim)]
    return l2_normalize(avg)


def sound_speed_m_s(environment: Dict[str, Any]) -> Optional[float]:
    c = to_float(environment.get("sound_speed_m_s"))
    if c is not None and c > 0:
        return c

    temp_c = to_float(
        (environment.get("weather") or {}).get("temperature_c")
        or environment.get("temperature_c")
    )
    if temp_c is not None:
        # Standard approximate dry-air speed. Humidity/pressure effects are not invented here.
        c = 331.3 + 0.606 * temp_c
        if c > 0:
            return c

    return None


# -----------------------------------------------------------------------------
# Policy gate
# -----------------------------------------------------------------------------

def policy_block_reasons(case: Dict[str, Any]) -> List[str]:
    reasons: List[str] = []

    scanned_parts: List[str] = []
    for key in ("objective", "questions", "scope", "authorization", "requested_outputs", "tags", "next_action_requests"):
        val = case.get(key)
        if val is not None:
            scanned_parts.append(json.dumps(val, ensure_ascii=False, default=str))

    text = " ".join(scanned_parts).lower()

    for phrase in BLOCK_PHRASES:
        if phrase in text:
            reasons.append(f"Forbidden ACOUSTINT action/request detected: '{phrase}'")

    scope = case.get("scope") if isinstance(case.get("scope"), dict) else {}
    auth = case.get("authorization") if isinstance(case.get("authorization"), dict) else {}
    requested = case.get("requested_outputs") if isinstance(case.get("requested_outputs"), dict) else {}

    if scope.get("authorized_only") is not True:
        reasons.append("scope.authorized_only must be true")

    if scope.get("passive_only") is False:
        reasons.append("scope.passive_only must be true")

    if scope.get("no_person_tracking") is False:
        reasons.append("scope.no_person_tracking must be true")

    if scope.get("voice_biometric") is True:
        reasons.append("scope.voice_biometric is prohibited")

    if scope.get("covert_recording") is True:
        reasons.append("scope.covert_recording is prohibited")

    if scope.get("weapon_targeting") is True:
        reasons.append("scope.weapon_targeting is prohibited")

    if scope.get("military_target_localization") is True:
        reasons.append("scope.military_target_localization is prohibited")

    if requested.get("person_location") is True:
        reasons.append("requested_outputs.person_location is prohibited")

    if requested.get("speaker_identity") is True:
        reasons.append("requested_outputs.speaker_identity is prohibited")

    if requested.get("weapon_targeting") is True:
        reasons.append("requested_outputs.weapon_targeting is prohibited")

    if not auth.get("lawful_basis"):
        reasons.append("authorization.lawful_basis is missing")

    if not auth.get("purpose"):
        reasons.append("authorization.purpose is missing")

    return reasons


def blocked_result(
    case: Dict[str, Any],
    reasons: List[str],
    started: str,
    input_path: Optional[str],
    input_hash: Optional[str],
) -> Dict[str, Any]:
    return {
        "case_id": case.get("case_id"),
        "task_id": case.get("task_id"),
        "objective": case.get("objective"),
        "status": "POLICY_BLOCKED",
        "policy_block_reasons": reasons,
        "mode": case.get("model_mode", "LOCAL_ONLY"),
        "safety_flags": [
            "NO_COVERT_LISTENING",
            "NO_PRIVATE_SPEECH_INTERCEPTION",
            "NO_VOICE_BIOMETRIC_IDENTIFICATION",
            "NO_PERSON_TRACKING",
            "NO_SONIC_WEAPON",
            "NO_ULTRASONIC_HARASSMENT",
            "NO_WEAPON_TARGETING",
            "NO_SHOOTER_TARGETING",
            "NO_MILITARY_TARGET_LOCALIZATION",
            "NO_SONAR_EVASION",
            "NO_ACOUSTIC_STEALTH_OPTIMIZATION",
            "NO_JAMMING_PUBLIC_SAFETY_ACOUSTIC_SYSTEMS",
        ],
        "privacy_flags": [
            "NO_SPEECH_TRANSCRIPTION_WITHOUT_AUTHORIZATION",
            "NO_SPEAKER_IDENTIFICATION",
            "NO_SENSITIVE_TRAIT_INFERENCE",
            "METADATA_MINIMIZATION",
        ],
        "recommended_next_actions": [
            "Restate objective as authorized passive acoustic event/signature analysis",
            "Use authorized sensor exports with calibration and clock metadata",
            "Hand speech content questions to AUDINT only under separate authorization",
            "Use multi-sensor uncertainty-aware localization for event regions only",
            "Escalate consequential public-safety findings to authorized human responders",
        ],
        "limitations": [
            "Requested or detected use crosses ACOUSTINT defensive boundary.",
            "No covert listening, private speech interception, voice biometrics, person tracking, sonic weapons, targeting, military localization, sonar evasion, or acoustic stealth support is provided.",
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
# Validation
# -----------------------------------------------------------------------------

def validate_sensors(case: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    issues: List[str] = []
    sensors: Dict[str, Dict[str, Any]] = {}

    for idx, s in enumerate(case.get("sensors") or []):
        if not isinstance(s, dict):
            issues.append(f"sensors[{idx}] is not an object")
            continue

        sid = s.get("sensor_id")
        if not sid:
            issues.append(f"sensors[{idx}] missing sensor_id")
            continue

        cal = str(s.get("calibration_status", "CALIBRATION_UNKNOWN")).strip().upper()
        if cal not in ALLOWED_CALIBRATION:
            issues.append(f"sensor {sid} unknown calibration_status={cal}; set CALIBRATION_UNKNOWN")
            cal = "CALIBRATION_UNKNOWN"
        s["_calibration_status"] = cal

        sync = str(s.get("clock_sync_state", "UNKNOWN")).strip().upper()
        if sync not in ALLOWED_SYNC:
            issues.append(f"sensor {sid} unknown clock_sync_state={sync}; set UNKNOWN")
            sync = "UNKNOWN"
        s["_clock_sync_state"] = sync

        loc = s.get("position") if isinstance(s.get("position"), dict) else {}
        lat = to_float(loc.get("latitude") if loc.get("latitude") is not None else loc.get("lat"))
        lon = to_float(loc.get("longitude") if loc.get("longitude") is not None else loc.get("lon"))
        alt = to_float(loc.get("altitude_m") if loc.get("altitude_m") is not None else loc.get("alt"))
        pos_acc = to_float(loc.get("accuracy_m") or loc.get("uncertainty_m"))

        if lat is not None and not (-90.0 <= lat <= 90.0):
            lat = None
        if lon is not None and not (-180.0 <= lon <= 180.0):
            lon = None

        s["_lat"] = lat
        s["_lon"] = lon
        s["_alt"] = alt
        s["_position_accuracy_m"] = pos_acc

        if lat is None or lon is None:
            add_flag(s, "sensor_position_missing")

        if cal != "CALIBRATED":
            add_flag(s, "uncalibrated" if cal == "UNCALIBRATED" else cal.lower())

        if sync == "UNSYNCHRONIZED":
            add_flag(s, "clock_unsynchronized")

        sensors[sid] = s

    if not sensors:
        issues.append("No authorized acoustic sensors supplied")

    return sensors, issues


def validate_recordings(
    case: Dict[str, Any],
    sensors: Dict[str, Dict[str, Any]],
) -> Tuple[Dict[str, Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    recordings: Dict[str, Dict[str, Any]] = {}

    signal_quality = case.get("signal_quality") if isinstance(case.get("signal_quality"), dict) else {}

    for idx, r in enumerate(case.get("recordings") or []):
        if not isinstance(r, dict):
            issues.append(f"recordings[{idx}] is not an object")
            continue

        rid = r.get("recording_id") or f"REC-{idx + 1}"
        r["recording_id"] = rid

        sid = r.get("sensor_id")
        if sid not in sensors:
            issues.append(f"recording {rid} references unknown sensor_id={sid}")

        sensor = sensors.get(sid, {})

        start = parse_dt(r.get("start_time"))
        end = parse_dt(r.get("end_time"))
        if start and end and end < start:
            issues.append(f"recording {rid} has end_time before start_time")

        r["_start"] = start
        r["_end"] = end

        sr = to_float(r.get("sample_rate_hz") or r.get("sample_rate") or sensor.get("sample_rate_hz"))
        r["_sample_rate_hz"] = sr
        if sr is not None and sr <= 0:
            add_flag(r, "invalid_sample_rate")
            r["_sample_rate_hz"] = None

        r["_nyquist_hz"] = (r["_sample_rate_hz"] / 2.0) if r["_sample_rate_hz"] else None

        if not r.get("content_hash"):
            add_flag(r, "provenance_missing")

        sq = signal_quality.get(rid, {}) if isinstance(signal_quality.get(rid), dict) else {}
        for k, v in sq.items():
            r.setdefault(k, v)

        r["_noise_floor_db"] = to_float(r.get("noise_floor_db") or r.get("noise_floor_dbfs"))
        r["_snr_db"] = to_float(r.get("snr_db"))
        r["_clipping"] = bool(r.get("clipping_detected") or r.get("clipping"))
        r["_saturation"] = bool(r.get("saturation"))
        r["_dropout"] = bool(r.get("dropout_detected") or r.get("dropout"))
        r["_agc_active"] = bool(r.get("agc_active") or r.get("agc"))
        r["_lossy_compression"] = bool(r.get("lossy_compression") or r.get("lossy"))
        r["_generated_or_reconstructed"] = bool(r.get("generated_or_reconstructed_audio") or r.get("generated_audio"))
        r["_synthetic_indicators"] = bool(r.get("synthetic_indicators_present") or r.get("synthetic_candidate"))
        r["_metadata_time_uncertainty_s"] = to_float(r.get("metadata_time_uncertainty_s"))

        if r["_clipping"]:
            add_flag(r, "clipping")
        if r["_saturation"]:
            add_flag(r, "saturation")
        if r["_dropout"]:
            add_flag(r, "dropout")
        if r["_agc_active"]:
            add_flag(r, "agc_active")
        if r["_lossy_compression"]:
            add_flag(r, "lossy_compression")
        if r["_generated_or_reconstructed"]:
            add_flag(r, "generated_audio")
        if r["_synthetic_indicators"]:
            add_flag(r, "synthetic_candidate")
        if r["_snr_db"] is not None and r["_snr_db"] < 3.0:
            add_flag(r, "low_snr")

        if sensor.get("_clock_sync_state") == "UNSYNCHRONIZED":
            add_flag(r, "clock_unsynchronized")

        if sensor.get("_calibration_status") in ("UNCALIBRATED", "CALIBRATION_UNKNOWN"):
            add_flag(r, sensor.get("_calibration_status", "calibration_unknown").lower())

        if r.get("absolute_spl_claimed") is True:
            if sensor.get("_calibration_status") != "CALIBRATED" or not r.get("gain") or not r.get("reference_pressure"):
                add_flag(r, "absolute_spl_unsupported")
                warnings.append(f"recording {rid}: absolute SPL claimed without sufficient calibration/gain/reference metadata")

        recordings[rid] = r

    if not recordings:
        issues.append("No recordings supplied")

    return recordings, issues, warnings


def validate_events(
    case: Dict[str, Any],
    sensors: Dict[str, Dict[str, Any]],
    recordings: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    events: List[Dict[str, Any]] = []

    for idx, ev in enumerate(case.get("acoustic_events") or []):
        if not isinstance(ev, dict):
            issues.append(f"acoustic_events[{idx}] is not an object")
            continue

        eid = ev.get("event_id") or f"EVT-{idx + 1}"
        ev["event_id"] = eid

        rid = ev.get("recording_id")
        if rid and rid not in recordings:
            issues.append(f"event {eid} references unknown recording_id={rid}")

        rec = recordings.get(rid, {}) if rid else {}
        sensor_ids = [x for x in ensure_list(ev.get("sensor_ids")) if x]
        if not sensor_ids and rec.get("sensor_id"):
            sensor_ids = [rec["sensor_id"]]
        ev["_sensor_ids"] = sensor_ids

        for sid in sensor_ids:
            if sid not in sensors:
                issues.append(f"event {eid} references unknown sensor_id={sid}")

        start = parse_dt(ev.get("start_time"))
        end = parse_dt(ev.get("end_time"))
        if start is None and rec.get("_start") is not None:
            # Recording start is not event onset. Preserve as recording window only.
            ev["_recording_start"] = rec.get("_start")
            add_flag(ev, "missing_event_time")
        else:
            ev["_recording_start"] = rec.get("_start")

        if start and end and end < start:
            issues.append(f"event {eid} has end_time before start_time")

        ev["_start"] = start
        ev["_end"] = end

        duration = to_float(ev.get("duration_s") or ev.get("duration"))
        if duration is None and start and end:
            duration = (end - start).total_seconds()
        ev["_duration_s"] = duration
        if duration is not None and duration < 0:
            add_flag(ev, "negative_duration")

        event_types = [str(x).strip().upper() for x in ensure_list(ev.get("event_type_candidate") or ev.get("event_types")) if x]
        unknown_types = [t for t in event_types if t not in EVENT_TYPES]
        if unknown_types:
            warnings.append(f"event {eid} has unknown event_type_candidate(s): {unknown_types}")
        ev["_event_types"] = event_types or ["UNKNOWN"]

        source_categories = [str(x).strip().lower() for x in ensure_list(ev.get("source_category") or ev.get("source_categories")) if x]
        derived_categories = [TYPE_TO_CATEGORY.get(t, "unknown") for t in ev["_event_types"]]
        ev["_source_categories"] = sorted(set(source_categories + derived_categories)) or ["unknown"]

        freq_range = ev.get("frequency_range_hz")
        if isinstance(freq_range, list) and len(freq_range) >= 2:
            ev["_freq_min_hz"] = to_float(freq_range[0])
            ev["_freq_max_hz"] = to_float(freq_range[1])
        else:
            ev["_freq_min_hz"] = to_float(ev.get("frequency_min_hz"))
            ev["_freq_max_hz"] = to_float(ev.get("frequency_max_hz"))

        dominant = [to_float(x) for x in ensure_list(ev.get("dominant_frequencies_hz") or ev.get("dominant_frequency_hz"))]
        ev["_dominant_frequencies_hz"] = [x for x in dominant if x is not None]

        # Nyquist check using available sample rates.
        sample_rates = []
        if rec.get("_nyquist_hz") is not None:
            sample_rates.append(rec["_nyquist_hz"])
        for sid in sensor_ids:
            s = sensors.get(sid, {})
            sr = to_float(s.get("sample_rate_hz"))
            if sr:
                sample_rates.append(sr / 2.0)

        nyq = min(sample_rates) if sample_rates else None
        ev["_nyquist_hz"] = nyq
        if nyq is not None:
            for f in [ev.get("_freq_max_hz")] + ev.get("_dominant_frequencies_hz", []):
                if f is not None and f > nyq * 1.001:
                    add_flag(ev, "above_nyquist")
                    warnings.append(f"event {eid}: frequency {f} Hz exceeds supplied Nyquist limit {nyq} Hz")
                    break

        spectral_features = ev.get("spectral_features")
        if not isinstance(spectral_features, dict):
            spectral_features = extract_spectral_features_from_bands(ev.get("band_energy"))
        ev["_spectral_features"] = spectral_features or {}

        ev["_snr_db"] = to_float(ev.get("snr_db") or rec.get("_snr_db"))
        ev["_impulsiveness"] = to_float(ev.get("impulsiveness"))
        ev["_rise_time_ms"] = to_float(ev.get("rise_time_ms"))
        ev["_periodicity_interval_s"] = to_float(
            ev.get("periodicity_interval_s")
            or (ev.get("periodicity") or {}).get("interval_s")
        )

        ev["_classification_confidence"] = to_float(ev.get("classification_confidence"))
        ev["_classifier_model"] = ev.get("classifier_model")
        ev["_classifier_version"] = ev.get("classifier_version")
        ev["_ood_candidate"] = bool(ev.get("ood_candidate") or ev.get("out_of_distribution"))

        if ev["_ood_candidate"]:
            add_flag(ev, "model_ood")

        # Copy recording quality flags into event, but do not erase event-specific flags.
        for flag in rec.get("_quality_flags", []):
            add_flag(ev, flag)

        if any(t in PERSON_RELATED_EVENT_TYPES for t in ev["_event_types"]):
            add_flag(ev, "speech_or_human_activity_present")

        ev["_feature_vector"] = build_event_vector(ev)
        ev["_source_ids"] = [x for x in ensure_list(ev.get("source_id") or ev.get("source_ids")) if x]
        ev["_evidence_ids"] = [x for x in ensure_list(ev.get("evidence_id") or ev.get("evidence_ids")) if x]

        events.append(ev)

    if not events:
        issues.append("No acoustic events supplied")

    return events, issues, warnings


def validate_doa(
    case: Dict[str, Any],
    sensors: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[str] = []
    observations: List[Dict[str, Any]] = []

    for idx, d in enumerate(case.get("doa_observations") or []):
        if not isinstance(d, dict):
            issues.append(f"doa_observations[{idx}] is not an object")
            continue

        oid = d.get("observation_id") or f"DOA-{idx + 1}"
        d["observation_id"] = oid

        sid = d.get("sensor_id") or d.get("array_id")
        d["_sensor_id"] = sid
        sensor = sensors.get(sid, {})

        bearing = normalize_deg(d.get("bearing_deg") or d.get("azimuth_deg"))
        unc = to_float(d.get("bearing_uncertainty_deg") or d.get("uncertainty_deg"))
        ts = parse_dt(d.get("timestamp"))

        d["_bearing_deg"] = bearing
        d["_uncertainty_deg"] = unc
        d["_timestamp"] = ts
        d["_event_id"] = d.get("event_id")
        d["_lat"] = sensor.get("_lat")
        d["_lon"] = sensor.get("_lon")
        d["_position_accuracy_m"] = sensor.get("_position_accuracy_m")

        if bearing is None:
            issues.append(f"DOA {oid} missing valid bearing_deg")
            continue
        if d["_lat"] is None or d["_lon"] is None:
            add_flag(d, "sensor_position_missing")
        if unc is None:
            add_flag(d, "doa_uncertainty_missing")
        if sensor.get("_clock_sync_state") == "UNSYNCHRONIZED":
            add_flag(d, "clock_unsynchronized")

        observations.append(d)

    return observations, issues


def validate_tdoa(
    case: Dict[str, Any],
    sensors: Dict[str, Dict[str, Any]],
    environment: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[str] = []
    observations: List[Dict[str, Any]] = []
    c = sound_speed_m_s(environment)

    for idx, t in enumerate(case.get("tdoa_observations") or []):
        if not isinstance(t, dict):
            issues.append(f"tdoa_observations[{idx}] is not an object")
            continue

        oid = t.get("observation_id") or f"TDOA-{idx + 1}"
        t["observation_id"] = oid

        pair = t.get("sensor_pair") or t.get("sensor_ids")
        if isinstance(pair, list) and len(pair) >= 2:
            s1, s2 = pair[0], pair[1]
        else:
            s1 = t.get("sensor_id_1")
            s2 = t.get("sensor_id_2")

        t["_sensor_pair"] = [s1, s2]
        t["_event_id"] = t.get("event_id")
        t["_timestamp"] = parse_dt(t.get("timestamp"))
        t["_time_difference_s"] = to_float(t.get("time_difference_s") or t.get("tdoa_s"))
        t["_uncertainty_s"] = to_float(t.get("uncertainty_s") or t.get("time_uncertainty_s"))
        t["_sound_speed_m_s"] = to_float(t.get("sound_speed_m_s")) or c

        for sid in [s1, s2]:
            sensor = sensors.get(sid, {})
            if sensor.get("_lat") is None or sensor.get("_lon") is None:
                add_flag(t, "sensor_position_missing")
            if sensor.get("_clock_sync_state") == "UNSYNCHRONIZED":
                add_flag(t, "clock_unsynchronized")

        if t["_time_difference_s"] is None:
            issues.append(f"TDOA {oid} missing time_difference_s")
            continue
        if t["_uncertainty_s"] is None:
            add_flag(t, "tdoa_uncertainty_missing")
        if t["_sound_speed_m_s"] is None:
            add_flag(t, "tdoa_sound_speed_missing")

        observations.append(t)

    return observations, issues


def validate_supplied_location_candidates(
    case: Dict[str, Any],
) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []

    for idx, c in enumerate(case.get("localization_candidates") or []):
        if not isinstance(c, dict):
            continue
        cid = c.get("candidate_id") or f"LOC-{idx + 1}"
        c["candidate_id"] = cid
        c["_lat"] = to_float(c.get("latitude") or c.get("lat"))
        c["_lon"] = to_float(c.get("longitude") or c.get("lon"))
        c["_uncertainty_radius_m"] = to_float(c.get("uncertainty_radius_m") or c.get("radius_m"))
        c["_event_id"] = c.get("event_id")
        c["_cluster_id"] = c.get("cluster_id")
        c["_timestamp"] = parse_dt(c.get("timestamp"))
        c["_method"] = str(c.get("method", "SUPPLIED_DETERMINISTIC_SOLVER")).upper()
        c["_confidence"] = str(c.get("confidence", "UNKNOWN")).upper()
        c["_precision"] = str(c.get("precision", "UNKNOWN")).upper()
        candidates.append(c)

    return candidates


# -----------------------------------------------------------------------------
# Independence / duplication
# -----------------------------------------------------------------------------

def sensor_independence(a: Dict[str, Any], b: Dict[str, Any]) -> str:
    if not a or not b:
        return "UNKNOWN"
    if a.get("sensor_id") == b.get("sensor_id"):
        return "DEPENDENT"

    shared_keys = [
        "upstream_recording_id",
        "processor_id",
        "array_id",
        "independence_group",
        "calibration_reference",
    ]

    for k in shared_keys:
        av = a.get(k)
        bv = b.get(k)
        if av is not None and bv is not None and av == bv:
            return "DEPENDENT"

    if a.get("clock_source") is not None and a.get("clock_source") == b.get("clock_source"):
        # Same clock can still be independent sensors, but evidence pedigree is weaker.
        return "PARTIALLY_DEPENDENT"

    if a.get("_lat") is None or b.get("_lat") is None:
        return "UNKNOWN"

    if a.get("sensor_type") == b.get("sensor_type") and a.get("platform") == b.get("platform"):
        return "PARTIALLY_DEPENDENT"

    return "INDEPENDENT"


def recording_independence(ra: Dict[str, Any], rb: Dict[str, Any]) -> str:
    if not ra or not rb:
        return "UNKNOWN"
    if ra.get("recording_id") == rb.get("recording_id"):
        return "DEPENDENT"
    ha = ra.get("content_hash")
    hb = rb.get("content_hash")
    if ha and hb and ha == hb:
        return "DEPENDENT"
    sa = ra.get("segment_hash")
    sb = rb.get("segment_hash")
    if sa and sb and sa == sb:
        return "PARTIALLY_DEPENDENT"
    if ra.get("upstream_recording_id") and ra.get("upstream_recording_id") == rb.get("upstream_recording_id"):
        return "DEPENDENT"
    return "UNKNOWN"


def summarize_independence(
    sensor_ids: List[str],
    recording_ids: List[str],
    sensors: Dict[str, Dict[str, Any]],
    recordings: Dict[str, Dict[str, Any]],
) -> str:
    ids = [s for s in sensor_ids if s]
    if len(ids) < 2:
        return "SINGLE_SENSOR"

    states: List[str] = []

    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            states.append(sensor_independence(sensors.get(ids[i], {}), sensors.get(ids[j], {})))

    rids = [r for r in recording_ids if r]
    for i in range(len(rids)):
        for j in range(i + 1, len(rids)):
            states.append(recording_independence(recordings.get(rids[i], {}), recordings.get(rids[j], {})))

    if all(s == "INDEPENDENT" for s in states):
        return "INDEPENDENT"
    if any(s == "DEPENDENT" for s in states):
        return "DEPENDENT_OR_UNKNOWN"
    if any(s == "PARTIALLY_DEPENDENT" for s in states):
        return "PARTIALLY_DEPENDENT"
    return "UNKNOWN"


def detect_duplicate_recordings(recordings: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_hash: Dict[str, List[str]] = defaultdict(list)
    duplicates: List[Dict[str, Any]] = []

    for rid, r in recordings.items():
        h = r.get("content_hash")
        if h:
            by_hash[h].append(rid)

    for h, rids in by_hash.items():
        if len(rids) > 1:
            duplicates.append(
                {
                    "content_hash": h,
                    "recording_ids": sorted(rids),
                    "independence_state": "DEPENDENT",
                    "note": "Multiple recording IDs share the same content hash. These are copies, not independent acoustic evidence.",
                }
            )

    return duplicates


# -----------------------------------------------------------------------------
# Event correlation
# -----------------------------------------------------------------------------

def time_overlap_or_close(a: Dict[str, Any], b: Dict[str, Any], window_s: float) -> bool:
    a_start = a.get("_start")
    a_end = a.get("_end") or a_start
    b_start = b.get("_start")
    b_end = b.get("_end") or b_start

    if not a_start or not b_start:
        return False

    # If intervals exist, check overlap or proximity.
    if a_end and b_end:
        if a_start <= b_end and b_start <= a_end:
            return True

    delta = abs((a_start - b_start).total_seconds())
    return delta <= window_s


def event_types_compatible(a: List[str], b: List[str]) -> bool:
    sa = set(a)
    sb = set(b)
    if "UNKNOWN" in sa or "UNKNOWN" in sb:
        return True
    return bool(sa & sb)


def source_categories_compatible(a: List[str], b: List[str]) -> bool:
    sa = set(a)
    sb = set(b)
    if "unknown" in sa or "unknown" in sb:
        return True
    return bool(sa & sb)


def correlate_events(
    events: List[Dict[str, Any]],
    supplied_correlations: List[Dict[str, Any]],
    sensors: Dict[str, Dict[str, Any]],
    recordings: Dict[str, Dict[str, Any]],
    settings: Dict[str, float],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    clusters: List[Dict[str, Any]] = []
    contradictions: List[Dict[str, Any]] = []
    event_by_id = {e.get("event_id"): e for e in events}
    used_event_ids: set = set()

    # 1) Use supplied multi-sensor correlations first.
    for idx, corr in enumerate(supplied_correlations or [], 1):
        if not isinstance(corr, dict):
            continue
        eids = [x for x in ensure_list(corr.get("event_ids")) if x in event_by_id]
        if len(eids) < 2:
            continue

        evs = [event_by_id[eid] for eid in eids]
        for e in evs:
            used_event_ids.add(e.get("event_id"))

        sensor_ids = sorted({sid for e in evs for sid in (e.get("_sensor_ids") or []) if sid})
        recording_ids = sorted({e.get("recording_id") for e in evs if e.get("recording_id")})
        independence = summarize_independence(sensor_ids, recording_ids, sensors, recordings)

        vectors = [e.get("_feature_vector") for e in evs if e.get("_feature_vector")]
        avg_vec = average_vectors(vectors)
        sims = [cosine_similarity(vectors[0], v) for v in vectors[1:]] if len(vectors) >= 2 else []
        avg_sim = statistics.fmean([s for s in sims if s is not None]) if sims else None

        starts = [e.get("_start") for e in evs if e.get("_start")]
        ends = [e.get("_end") for e in evs if e.get("_end")]

        quality_flags = sorted({flag for e in evs for flag in (e.get("_quality_flags") or [])})
        classification_confidences = [e.get("_classification_confidence") for e in evs if e.get("_classification_confidence") is not None]

        cluster = {
            "cluster_id": corr.get("cluster_id") or f"CL-{idx}",
            "event_ids": eids,
            "sensor_ids": sensor_ids,
            "recording_ids": recording_ids,
            "start_time": iso_or_none(min(starts)) if starts else None,
            "end_time": iso_or_none(max(ends)) if ends else None,
            "_start": min(starts) if starts else None,
            "_end": max(ends) if ends else None,
            "event_types": sorted({t for e in evs for t in (e.get("_event_types") or [])}),
            "source_categories": sorted({c for e in evs for c in (e.get("_source_categories") or [])}),
            "source_independence": independence,
            "spectral_similarity": avg_sim,
            "feature_vector": avg_vec,
            "quality_flags": quality_flags,
            "classification_confidence": statistics.median(classification_confidences) if classification_confidences else None,
            "correlation_source": "SUPPLIED_MULTI_SENSOR_CORRELATION",
            "confidence": str(corr.get("confidence", "MODERATE")).upper(),
            "limitations": [
                "Supplied correlation is accepted as a candidate, not proven identity.",
                "Source independence depends on supplied sensor/recording pedigree.",
            ],
        }

        # Contradiction: supplied correlation but very low spectral similarity.
        if avg_sim is not None and avg_sim < settings["spectral_similarity_threshold"]:
            contradictions.append(
                {
                    "type": "supplied_correlation_low_spectral_similarity",
                    "cluster_id": cluster["cluster_id"],
                    "spectral_similarity": avg_sim,
                    "threshold": settings["spectral_similarity_threshold"],
                    "note": "Preserve contradiction. Do not merge events solely because a supplied correlation says so.",
                }
            )

        clusters.append(cluster)

    # 2) Heuristic correlation for remaining events.
    remaining = [e for e in events if e.get("event_id") not in used_event_ids]
    remaining.sort(key=lambda x: x.get("_start") or datetime.min.replace(tzinfo=timezone.utc))

    next_id = len(clusters) + 1
    for ev in remaining:
        placed = False
        for cl in clusters:
            if cl.get("correlation_source") != "HEURISTIC":
                continue

            evs = [event_by_id[eid] for eid in cl.get("event_ids", []) if eid in event_by_id]
            if not evs:
                continue

            if not any(time_overlap_or_close(ev, x, settings["correlation_time_window_s"]) for x in evs):
                continue

            if not all(event_types_compatible(ev.get("_event_types", []), x.get("_event_types", [])) for x in evs):
                continue
            if not all(source_categories_compatible(ev.get("_source_categories", []), x.get("_source_categories", [])) for x in evs):
                continue

            vec = ev.get("_feature_vector")
            cl_vec = cl.get("feature_vector")
            sim = cosine_similarity(vec, cl_vec) if vec and cl_vec else None
            if sim is None or sim < settings["spectral_similarity_threshold"]:
                continue

            new_sensor_ids = set(ev.get("_sensor_ids") or [])
            old_sensor_ids = set(cl.get("sensor_ids") or [])
            if not (new_sensor_ids - old_sensor_ids):
                # Same sensor only; not independent multi-sensor correlation.
                continue

            cl["event_ids"].append(ev.get("event_id"))
            cl["sensor_ids"] = sorted(old_sensor_ids | new_sensor_ids)
            cl["recording_ids"] = sorted(set(cl.get("recording_ids", [])) | {ev.get("recording_id")} - {None})
            cl["event_types"] = sorted(set(cl.get("event_types", [])) | set(ev.get("_event_types", [])))
            cl["source_categories"] = sorted(set(cl.get("source_categories", [])) | set(ev.get("_source_categories", [])))
            cl["quality_flags"] = sorted(set(cl.get("quality_flags", [])) | set(ev.get("_quality_flags", [])))

            starts = [x.get("_start") for x in [event_by_id[eid] for eid in cl["event_ids"]] if x and x.get("_start")]
            ends = [x.get("_end") for x in [event_by_id[eid] for eid in cl["event_ids"]] if x and x.get("_end")]
            cl["_start"] = min(starts) if starts else cl.get("_start")
            cl["_end"] = max(ends) if ends else cl.get("_end")
            cl["start_time"] = iso_or_none(cl["_start"])
            cl["end_time"] = iso_or_none(cl["_end"])

            vectors = [event_by_id[eid].get("_feature_vector") for eid in cl["event_ids"] if event_by_id.get(eid) and event_by_id[eid].get("_feature_vector")]
            cl["feature_vector"] = average_vectors(vectors)
            sims = []
            if len(vectors) >= 2:
                for i in range(len(vectors) - 1):
                    s = cosine_similarity(vectors[i], vectors[i + 1])
                    if s is not None:
                        sims.append(s)
            cl["spectral_similarity"] = statistics.fmean(sims) if sims else None
            cl["source_independence"] = summarize_independence(cl["sensor_ids"], cl["recording_ids"], sensors, recordings)

            confs = [event_by_id[eid].get("_classification_confidence") for eid in cl["event_ids"] if event_by_id.get(eid) and event_by_id[eid].get("_classification_confidence") is not None]
            cl["classification_confidence"] = statistics.median(confs) if confs else None

            placed = True
            break

        if not placed:
            sensor_ids = sorted({sid for sid in (ev.get("_sensor_ids") or []) if sid})
            recording_ids = [ev.get("recording_id")] if ev.get("recording_id") else []
            cluster = {
                "cluster_id": f"CL-{next_id}",
                "event_ids": [ev.get("event_id")],
                "sensor_ids": sensor_ids,
                "recording_ids": recording_ids,
                "start_time": iso_or_none(ev.get("_start")),
                "end_time": iso_or_none(ev.get("_end")),
                "_start": ev.get("_start"),
                "_end": ev.get("_end"),
                "event_types": sorted(set(ev.get("_event_types") or [])),
                "source_categories": sorted(set(ev.get("_source_categories") or [])),
                "source_independence": "SINGLE_SENSOR",
                "spectral_similarity": None,
                "feature_vector": ev.get("_feature_vector"),
                "quality_flags": sorted(set(ev.get("_quality_flags") or [])),
                "classification_confidence": ev.get("_classification_confidence"),
                "correlation_source": "SINGLE_EVENT",
                "confidence": "LOW",
                "limitations": ["Single-event cluster; no multi-sensor correlation established."],
            }
            clusters.append(cluster)
            next_id += 1

    return clusters, contradictions


# -----------------------------------------------------------------------------
# Classification / signatures
# -----------------------------------------------------------------------------

def classification_state(cluster: Dict[str, Any]) -> str:
    types = set(cluster.get("event_types") or [])
    conf = cluster.get("classification_confidence")
    flags = set(cluster.get("quality_flags") or [])
    independence = cluster.get("source_independence")

    severe = bool(flags & SEVERE_QUALITY_FLAGS)
    sensitive = bool(types & SENSITIVE_EVENT_TYPES)

    if not types or types == {"UNKNOWN"}:
        return "UNRESOLVED"

    if severe or independence in ("DEPENDENT_OR_UNKNOWN", "UNKNOWN"):
        return "POSSIBLE_CATEGORY"

    if sensitive:
        # Sensitive categories are capped conservatively.
        if independence == "INDEPENDENT" and conf is not None and conf >= 0.9:
            return "PROBABLE_CATEGORY"
        return "POSSIBLE_CATEGORY"

    if independence == "INDEPENDENT" and conf is not None and conf >= 0.8:
        return "SUPPORTED_CATEGORY"
    if conf is not None and conf >= 0.5:
        return "PROBABLE_CATEGORY"
    return "POSSIBLE_CATEGORY"


def build_signature_matches(
    clusters: List[Dict[str, Any]],
    reference_signatures: List[Dict[str, Any]],
    threshold: float,
) -> List[Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []

    refs_with_vecs: List[Tuple[Dict[str, Any], List[float]]] = []
    for r in reference_signatures or []:
        if not isinstance(r, dict):
            continue
        rv = build_reference_vector(r)
        if rv:
            refs_with_vecs.append((r, rv))

    for cl in clusters:
        cv = cl.get("feature_vector")
        if not cv:
            continue

        for ref, rv in refs_with_vecs:
            sim = cosine_similarity(cv, rv)
            if sim is None:
                continue

            if sim >= max(0.95, threshold + 0.1):
                state = "STRONG_SIMILARITY"
            elif sim >= threshold:
                state = "MODERATE_SIMILARITY"
            elif sim >= threshold * 0.75:
                state = "WEAK_SIMILARITY"
            else:
                state = "NO_MATERIAL_SIMILARITY"

            matches.append(
                {
                    "match_id": f"SIGMATCH-{len(matches) + 1}",
                    "cluster_id": cl.get("cluster_id"),
                    "reference_signature_id": ref.get("reference_signature_id") or ref.get("signature_id"),
                    "reference_class": ref.get("class_label") or ref.get("source_category"),
                    "similarity": sim,
                    "metric": "cosine_similarity",
                    "match_state": state,
                    "threshold": threshold,
                    "limitations": [
                        "Signature similarity is not source identity.",
                        "Reference library may be incomplete or condition-dependent.",
                        "Domain shift in microphone, distance, environment, load, or compression affects similarity.",
                    ],
                }
            )

    return matches


# -----------------------------------------------------------------------------
# Localization
# -----------------------------------------------------------------------------

def estimate_localization_from_doa(
    cluster: Dict[str, Any],
    doa_observations: List[Dict[str, Any]],
    sensors: Dict[str, Dict[str, Any]],
    environment: Dict[str, Any],
    settings: Dict[str, float],
) -> Dict[str, Any]:
    result = {
        "cluster_id": cluster.get("cluster_id"),
        "method": "DOA_BEARING_INTERSECTION",
        "location_candidate": None,
        "precision": "UNKNOWN",
        "confidence": "UNKNOWN",
        "uncertainty_radius_m": None,
        "sensor_ids": [],
        "limitations": [],
    }

    cids = set(cluster.get("event_ids") or [])
    relevant = []
    for d in doa_observations:
        if d.get("_event_id") in cids:
            relevant.append(d)
        elif d.get("_timestamp") and cluster.get("_start") and cluster.get("_end"):
            ts = d["_timestamp"]
            if cluster["_start"] <= ts <= cluster["_end"] and d.get("_sensor_id") in set(cluster.get("sensor_ids") or []):
                relevant.append(d)

    if not relevant:
        result["limitations"].append("No DOA observations associated with this event cluster.")
        return result

    valid = [d for d in relevant if d.get("_bearing_deg") is not None and d.get("_lat") is not None and d.get("_lon") is not None]
    if not valid:
        result["precision"] = "UNKNOWN"
        result["limitations"].append("DOA observations lack bearing or sensor position.")
        return result

    if len(valid) == 1:
        result["precision"] = "DIRECTION_ONLY"
        result["confidence"] = "LOW"
        result["location_candidate"] = {
            "bearing_deg": valid[0].get("_bearing_deg"),
            "bearing_uncertainty_deg": valid[0].get("_uncertainty_deg"),
            "sensor_id": valid[0].get("_sensor_id"),
        }
        result["limitations"].append("Single bearing defines direction, not exact location.")
        return result

    ref_lat = valid[0]["_lat"]
    ref_lon = valid[0]["_lon"]
    candidates = []

    for i in range(len(valid)):
        for j in range(i + 1, len(valid)):
            o1, o2 = valid[i], valid[j]
            s1 = sensors.get(o1.get("_sensor_id"), {})
            s2 = sensors.get(o2.get("_sensor_id"), {})

            if o1.get("_uncertainty_deg") is None or o2.get("_uncertainty_deg") is None:
                continue

            p1 = local_enu(o1["_lat"], o1["_lon"], ref_lat, ref_lon)
            p2 = local_enu(o2["_lat"], o2["_lon"], ref_lat, ref_lon)
            d1 = bearing_vector_deg(o1["_bearing_deg"])
            d2 = bearing_vector_deg(o2["_bearing_deg"])

            inter = line_intersection(p1, d1, p2, d2)
            if not inter:
                continue
            point, t, u = inter
            if t <= 0 or u <= 0:
                # Intersection behind one or both sensors; not a valid forward DOA solution.
                continue

            lat, lon = enu_to_latlon(point[0], point[1], ref_lat, ref_lon)

            dist1 = math.hypot(point[0] - p1[0], point[1] - p1[1])
            dist2 = math.hypot(point[0] - p2[0], point[1] - p2[1])

            dot = max(-1.0, min(1.0, d1[0] * d2[0] + d1[1] * d2[1]))
            gamma = math.acos(dot)

            # Poor geometry produces large uncertainty.
            if gamma < 0.17 or gamma > math.pi - 0.17:
                geometry_penalty = 10.0
            else:
                geometry_penalty = 1.0 / max(0.05, math.sin(gamma))

            u1 = math.radians(max(1.0, float(o1["_uncertainty_deg"])))
            u2 = math.radians(max(1.0, float(o2["_uncertainty_deg"])))

            radius = math.sqrt((dist1 * math.tan(u1)) ** 2 + (dist2 * math.tan(u2)) ** 2) * geometry_penalty

            pos_acc1 = to_float(s1.get("_position_accuracy_m")) or 0.0
            pos_acc2 = to_float(s2.get("_position_accuracy_m")) or 0.0
            radius += pos_acc1 + pos_acc2

            # Environmental multipath/occlusion increases uncertainty.
            multipath = str(environment.get("multipath_risk", "UNKNOWN")).upper()
            occlusion = str(environment.get("occlusion_risk", "UNKNOWN")).upper()
            if multipath in ("HIGH", "MEDIUM"):
                radius *= 1.5 if multipath == "MEDIUM" else 2.5
            if occlusion in ("HIGH", "MEDIUM"):
                radius *= 1.3 if occlusion == "MEDIUM" else 1.8

            radius = min(radius, settings.get("localization_max_radius_m", 100000.0))

            sync_ok = all(
                sensors.get(sid, {}).get("_clock_sync_state") in ("SYNCHRONIZED", "OFFSET_CORRECTED", "APPROXIMATELY_ALIGNED")
                for sid in [o1.get("_sensor_id"), o2.get("_sensor_id")]
            )
            indep = sensor_independence(s1, s2)

            if indep == "INDEPENDENT" and sync_ok and radius <= 500:
                conf = "MODERATE"
            elif indep in ("INDEPENDENT", "PARTIALLY_DEPENDENT") and sync_ok and radius <= 2000:
                conf = "LOW"
            else:
                conf = "LOW"

            candidates.append(
                {
                    "latitude": lat,
                    "longitude": lon,
                    "uncertainty_radius_m": radius,
                    "sensor_ids": [o1.get("_sensor_id"), o2.get("_sensor_id")],
                    "confidence": conf,
                    "pair_geometry_angle_deg": math.degrees(gamma),
                }
            )

    if not candidates:
        result["precision"] = "DIRECTION_ONLY"
        result["confidence"] = "LOW"
        result["limitations"].append("DOA pairs did not produce a stable forward intersection.")
        return result

    lats = [c["latitude"] for c in candidates]
    lons = [c["longitude"] for c in candidates]
    radii = [c["uncertainty_radius_m"] for c in candidates]

    med_lat = statistics.median(lats)
    med_lon = statistics.median(lons)
    med_radius = statistics.median(radii)
    max_radius = max(radii)

    # Preserve spread as additional uncertainty.
    spread = max(haversine_m(med_lat, med_lon, la, lo) or 0.0 for la, lo in zip(lats, lons))
    final_radius = max(med_radius, spread * 1.5, max_radius * 0.5)

    if final_radius <= 100:
        precision = "SITE_CANDIDATE"
    elif final_radius <= 500:
        precision = "AREA"
    elif final_radius <= 5000:
        precision = "REGION"
    else:
        precision = "BROAD_AREA"

    confidences = [c.get("confidence") for c in candidates]
    if "MODERATE" in confidences and max_radius <= 1000:
        confidence = "MODERATE"
    else:
        confidence = "LOW"

    # Code-derived localization is capped conservatively.
    if precision == "SITE_CANDIDATE":
        precision = "SITE_CANDIDATE"
    elif precision in ("AREA", "REGION", "BROAD_AREA"):
        pass

    result.update(
        {
            "location_candidate": {
                "latitude": med_lat,
                "longitude": med_lon,
                "uncertainty_radius_m": final_radius,
                "candidate_count": len(candidates),
            },
            "precision": precision,
            "confidence": confidence,
            "sensor_ids": sorted({sid for c in candidates for sid in c.get("sensor_ids", []) if sid}),
            "limitations": [
                "DOA intersection is a candidate event region, not exact source location.",
                "Multipath, occlusion, sensor position error, and clock uncertainty affect result.",
                "Event location is not person location.",
            ],
        }
    )

    return result


def evaluate_tdoa_against_candidate(
    candidate: Optional[Dict[str, Any]],
    tdoa_observations: List[Dict[str, Any]],
    cluster: Dict[str, Any],
    sensors: Dict[str, Dict[str, Any]],
    environment: Dict[str, Any],
    settings: Dict[str, float],
) -> Dict[str, Any]:
    result = {
        "cluster_id": cluster.get("cluster_id"),
        "tdoa_observation_count": len(tdoa_observations),
        "sound_speed_m_s": sound_speed_m_s(environment),
        "residuals": [],
        "consistency_state": "NOT_EVALUATED",
        "limitations": [],
    }

    if not tdoa_observations:
        result["limitations"].append("No TDOA observations supplied.")
        return result

    c = result["sound_speed_m_s"]
    if c is None:
        result["consistency_state"] = "UNSOUND_SPEED_MISSING"
        result["limitations"].append("TDOA evaluation requires sound speed from environment or observation.")
        return result

    if not candidate or candidate.get("latitude") is None or candidate.get("longitude") is None:
        result["consistency_state"] = "NO_CANDIDATE"
        result["limitations"].append("This scaffold does not solve TDOA location directly; it validates supplied/DOA-derived candidates only.")
        return result

    lat0 = candidate["latitude"]
    lon0 = candidate["longitude"]

    for t in tdoa_observations:
        pair = t.get("_sensor_pair") or []
        if len(pair) < 2:
            continue
        s1 = sensors.get(pair[0], {})
        s2 = sensors.get(pair[1], {})
        if s1.get("_lat") is None or s2.get("_lat") is None:
            continue

        d1 = haversine_m(lat0, lon0, s1["_lat"], s1["_lon"]) or 0.0
        d2 = haversine_m(lat0, lon0, s2["_lat"], s2["_lon"]) or 0.0
        predicted_abs = abs(d1 - d2) / c
        observed_abs = abs(t.get("_time_difference_s") or 0.0)
        residual = abs(predicted_abs - observed_abs)

        unc = t.get("_uncertainty_s")
        cand_radius_unc = (candidate.get("uncertainty_radius_m") or 0.0) / c
        combined_unc = math.sqrt((unc or 0.0) ** 2 + cand_radius_unc ** 2) if unc is not None else cand_radius_unc

        tolerance = max(settings.get("tdoa_residual_tolerance_s", 0.05), 3.0 * combined_unc if combined_unc else 0.0)

        result["residuals"].append(
            {
                "observation_id": t.get("observation_id"),
                "sensor_pair": pair,
                "predicted_abs_tdoa_s": predicted_abs,
                "observed_abs_tdoa_s": observed_abs,
                "residual_s": residual,
                "tolerance_s": tolerance,
                "consistent": residual <= tolerance,
            }
        )

    if not result["residuals"]:
        result["consistency_state"] = "NO_VALID_PAIRS"
        return result

    consistent_count = sum(1 for r in result["residuals"] if r["consistent"])
    if consistent_count == len(result["residuals"]):
        result["consistency_state"] = "CONSISTENT"
    elif consistent_count > 0:
        result["consistency_state"] = "PARTIALLY_CONSISTENT"
    else:
        result["consistency_state"] = "INCONSISTENT"
        result["limitations"].append("TDOA residuals conflict with candidate; preserve contradiction and do not force localization.")

    return result


def localize_clusters(
    clusters: List[Dict[str, Any]],
    doa_observations: List[Dict[str, Any]],
    tdoa_observations: List[Dict[str, Any]],
    supplied_candidates: List[Dict[str, Any]],
    sensors: Dict[str, Dict[str, Any]],
    environment: Dict[str, Any],
    settings: Dict[str, float],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    localization_results: List[Dict[str, Any]] = []
    contradictions: List[Dict[str, Any]] = []

    for cl in clusters:
        doa_res = estimate_localization_from_doa(cl, doa_observations, sensors, environment, settings)

        # Prefer supplied deterministic candidate if it matches cluster and has better metadata.
        matched_supplied = None
        for sc in supplied_candidates:
            if sc.get("_cluster_id") == cl.get("cluster_id"):
                matched_supplied = sc
                break
            if sc.get("_event_id") in set(cl.get("event_ids") or []):
                matched_supplied = sc
                break
            if sc.get("_timestamp") and cl.get("_start") and cl.get("_end"):
                if cl["_start"] <= sc["_timestamp"] <= cl["_end"]:
                    matched_supplied = sc
                    break

        final = doa_res
        if matched_supplied:
            final = {
                "cluster_id": cl.get("cluster_id"),
                "method": matched_supplied.get("_method", "SUPPLIED_DETERMINISTIC_SOLVER"),
                "location_candidate": {
                    "latitude": matched_supplied.get("_lat"),
                    "longitude": matched_supplied.get("_lon"),
                    "uncertainty_radius_m": matched_supplied.get("_uncertainty_radius_m"),
                },
                "precision": matched_supplied.get("_precision", "UNKNOWN"),
                "confidence": matched_supplied.get("_confidence", "UNKNOWN"),
                "sensor_ids": matched_supplied.get("sensor_ids") or cl.get("sensor_ids"),
                "limitations": matched_supplied.get("limitations") or [
                    "Supplied candidate is retained with its original method and uncertainty."
                ],
            }

            if doa_res.get("location_candidate") and final.get("location_candidate"):
                d = haversine_m(
                    doa_res["location_candidate"].get("latitude"),
                    doa_res["location_candidate"].get("longitude"),
                    final["location_candidate"].get("latitude"),
                    final["location_candidate"].get("longitude"),
                )
                combined_radius = (doa_res["location_candidate"].get("uncertainty_radius_m") or 0.0) + (final["location_candidate"].get("uncertainty_radius_m") or 0.0)
                if d is not None and combined_radius > 0 and d > 3.0 * combined_radius:
                    contradictions.append(
                        {
                            "type": "localization_conflict",
                            "cluster_id": cl.get("cluster_id"),
                            "doa_distance_m": d,
                            "combined_uncertainty_m": combined_radius,
                            "note": "DOA-derived and supplied localization candidates conflict. Preserve contradiction.",
                        }
                    )

        tdoa_eval = evaluate_tdoa_against_candidate(
            final.get("location_candidate"),
            [t for t in tdoa_observations if t.get("_event_id") in set(cl.get("event_ids") or [])],
            cl,
            sensors,
            environment,
            settings,
        )

        # Privacy restraint: do not infer person location.
        if any(t in PERSON_RELATED_EVENT_TYPES for t in cl.get("event_types", [])):
            final["privacy_restraint"] = "EVENT_REGION_ONLY_NO_PERSON_ASSOCIATION"
            final.setdefault("limitations", []).append(
                "Speech/human-activity context detected. No person identity, continuing location, or biometric inference is attempted."
            )

        final["tdoa_evaluation"] = tdoa_eval
        localization_results.append(final)

    return localization_results, contradictions


# -----------------------------------------------------------------------------
# Contradictions, facts, hypotheses, dual review
# -----------------------------------------------------------------------------

def detect_contradictions(
    clusters: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    localization_results: List[Dict[str, Any]],
    signature_matches: List[Dict[str, Any]],
    duplicate_recordings: List[Dict[str, Any]],
    initial_contradictions: List[Dict[str, Any]],
    settings: Dict[str, float],
) -> List[Dict[str, Any]]:
    contradictions = list(initial_contradictions)
    event_by_id = {e.get("event_id"): e for e in events}

    for cl in clusters:
        evs = [event_by_id[eid] for eid in cl.get("event_ids", []) if eid in event_by_id]

        # Time disagreement within heuristic cluster.
        starts = [e.get("_start") for e in evs if e.get("_start")]
        if len(starts) >= 2:
            span = (max(starts) - min(starts)).total_seconds()
            if span > settings["correlation_time_window_s"] * 5 and cl.get("correlation_source") == "HEURISTIC":
                contradictions.append(
                    {
                        "type": "event_time_disagreement",
                        "cluster_id": cl.get("cluster_id"),
                        "time_span_s": span,
                        "note": "Heuristic cluster has wide time spread; do not treat as one event without stronger evidence.",
                    }
                )

        # Classification conflict.
        type_sets = [set(e.get("_event_types", [])) for e in evs if e.get("_event_types")]
        if len(type_sets) >= 2:
            intersection = set.intersection(*type_sets)
            union = set.union(*type_sets)
            if not intersection and "UNKNOWN" not in union:
                contradictions.append(
                    {
                        "type": "classification_conflict",
                        "cluster_id": cl.get("cluster_id"),
                        "event_types": sorted(union),
                        "note": "Preserve conflict. Do not force one event category.",
                    }
                )

        # Duplicate recordings presented as independent.
        dup_hashes = {d.get("content_hash") for d in duplicate_recordings}
        rec_hashes = {event_by_id[eid].get("recording_id") for eid in cl.get("event_ids", []) if eid in event_by_id}
        rec_hash_values = {recordings_hash.get(rid) for rid in rec_hashes if (recordings_hash := {r.get("recording_id"): r.get("content_hash") for r in []})}  # placeholder avoided

        # Simpler duplicate check: if cluster independence is INDEPENDENT but duplicate recordings exist among its recording_ids.
        if cl.get("source_independence") == "INDEPENDENT":
            for dup in duplicate_recordings:
                if set(dup.get("recording_ids", [])) & set(cl.get("recording_ids", [])):
                    contradictions.append(
                        {
                            "type": "duplicate_recording_dependency",
                            "cluster_id": cl.get("cluster_id"),
                            "content_hash": dup.get("content_hash"),
                            "recording_ids": dup.get("recording_ids"),
                            "note": "Cluster claimed independent but contains duplicate recording copies.",
                        }
                    )

    for loc in localization_results:
        tdoa = loc.get("tdoa_evaluation") or {}
        if tdoa.get("consistency_state") == "INCONSISTENT":
            contradictions.append(
                {
                    "type": "tdoa_localization_inconsistency",
                    "cluster_id": loc.get("cluster_id"),
                    "details": tdoa,
                    "note": "TDOA residuals conflict with localization candidate.",
                }
            )

    for match in signature_matches:
        if match.get("match_state") in {"STRONG_SIMILARITY", "MODERATE_SIMILARITY"}:
            sim = match.get("similarity")
            if sim is not None and sim < match.get("threshold", 0.0):
                contradictions.append(
                    {
                        "type": "signature_match_inconsistency",
                        "match_id": match.get("match_id"),
                        "similarity": sim,
                        "threshold": match.get("threshold"),
                        "note": "Match state inconsistent with similarity threshold.",
                    }
                )

    return contradictions


def measurement_confidence(cluster: Dict[str, Any]) -> str:
    flags = set(cluster.get("quality_flags") or [])
    independence = cluster.get("source_independence")
    severe = bool(flags & SEVERE_QUALITY_FLAGS)

    if severe:
        return "LOW"
    if independence == "INDEPENDENT":
        return "MODERATE"
    if independence == "PARTIALLY_DEPENDENT":
        return "LOW"
    return "UNKNOWN"


def build_facts(
    clusters: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    localization_results: List[Dict[str, Any]],
    signature_matches: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    supported: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    partial: List[Dict[str, Any]] = []
    disputed: List[Dict[str, Any]] = []

    not_facts = [
        "No person identity is inferred.",
        "No speaker identity or voiceprint match is performed.",
        "No passenger, driver, operator, or occupant is inferred.",
        "No weapon, shooter, explosive device, or malicious actor is established.",
        "Gunshot-like is not verified gunshot.",
        "Explosion-like is not verified explosive device.",
        "Event location is not person location.",
        "Louder sound is not automatically closer source.",
        "DOA is not exact location.",
        "Non-detection is not non-occurrence.",
        "Processed audio is not original evidence.",
        "AI-enhanced or generated audio details are not primary evidence.",
        "Embedding/signature similarity is not identity.",
        "Multiple copies of one recording are not independent sources.",
        "Multiple model agreements are not independent acoustic corroboration.",
    ]

    loc_by_cluster = {l.get("cluster_id"): l for l in localization_results}

    for cl in clusters:
        cid = cl.get("cluster_id")
        conf = measurement_confidence(cl)
        types = cl.get("event_types") or []
        cats = cl.get("source_categories") or []
        independence = cl.get("source_independence")

        if types:
            item = {
                "fact_id": f"FCT-{len(supported) + len(candidates) + len(partial) + 1}",
                "statement": f"Event cluster {cid} contains acoustic event type candidates: {', '.join(types)}.",
                "cluster_id": cid,
                "confidence": conf,
                "limitation": "Event type candidate is not exact source identity.",
            }
            if conf == "MODERATE":
                candidates.append(item)
            else:
                partial.append(item)

        if independence == "INDEPENDENT" and not (set(cl.get("quality_flags", [])) & SEVERE_QUALITY_FLAGS):
            supported.append(
                {
                    "fact_id": f"FCT-IND-{len(supported) + 1}",
                    "statement": f"Cluster {cid} is supported by multiple independent authorized acoustic sensors.",
                    "cluster_id": cid,
                    "confidence": "MODERATE",
                    "limitation": "Independence depends on supplied sensor/recording pedigree.",
                }
            )

        loc = loc_by_cluster.get(cid, {})
        cand = loc.get("location_candidate")
        if cand and cand.get("latitude") is not None and cand.get("longitude") is not None:
            candidates.append(
                {
                    "fact_id": f"FCT-LOC-{len(candidates) + 1}",
                    "statement": (
                        f"Cluster {cid} has an event-region candidate near "
                        f"({cand.get('latitude')}, {cand.get('longitude')}) with uncertainty radius "
                        f"{cand.get('uncertainty_radius_m')} m."
                    ),
                    "cluster_id": cid,
                    "confidence": loc.get("confidence", "LOW"),
                    "limitation": "Event-region candidate is not exact source location and not person location.",
                }
            )

        if any(t in PERSON_RELATED_EVENT_TYPES for t in types):
            partial.append(
                {
                    "fact_id": f"FCT-SPEECH-{len(partial) + 1}",
                    "statement": f"Cluster {cid} contains speech/human-activity acoustic context.",
                    "cluster_id": cid,
                    "confidence": "LOW",
                    "limitation": "Speech content and speaker identity are not analyzed. Handoff to AUDINT only under separate authorization.",
                }
            )

    for match in signature_matches:
        if match.get("match_state") in {"STRONG_SIMILARITY", "MODERATE_SIMILARITY"}:
            candidates.append(
                {
                    "fact_id": f"FCT-SIG-{len(candidates) + 1}",
                    "statement": (
                        f"Cluster {match.get('cluster_id')} is similar to reference "
                        f"{match.get('reference_signature_id')} (similarity={match.get('similarity')})."
                    ),
                    "match_id": match.get("match_id"),
                    "confidence": "MODERATE" if match.get("match_state") == "STRONG_SIMILARITY" else "LOW",
                    "limitation": "Signature similarity is not source identity.",
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
    clusters: List[Dict[str, Any]],
    localization_results: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    issues: List[str],
) -> List[Dict[str, Any]]:
    hypotheses: List[Dict[str, Any]] = []
    loc_by_cluster = {l.get("cluster_id"): l for l in localization_results}

    for idx, cl in enumerate(clusters, 1):
        cid = cl.get("cluster_id")
        types = set(cl.get("event_types") or [])
        flags = set(cl.get("quality_flags") or [])
        independence = cl.get("source_independence")
        loc = loc_by_cluster.get(cid, {})

        base = {
            "hypothesis_set_id": f"HSET-{idx}",
            "cluster_id": cid,
            "event_types": sorted(types),
        }

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-REAL_ACOUSTIC_EVENT",
                "statement": "The cluster represents a real acoustic event observed by authorized sensors.",
                "support": [
                    "Acoustic event features supplied." if cl.get("feature_vector") else "No feature vector supplied.",
                    f"Source independence: {independence}.",
                    f"Localization candidate present." if loc.get("location_candidate") else "No localization candidate.",
                ],
                "opposition": [
                    "Severe quality flags present." if flags & SEVERE_QUALITY_FLAGS else "No severe quality flags recorded.",
                    "Contradictions present." if contradictions else "No contradictions recorded.",
                ],
                "unknowns": ["Exact source identity", "operator", "intent", "person presence"],
                "falsification_conditions": [
                    "Independent sensor fails to reproduce event within timing/spectral uncertainty.",
                    "Sensor health/calibration check reveals artifact.",
                    "Duplicate recording pedigree explains apparent multi-sensor agreement.",
                ],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-SENSOR_ARTIFACT",
                "statement": "The observation may be a sensor, processing, clock, or recording artifact.",
                "support": [
                    "Quality flags present." if flags else "No quality flags recorded.",
                    f"Calibration/sync limitations: {sorted(flags & {'uncalibrated', 'calibration_unknown', 'clock_unsynchronized'}) or 'none recorded'}.",
                ],
                "opposition": [
                    "Independent synchronized calibrated sensors agree." if independence == "INDEPENDENT" and not flags & SEVERE_QUALITY_FLAGS else "No strong independent corroboration recorded.",
                ],
                "unknowns": ["Sensor health logs", "calibration certificate", "clock offset", "processing pipeline"],
                "falsification_conditions": [
                    "Sensor self-test/calibration record confirms healthy operation.",
                    "Independent sensor reproduces same spectral/temporal features.",
                ],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-ENVIRONMENTAL_REVERBERATION",
                "statement": "The observation may be environmental noise, reverberation, multipath, or reflection misinterpreted as a distinct source.",
                "support": [
                    "Environment/propagation context missing or risky." if not cl.get("environment_context") else "Environment context supplied.",
                    "Localization uncertainty high." if (loc.get("uncertainty_radius_m") or 0) > 1000 else "Localization uncertainty not high.",
                ],
                "opposition": [
                    "Multi-sensor timing/spectral profile consistent with direct event." if independence == "INDEPENDENT" else "No strong multi-sensor direct-path evidence recorded.",
                ],
                "unknowns": ["Terrain", "structures", "wind", "surface materials", "sensor placement"],
                "falsification_conditions": [
                    "Propagation model and independent sensors show direct arrival.",
                    "Reverberation simulation/control measurements do not reproduce feature set.",
                ],
            }
        )

        if types & {"IMPACT", "EXPLOSION_LIKE", "GUNSHOT_LIKE", "UNKNOWN_IMPULSIVE", "CONSTRUCTION"}:
            for alt, label in [
                ("CONSTRUCTION", "construction activity"),
                ("VEHICLE_BACKFIRE", "vehicle backfire-like event"),
                ("FIREWORK", "firework-like event"),
                ("GUNSHOT_LIKE", "gunshot-like event"),
                ("MECHANICAL_IMPACT", "mechanical impact"),
            ]:
                hypotheses.append(
                    {
                        **base,
                        "hypothesis_id": f"H{idx}-{alt}",
                        "statement": f"The impulsive event may be {label}.",
                        "support": ["Impulsive spectral/temporal features supplied." if cl.get("feature_vector") else "No feature vector supplied."],
                        "opposition": ["Alternative common sources can produce similar impulses."],
                        "unknowns": ["Actor", "weapon", "intent", "exact device"],
                        "falsification_conditions": [
                            "Independent video/incident evidence confirms or excludes source.",
                            "Multi-sensor localization and propagation analysis discriminate source region.",
                            "Reference library and environmental context exclude alternative source class.",
                        ],
                        "restriction": "Gunshot-like is not verified gunshot. Explosion-like is not verified explosive device.",
                    }
                )

        if types & {"MACHINERY", "ROTATING_MACHINE", "PUMP", "FAN", "MOTOR", "COMPRESSOR", "MECHANICAL_FAILURE_LIKE"}:
            hypotheses.append(
                {
                    **base,
                    "hypothesis_id": f"H{idx}-NORMAL_MACHINE_OPERATION",
                    "statement": "The acoustic signature may represent normal machinery operation under current load/speed/environment.",
                    "support": ["Machine context supplied." if cl.get("machine_context") else "No machine context supplied."],
                    "opposition": ["Deviation from baseline would weaken normal-operation hypothesis." if cl.get("baseline_deviation") else "No baseline deviation recorded."],
                    "falsification_conditions": ["Context-matched machine baseline shows measurement within normal variation."],
                }
            )
            hypotheses.append(
                {
                    **base,
                    "hypothesis_id": f"H{idx}-MACHINE_ANOMALY_CANDIDATE",
                    "statement": "The acoustic signature may indicate a mechanical anomaly candidate.",
                    "support": ["Mechanical-failure-like event type present." if "MECHANICAL_FAILURE_LIKE" in types else "No explicit failure-like type present."],
                    "opposition": ["Load, speed, sensor change, or environment may explain change."],
                    "falsification_conditions": ["Maintenance/engineering review and vibration/telemetry correlation exclude anomaly."],
                    "restriction": "Acoustic anomaly is not confirmed failure. Do not prescribe unsafe maintenance actions.",
                }
            )

        if "SPEECH_PRESENT" in types:
            hypotheses.append(
                {
                    **base,
                    "hypothesis_id": f"H{idx}-SPEECH_PRESENT_HANDOFF_AUDINT",
                    "statement": "Speech-like acoustic content is present and should be handled only by authorized AUDINT workflow.",
                    "support": ["Speech-present event type supplied."],
                    "opposition": ["No speaker identity, transcription, or biometric analysis is performed by ACOUSTINT."],
                    "falsification_conditions": ["Authorized AUDINT review determines speech content/status under separate policy."],
                    "restriction": "No voiceprint, no person identification, no sensitive trait inference.",
                }
            )

    if issues:
        hypotheses.append(
            {
                "hypothesis_set_id": "HSET-GLOBAL",
                "hypothesis_id": "H-GLOBAL-VALIDATION-WEAKNESS",
                "statement": "Validation issues materially weaken all acoustic interpretations.",
                "support": issues[:10],
                "opposition": ["No independent clean source supplied yet."],
                "falsification_conditions": ["Resolve validation issues and rerun deterministic ingestion."],
            }
        )

    return hypotheses


def dual_ai_review(
    clusters: List[Dict[str, Any]],
    localization_results: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    issues: List[str],
) -> Dict[str, Any]:
    primary = {
        "role": "Primary Acoustic Analyst",
        "assessment": (
            "Acoustic event clusters and/or feature-level observations exist."
            if clusters
            else "No usable acoustic events were supplied."
        ),
        "classification": "Source-category conclusions remain conservative and evidence-bounded.",
    }

    if not clusters:
        skeptic = {
            "role": "Independent Acoustic Skeptic",
            "verdict": "INSUFFICIENT_EVIDENCE",
            "reason": "No deterministic acoustic events were supplied. Do not infer events from narrative.",
        }
    elif issues:
        skeptic = {
            "role": "Independent Acoustic Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Validation issues require downgraded confidence.",
        }
    elif contradictions:
        skeptic = {
            "role": "Independent Acoustic Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Contradictions must be preserved; do not silently resolve sensor/classification/localization conflicts.",
        }
    elif clusters and any(c.get("source_independence") == "INDEPENDENT" for c in clusters):
        skeptic = {
            "role": "Independent Acoustic Skeptic",
            "verdict": "AGREE_ON_EVENT_PRESENCE_ONLY",
            "reason": "Independent multi-sensor support may justify event-presence assessment only, not source identity, person attribution, or weapon use.",
        }
    else:
        skeptic = {
            "role": "Independent Acoustic Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Single-source or incomplete evidence supports candidate events only.",
        }

    return {
        "primary": primary,
        "skeptic": skeptic,
        "comparison": skeptic.get("verdict", "INSUFFICIENT_EVIDENCE"),
        "note": "Rule-based dual-review scaffold. AI agreement is not independent acoustic corroboration. Human review required for consequential conclusions.",
    }


# -----------------------------------------------------------------------------
# Graphical memory scaffold
# -----------------------------------------------------------------------------

def build_graph(
    sensors: Dict[str, Dict[str, Any]],
    recordings: Dict[str, Dict[str, Any]],
    events: List[Dict[str, Any]],
    clusters: List[Dict[str, Any]],
    localization_results: List[Dict[str, Any]],
    signature_matches: List[Dict[str, Any]],
    facts: List[Dict[str, Any]],
    hypotheses: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    def add_node(node_id: str, node_type: str, props: Dict[str, Any]) -> None:
        if not node_id:
            return
        if any(n.get("id") == node_id for n in nodes):
            return
        nodes.append({"id": node_id, "type": node_type, "properties": props})

    def add_edge(src: str, dst: str, rel: str, props: Dict[str, Any]) -> None:
        if not src or not dst:
            return
        edges.append({"from": src, "to": dst, "type": rel, "properties": props})

    for sid, s in sensors.items():
        node_type = "Hydrophone" if "HYDRO" in str(s.get("sensor_type", "")).upper() else "Microphone"
        add_node(sid, "AcousticSensor", public_dict(s))
        add_node(sid, node_type, {"sensor_id": sid})
        add_edge(sid, node_type, "IS_A", {"sensor_id": sid})

    for rid, r in recordings.items():
        add_node(rid, "AcousticRecording", public_dict(r))
        if r.get("sensor_id"):
            add_edge(rid, r["sensor_id"], "RECORDED_BY", {"recording_id": rid})

    for ev in events:
        eid = ev.get("event_id")
        add_node(
            eid,
            "AcousticEvent",
            {
                "recording_id": ev.get("recording_id"),
                "sensor_ids": ev.get("_sensor_ids"),
                "start_time": iso_or_none(ev.get("_start")),
                "end_time": iso_or_none(ev.get("_end")),
                "event_types": ev.get("_event_types"),
                "source_categories": ev.get("_source_categories"),
                "quality_flags": ev.get("_quality_flags"),
            },
        )
        if ev.get("recording_id"):
            add_edge(eid, ev["recording_id"], "CONTAINED_IN", {"event_id": eid})
        for sid in ev.get("_sensor_ids") or []:
            add_edge(eid, sid, "OBSERVED_BY", {"event_id": eid})

    for cl in clusters:
        cid = cl.get("cluster_id")
        add_node(
            cid,
            "AcousticEvent",
            {
                "cluster": True,
                "event_ids": cl.get("event_ids"),
                "sensor_ids": cl.get("sensor_ids"),
                "event_types": cl.get("event_types"),
                "source_categories": cl.get("source_categories"),
                "source_independence": cl.get("source_independence"),
            },
        )
        for eid in cl.get("event_ids") or []:
            add_edge(cid, eid, "CORRELATED_WITH", {"cluster_id": cid})

    for cat in sorted({c for cl in clusters for c in (cl.get("source_categories") or [])}):
        add_node(f"CAT:{cat}", "SourceCategory", {"category": cat})
        for cl in clusters:
            if cat in (cl.get("source_categories") or []):
                add_edge(cl.get("cluster_id"), f"CAT:{cat}", "SOURCE_CATEGORY_CANDIDATE", {"cluster_id": cl.get("cluster_id")})

    for loc in localization_results:
        lid = f"LOC:{loc.get('cluster_id')}"
        cand = loc.get("location_candidate") or {}
        add_node(
            lid,
            "LocalizationCandidate",
            {
                "cluster_id": loc.get("cluster_id"),
                "method": loc.get("method"),
                "latitude": cand.get("latitude"),
                "longitude": cand.get("longitude"),
                "uncertainty_radius_m": cand.get("uncertainty_radius_m"),
                "precision": loc.get("precision"),
                "confidence": loc.get("confidence"),
            },
        )
        if loc.get("cluster_id"):
            add_edge(loc["cluster_id"], lid, "OCCURRED_AT_CANDIDATE", {"cluster_id": loc["cluster_id"]})

    for match in signature_matches:
        mid = match.get("match_id")
        add_node(mid, "AcousticSignature", match)
        if match.get("cluster_id"):
            add_edge(match["cluster_id"], mid, "HAS_SIGNATURE", {"match_id": mid})

    for fac in facts:
        fid = fac.get("fact_id")
        add_node(fid, "Fact", fac)
        if fac.get("cluster_id"):
            add_edge(fid, fac["cluster_id"], "SUPPORTED_BY", {"fact_id": fid})

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
    clusters: List[Dict[str, Any]],
    localization_results: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    issues: List[str],
    sensors: Dict[str, Dict[str, Any]],
    recordings: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    gaps: List[Dict[str, Any]] = []

    if not clusters:
        gaps.append(
            {
                "gap_id": "GAP-NO-EVENTS",
                "gap": "No usable acoustic events supplied",
                "importance": "HIGH",
                "recommended_source": "Authorized deterministic acoustic event export",
                "expected_information_value": "Establishes whether any acoustic event is measurable",
            }
        )

    if issues:
        gaps.append(
            {
                "gap_id": "GAP-VALIDATION-ISSUES",
                "gap": "Input validation issues present",
                "importance": "HIGH",
                "recommended_source": "Corrected sensor metadata, calibration, clock sync, recording provenance",
                "expected_information_value": "Improves measurement trust",
            }
        )

    unknown_cal = [sid for sid, s in sensors.items() if s.get("_calibration_status") in ("UNCALIBRATED", "CALIBRATION_UNKNOWN")]
    if unknown_cal:
        gaps.append(
            {
                "gap_id": "GAP-CALIBRATION",
                "gap": f"Calibration insufficient for sensors: {', '.join(unknown_cal)}",
                "importance": "HIGH",
                "recommended_source": "Microphone/hydrophone calibration certificate",
                "expected_information_value": "Allows stronger amplitude/SPL interpretation",
            }
        )

    unsync = [sid for sid, s in sensors.items() if s.get("_clock_sync_state") in ("UNSYNCHRONIZED", "UNKNOWN")]
    if unsync:
        gaps.append(
            {
                "gap_id": "GAP-CLOCK-SYNC",
                "gap": f"Clock synchronization insufficient for sensors: {', '.join(unsync)}",
                "importance": "HIGH",
                "recommended_source": "GPS/PTP/NTP sync record, clock offset measurement",
                "expected_information_value": "Required for TDOA/DOA confidence",
            }
        )

    if any(not r.get("content_hash") for r in recordings.values()):
        gaps.append(
            {
                "gap_id": "GAP-PROVENANCE",
                "gap": "Recording provenance/hash missing for some recordings",
                "importance": "MODERATE",
                "recommended_source": "Original file hash, capture chain-of-custody",
                "expected_information_value": "Supports duplicate/independence analysis",
            }
        )

    if localization_results and all(not l.get("location_candidate") for l in localization_results):
        gaps.append(
            {
                "gap_id": "GAP-LOCALIZATION",
                "gap": "Localization unresolved from supplied DOA/TDOA data",
                "importance": "MODERATE",
                "recommended_source": "Synchronized sensor array, known positions, propagation model, deterministic TDOA solver",
                "expected_information_value": "Constrains event region with uncertainty",
            }
        )

    if contradictions:
        gaps.append(
            {
                "gap_id": "GAP-CONTRADICTIONS",
                "gap": "Material contradictions present",
                "importance": "HIGH",
                "recommended_source": "Raw sensor records, clock offsets, independent feed, video/incident logs",
                "expected_information_value": "Prevents silent false resolution",
            }
        )

    gaps.append(
        {
            "gap_id": "GAP-SOURCE-IDENTITY",
            "gap": "Exact source identity unresolved by design",
            "importance": "CONTEXTUAL",
            "recommended_source": "TECHINT / authorized equipment records / independent phenomenology",
            "expected_information_value": "ACOUSTINT alone rarely establishes exact source or actor",
        }
    )

    return gaps


def build_next_actions(
    clusters: List[Dict[str, Any]],
    localization_results: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
) -> List[str]:
    actions: List[str] = []

    if not clusters:
        actions.append("Supply deterministic authorized acoustic event exports with sensor metadata")

    if any(g["gap_id"] == "GAP-CALIBRATION" for g in gaps):
        actions.append("Obtain microphone/hydrophone calibration record before absolute SPL interpretation")

    if any(g["gap_id"] == "GAP-CLOCK-SYNC" for g in gaps):
        actions.append("Verify sensor clock synchronization and offset before TDOA/DOA interpretation")

    if any(g["gap_id"] == "GAP-PROVENANCE" for g in gaps):
        actions.append("Preserve original recording hashes and processing chain")

    if contradictions:
        actions.append("Preserve contradictions and inspect raw sensor/processing provenance before resolution")

    if localization_results:
        actions.append("Correlate event-region candidates with authorized video, incident logs, and GEOINT context")

    if any(any(t in PERSON_RELATED_EVENT_TYPES for t in cl.get("event_types", [])) for cl in clusters):
        actions.append("Hand speech content questions to AUDINT only under separate authorization; no ACOUSTINT voice biometrics")

    if any(set(cl.get("event_types", [])) & {"MACHINERY", "ROTATING_MACHINE", "MECHANICAL_FAILURE_LIKE"} for cl in clusters):
        actions.append("Compare machine signature against context-matched baseline and maintenance/telemetry records")

    actions.append("Maintain passive-only posture; no covert recording, no person tracking, no sonic weapons, no targeting, no sonar evasion, no acoustic stealth optimization")

    return actions


def build_specialist_handoffs(
    clusters: List[Dict[str, Any]],
    localization_results: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    handoffs: List[Dict[str, Any]] = []

    if any("SPEECH_PRESENT" in (cl.get("event_types") or []) for cl in clusters):
        handoffs.append(
            {
                "to": "AUDINT",
                "reason": "Speech content/speaker questions exceed ACOUSTINT boundary",
                "restrictions": [
                    "No voiceprint-to-name",
                    "No private conversation interception",
                    "No sensitive trait inference",
                    "Requires separate authorization",
                ],
            }
        )

    if localization_results and any(l.get("location_candidate") for l in localization_results):
        handoffs.append(
            {
                "to": "GEOINT",
                "reason": "Terrain, structures, propagation, and spatial validation may be required",
                "restrictions": ["No person location inference", "No weapon targeting"],
            }
        )

    if any(set(cl.get("event_types", [])) & {"IMPACT", "EXPLOSION_LIKE", "GUNSHOT_LIKE", "ALARM", "SIREN", "GLASS_BREAK_LIKE"} for cl in clusters):
        handoffs.append(
            {
                "to": "INCIDENTINT",
                "reason": "Possible public-safety or incident event requires authorized incident correlation",
                "restrictions": ["No shooter targeting", "No weapon attribution without evidence", "Human governance required"],
            }
        )

    if any(set(cl.get("event_types", [])) & {"MACHINERY", "ROTATING_MACHINE", "PUMP", "FAN", "MOTOR", "COMPRESSOR", "MECHANICAL_FAILURE_LIKE"} for cl in clusters):
        handoffs.append(
            {
                "to": "TECHINT / INDUSTRIAL ENGINEERING",
                "reason": "Machine identity/fault diagnosis exceeds acoustic signature similarity",
                "restrictions": ["No unsafe remote maintenance action", "Use authorized engineering review"],
            }
        )

    if any(set(cl.get("event_types", [])) & {"VEHICLE", "ENGINE", "AIRCRAFT_LIKE", "RAIL_LIKE", "MARINE_VESSEL_LIKE"} for cl in clusters):
        handoffs.append(
            {
                "to": "TRANSPORTINT / AISINT",
                "reason": "Vehicle/vessel movement identity requires transport/maritime intelligence",
                "restrictions": ["No driver/occupant inference", "No military targeting"],
            }
        )

    if contradictions:
        handoffs.append(
            {
                "to": "MASINT",
                "reason": "Cross-phenomenology fusion may help resolve acoustic contradictions",
                "restrictions": ["Do not force modal agreement", "Preserve uncertainty"],
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

    clusters = r.get("acoustic_events") or []
    locs = r.get("localization_candidates") or []

    lines = [
        "ACOUSTIC DATA: recordings=" + str(len(r.get("recordings") or {})) + " events=" + str(len(r.get("event_segments") or [])) + " clusters=" + str(len(clusters)),
        "SENSORS: " + fmt_list(r.get("sensors")),
        "CALIBRATION: " + fmt_list([f"{k}={v}" for k, v in (r.get("calibration_states") or {}).items()]),
        "CLOCK / SYNCHRONIZATION: " + fmt_list([f"{k}={v}" for k, v in (r.get("clock_states") or {}).items()]),
        "SIGNAL QUALITY: " + fmt_list(sorted({flag for cl in clusters for flag in (cl.get("quality_flags") or [])})),
        "EVENTS DETECTED: " + fmt_list([f"{c.get('cluster_id')}:{','.join(c.get('event_types') or [])}" for c in clusters]),
        "EVENT CLASSIFICATION: " + fmt_list([f"{c.get('cluster_id')}={c.get('classification_state')}" for c in clusters]),
        "SOURCE CATEGORY: " + fmt_list(sorted({cat for c in clusters for cat in (c.get("source_categories") or [])})),
        "FREQUENCY CHARACTERISTICS: " + json.dumps(r.get("frequency_features") or {}, default=str),
        "TEMPORAL CHARACTERISTICS: " + json.dumps(r.get("temporal_features") or {}, default=str),
        "SIGNATURE COMPARISON: " + fmt_list([f"{m.get('reference_signature_id')}={m.get('match_state')}" for m in (r.get("signature_matches") or [])]),
        "MULTI-SENSOR CORRELATION: " + fmt_list([f"{c.get('cluster_id')}={c.get('source_independence')}" for c in clusters]),
        "DIRECTION OF ARRIVAL: " + str(len(r.get("doa_results") or [])),
        "LOCALIZATION: " + fmt_list([f"{l.get('cluster_id')}={l.get('precision')}" for l in locs]),
        "LOCALIZATION UNCERTAINTY: " + fmt_list([f"{l.get('cluster_id')} radius={ (l.get('location_candidate') or {}).get('uncertainty_radius_m') }" for l in locs]),
        "MACHINE / VEHICLE / INDUSTRIAL CONTEXT: " + fmt_list(r.get("industrial_context") or r.get("vehicle_context") or []),
        "ENVIRONMENTAL CONTEXT: " + json.dumps(r.get("environmental_context") or {}, default=str),
        "PROVENANCE: duplicates=" + str(len(r.get("duplicate_recordings") or [])),
        "SOURCE RELIABILITY: " + fmt_list([f"{s.get('sensor_id')}={s.get('reliability')}" for s in (r.get("sensor_reliability") or [])]),
        "SOURCE INDEPENDENCE: " + str(r.get("source_independence")),
        "CONTRADICTIONS: " + str(len(r.get("contradictions") or [])),
        "ALTERNATIVE SOURCES: " + str(len(r.get("hypotheses") or [])),
        "UNKNOWN: " + fmt_list(r.get("unknowns")),
        "NEXT ACTION: " + ((r.get("recommended_next_actions") or ["NONE"])[0]),
    ]

    return "\n".join(lines)


# -----------------------------------------------------------------------------
# Main analysis
# -----------------------------------------------------------------------------

def analyze(case: Dict[str, Any], input_path: Optional[str] = None, input_hash: Optional[str] = None) -> Dict[str, Any]:
    started = utcnow_iso()

    block_reasons = policy_block_reasons(case)
    if block_reasons:
        return blocked_result(case, block_reasons, started, input_path, input_hash)

    sensors, sensor_issues = validate_sensors(case)
    recordings, rec_issues, rec_warnings = validate_recordings(case, sensors)
    events, ev_issues, ev_warnings = validate_events(case, sensors, recordings)
    doa_observations, doa_issues = validate_doa(case, sensors)
    environment = case.get("environment_context") if isinstance(case.get("environment_context"), dict) else {}
    tdoa_observations, tdoa_issues = validate_tdoa(case, sensors, environment)
    supplied_candidates = validate_supplied_location_candidates(case)

    issues = sensor_issues + rec_issues + ev_issues + doa_issues + tdoa_issues
    warnings = rec_warnings + ev_warnings

    settings_raw = case.get("analysis_settings") or {}

    def setting_float(name: str, default: float) -> float:
        try:
            return float(settings_raw.get(name, default))
        except Exception:
            return default

    settings = {
        "correlation_time_window_s": setting_float("correlation_time_window_s", 2.0),
        "spectral_similarity_threshold": setting_float("spectral_similarity_threshold", 0.75),
        "signature_similarity_threshold": setting_float("signature_similarity_threshold", 0.80),
        "localization_max_radius_m": setting_float("localization_max_radius_m", 100000.0),
        "tdoa_residual_tolerance_s": setting_float("tdoa_residual_tolerance_s", 0.05),
    }

    duplicate_recordings = detect_duplicate_recordings(recordings)

    clusters, correlation_contradictions = correlate_events(
        events,
        case.get("multi_sensor_correlations") or [],
        sensors,
        recordings,
        settings,
    )

    for cl in clusters:
        cl["classification_state"] = classification_state(cl)

    signature_matches = build_signature_matches(
        clusters,
        case.get("reference_signatures") or [],
        settings["signature_similarity_threshold"],
    )

    localization_results, localization_contradictions = localize_clusters(
        clusters,
        doa_observations,
        tdoa_observations,
        supplied_candidates,
        sensors,
        environment,
        settings,
    )

    contradictions = detect_contradictions(
        clusters,
        events,
        localization_results,
        signature_matches,
        duplicate_recordings,
        list(case.get("existing_contradictions") or []) + correlation_contradictions + localization_contradictions,
        settings,
    )

    supported_facts, candidate_facts, partial_facts, disputed_facts, not_facts = build_facts(
        clusters,
        events,
        localization_results,
        signature_matches,
        contradictions,
    )

    hypotheses = build_hypotheses(clusters, localization_results, contradictions, issues)
    dual = dual_ai_review(clusters, localization_results, contradictions, issues)

    gaps = build_knowledge_gaps(clusters, localization_results, contradictions, issues, sensors, recordings)
    next_actions = build_next_actions(clusters, localization_results, gaps, contradictions)
    handoffs = build_specialist_handoffs(clusters, localization_results, contradictions)

    graph = build_graph(
        sensors,
        recordings,
        events,
        clusters,
        localization_results,
        signature_matches,
        supported_facts + candidate_facts + partial_facts,
        hypotheses,
        contradictions,
        gaps,
    )

    # Summaries
    calibration_states = {sid: s.get("_calibration_status", "CALIBRATION_UNKNOWN") for sid, s in sensors.items()}
    clock_states = {sid: s.get("_clock_sync_state", "UNKNOWN") for sid, s in sensors.items()}

    frequency_features = {
        "dominant_frequency_summary": numeric_summary([f for e in events for f in (e.get("_dominant_frequencies_hz") or [])]),
        "frequency_min_summary": numeric_summary([e.get("_freq_min_hz") for e in events]),
        "frequency_max_summary": numeric_summary([e.get("_freq_max_hz") for e in events]),
        "spectral_centroid_summary": numeric_summary([e.get("_spectral_features", {}).get("spectral_centroid_hz") for e in events]),
        "spectral_rolloff_summary": numeric_summary([e.get("_spectral_features", {}).get("spectral_rolloff_hz") for e in events]),
    }

    temporal_features = {
        "duration_summary": numeric_summary([e.get("_duration_s") for e in events]),
        "periodicity_interval_summary": numeric_summary([e.get("_periodicity_interval_s") for e in events]),
        "impulsiveness_summary": numeric_summary([e.get("_impulsiveness") for e in events]),
        "rise_time_ms_summary": numeric_summary([e.get("_rise_time_ms") for e in events]),
    }

    signal_quality = {
        "snr_summary": numeric_summary([e.get("_snr_db") for e in events]),
        "noise_floor_summary": numeric_summary([r.get("_noise_floor_db") for r in recordings.values()]),
        "clipping_count": sum(1 for r in recordings.values() if r.get("_clipping")),
        "saturation_count": sum(1 for r in recordings.values() if r.get("_saturation")),
        "dropout_count": sum(1 for r in recordings.values() if r.get("_dropout")),
        "agc_count": sum(1 for r in recordings.values() if r.get("_agc_active")),
        "lossy_count": sum(1 for r in recordings.values() if r.get("_lossy_compression")),
        "generated_count": sum(1 for r in recordings.values() if r.get("_generated_or_reconstructed")),
        "synthetic_candidate_count": sum(1 for r in recordings.values() if r.get("_synthetic_indicators")),
    }

    event_segments = [
        {
            "event_id": e.get("event_id"),
            "recording_id": e.get("recording_id"),
            "sensor_ids": e.get("_sensor_ids"),
            "start_time": iso_or_none(e.get("_start")),
            "end_time": iso_or_none(e.get("_end")),
            "duration_s": e.get("_duration_s"),
            "event_type_candidate": e.get("_event_types"),
            "source_category": e.get("_source_categories"),
            "frequency_range_hz": [e.get("_freq_min_hz"), e.get("_freq_max_hz")],
            "dominant_frequencies_hz": e.get("_dominant_frequencies_hz"),
            "spectral_features": e.get("_spectral_features"),
            "snr_db": e.get("_snr_db"),
            "impulsiveness": e.get("_impulsiveness"),
            "periodicity_interval_s": e.get("_periodicity_interval_s"),
            "quality_flags": e.get("_quality_flags"),
            "classification_confidence": e.get("_classification_confidence"),
            "ood_candidate": e.get("_ood_candidate"),
            "evidence_ids": e.get("_evidence_ids"),
            "source_ids": e.get("_source_ids"),
        }
        for e in events
    ]

    acoustic_events_public = [
        {
            "cluster_id": cl.get("cluster_id"),
            "event_ids": cl.get("event_ids"),
            "sensor_ids": cl.get("sensor_ids"),
            "recording_ids": cl.get("recording_ids"),
            "start_time": cl.get("start_time"),
            "end_time": cl.get("end_time"),
            "event_types": cl.get("event_types"),
            "source_categories": cl.get("source_categories"),
            "classification_state": cl.get("classification_state"),
            "source_independence": cl.get("source_independence"),
            "spectral_similarity": cl.get("spectral_similarity"),
            "quality_flags": cl.get("quality_flags"),
            "confidence": measurement_confidence(cl),
            "limitations": cl.get("limitations"),
        }
        for cl in clusters
    ]

    doa_results = [
        {
            "observation_id": d.get("observation_id"),
            "event_id": d.get("_event_id"),
            "sensor_id": d.get("_sensor_id"),
            "bearing_deg": d.get("_bearing_deg"),
            "bearing_uncertainty_deg": d.get("_uncertainty_deg"),
            "timestamp": iso_or_none(d.get("_timestamp")),
            "quality_flags": d.get("_quality_flags"),
        }
        for d in doa_observations
    ]

    tdoa_results = [
        {
            "observation_id": t.get("observation_id"),
            "event_id": t.get("_event_id"),
            "sensor_pair": t.get("_sensor_pair"),
            "time_difference_s": t.get("_time_difference_s"),
            "uncertainty_s": t.get("_uncertainty_s"),
            "sound_speed_m_s": t.get("_sound_speed_m_s"),
            "timestamp": iso_or_none(t.get("_timestamp")),
            "quality_flags": t.get("_quality_flags"),
        }
        for t in tdoa_observations
    ]

    localization_candidates = [
        {
            "cluster_id": l.get("cluster_id"),
            "method": l.get("method"),
            "location_candidate": l.get("location_candidate"),
            "precision": l.get("precision"),
            "confidence": l.get("confidence"),
            "sensor_ids": l.get("sensor_ids"),
            "tdoa_evaluation": l.get("tdoa_evaluation"),
            "privacy_restraint": l.get("privacy_restraint"),
            "limitations": l.get("limitations"),
        }
        for l in localization_results
    ]

    source_reliability = []
    for sid, s in sensors.items():
        cal = s.get("_calibration_status", "CALIBRATION_UNKNOWN")
        sync = s.get("_clock_sync_state", "UNKNOWN")
        if cal == "CALIBRATED" and sync in ("SYNCHRONIZED", "OFFSET_CORRECTED"):
            rel = "HIGH"
        elif cal == "CALIBRATED" or sync in ("SYNCHRONIZED", "OFFSET_CORRECTED", "APPROXIMATELY_ALIGNED"):
            rel = "MODERATE"
        elif cal == "PARTIALLY_CALIBRATED":
            rel = "LOW"
        else:
            rel = "UNKNOWN"
        source_reliability.append(
            {
                "sensor_id": sid,
                "sensor_type": s.get("sensor_type"),
                "platform": s.get("platform"),
                "calibration_status": cal,
                "clock_sync_state": sync,
                "reliability": rel,
                "known_limitations": s.get("known_limitations"),
                "independence_group": s.get("independence_group"),
                "upstream_recording_id": s.get("upstream_recording_id"),
            }
        )

    if any(cl.get("source_independence") == "INDEPENDENT" for cl in clusters):
        source_independence = "INDEPENDENT_OBSERVATION_AVAILABLE"
    elif clusters:
        source_independence = "SINGLE_SOURCE_OR_UNKNOWN"
    else:
        source_independence = "NO_OBSERVATION"

    unknowns: List[str] = []
    if not clusters:
        unknowns.append("No measurable acoustic event supplied")
    if not any(cl.get("source_independence") == "INDEPENDENT" for cl in clusters):
        unknowns.append("Independent multi-sensor corroboration unavailable")
    if not localization_candidates or all(not l.get("location_candidate") for l in localization_candidates):
        unknowns.append("Localization unresolved")
    if any("SPEECH_PRESENT" in (cl.get("event_types") or []) for cl in clusters):
        unknowns.append("Speech content/speaker identity not analyzed by ACOUSTINT")
    unknowns.append("Exact source identity unresolved by design")
    unknowns.append("Operator/actor/intent unresolved")

    if contradictions:
        status = "SOURCE_CONFLICT"
    elif issues:
        status = "PARTIAL"
    elif not clusters:
        status = "INCONCLUSIVE"
    elif clusters and all(cl.get("classification_state") in ("SUPPORTED_CATEGORY", "PROBABLE_CATEGORY") for cl in clusters):
        status = "PARTIAL"
    else:
        status = "PARTIAL"

    industrial_context = [
        cl.get("cluster_id")
        for cl in clusters
        if set(cl.get("event_types", [])) & {"MACHINERY", "ROTATING_MACHINE", "PUMP", "FAN", "MOTOR", "COMPRESSOR", "MECHANICAL_FAILURE_LIKE", "CONSTRUCTION"}
    ]
    vehicle_context = [
        cl.get("cluster_id")
        for cl in clusters
        if set(cl.get("event_types", [])) & {"VEHICLE", "ENGINE", "AIRCRAFT_LIKE", "RAIL_LIKE", "MARINE_VESSEL_LIKE"}
    ]
    hydroacoustic_context = [
        cl.get("cluster_id")
        for cl in clusters
        if set(cl.get("event_types", [])) & {"HYDROACOUSTIC_EVENT", "MARINE_VESSEL_LIKE"}
    ]

    acoustic_scenes = sorted({str(environment.get("scene_class", "UNKNOWN")).upper()})

    result: Dict[str, Any] = {
        "case_id": case.get("case_id"),
        "task_id": case.get("task_id"),
        "objective": case.get("objective"),
        "questions": case.get("questions") or [],
        "mode": case.get("model_mode", "LOCAL_ONLY"),
        "status": status,
        "source_ids": sorted({sid for e in events for sid in (e.get("_source_ids") or [])}),
        "evidence_ids": sorted({eid for e in events for eid in (e.get("_evidence_ids") or [])}),
        "recordings": {rid: public_dict(r) for rid, r in recordings.items()},
        "recording_hashes": {rid: r.get("content_hash") for rid, r in recordings.items() if r.get("content_hash")},
        "sensors": list(sensors.keys()),
        "sensor_types": sorted({str(s.get("sensor_type")) for s in sensors.values() if s.get("sensor_type")}),
        "sensor_positions": {
            sid: {
                "latitude": s.get("_lat"),
                "longitude": s.get("_lon"),
                "altitude_m": s.get("_alt"),
                "accuracy_m": s.get("_position_accuracy_m"),
            }
            for sid, s in sensors.items()
        },
        "sensor_orientations": {sid: s.get("orientation") for sid, s in sensors.items()},
        "calibration_states": calibration_states,
        "clock_states": clock_states,
        "sample_rates": {rid: r.get("_sample_rate_hz") for rid, r in recordings.items()},
        "channels": {rid: r.get("channels") for rid, r in recordings.items()},
        "signal_quality": signal_quality,
        "noise_floors": {rid: r.get("_noise_floor_db") for rid, r in recordings.items()},
        "snr_values": {e.get("event_id"): e.get("_snr_db") for e in events},
        "clipping": {rid: bool(r.get("_clipping")) for rid, r in recordings.items()},
        "dropouts": {rid: bool(r.get("_dropout")) for rid, r in recordings.items()},
        "acoustic_events": acoustic_events_public,
        "event_segments": event_segments,
        "event_types": sorted({t for cl in clusters for t in (cl.get("event_types") or [])}),
        "source_categories": sorted({c for cl in clusters for c in (cl.get("source_categories") or [])}),
        "frequency_features": frequency_features,
        "spectral_features": [e.get("_spectral_features") for e in events],
        "temporal_features": temporal_features,
        "periodicity_features": [
            {
                "event_id": e.get("event_id"),
                "periodicity_interval_s": e.get("_periodicity_interval_s"),
                "periodicity": e.get("periodicity"),
            }
            for e in events
            if e.get("_periodicity_interval_s") is not None or e.get("periodicity")
        ],
        "impulsive_events": [
            cl.get("cluster_id")
            for cl in clusters
            if set(cl.get("event_types", [])) & {"IMPACT", "EXPLOSION_LIKE", "GUNSHOT_LIKE", "UNKNOWN_IMPULSIVE", "CONSTRUCTION", "GLASS_BREAK_LIKE"}
        ],
        "tonal_events": [
            cl.get("cluster_id")
            for cl in clusters
            if set(cl.get("event_types", [])) & {"ALARM", "SIREN", "BELL", "ELECTRICAL_BUZZ", "UNKNOWN_TONAL", "ROTATING_MACHINE", "FAN", "MOTOR"}
        ],
        "machine_signatures": [
            cl.get("cluster_id")
            for cl in clusters
            if set(cl.get("event_types", [])) & {"MACHINERY", "ROTATING_MACHINE", "PUMP", "FAN", "MOTOR", "COMPRESSOR", "MECHANICAL_FAILURE_LIKE"}
        ],
        "vehicle_context": vehicle_context,
        "industrial_context": industrial_context,
        "environmental_context": environment,
        "hydroacoustic_context": hydroacoustic_context,
        "acoustic_scenes": acoustic_scenes,
        "signature_matches": signature_matches,
        "duplicate_recordings": duplicate_recordings,
        "provenance": case.get("provenance") or [
            {
                "recording_id": rid,
                "content_hash": r.get("content_hash"),
                "codec": r.get("codec"),
                "container": r.get("container"),
                "sensor_id": r.get("sensor_id"),
                "authorization_context": r.get("authorization_context"),
            }
            for rid, r in recordings.items()
        ],
        "multi_sensor_correlations": clusters,
        "doa_results": doa_results,
        "tdoa_results": tdoa_results,
        "localization_candidates": localization_candidates,
        "localization_uncertainty": [
            {
                "cluster_id": l.get("cluster_id"),
                "uncertainty_radius_m": (l.get("location_candidate") or {}).get("uncertainty_radius_m"),
                "precision": l.get("precision"),
                "confidence": l.get("confidence"),
            }
            for l in localization_results
        ],
        "weather_context": environment.get("weather") or {},
        "environment_models": {
            "sound_speed_m_s": sound_speed_m_s(environment),
            "propagation_model": environment.get("propagation_model"),
            "multipath_risk": environment.get("multipath_risk"),
            "occlusion_risk": environment.get("occlusion_risk"),
        },
        "timeline_updates": [
            {
                "cluster_id": cl.get("cluster_id"),
                "start_time": cl.get("start_time"),
                "end_time": cl.get("end_time"),
                "event_types": cl.get("event_types"),
            }
            for cl in clusters
        ],
        "observations": event_segments,
        "candidate_facts": candidate_facts,
        "supported_facts": supported_facts,
        "partial_facts": partial_facts,
        "disputed_facts": disputed_facts,
        "source_reliability": source_reliability,
        "sensor_reliability": source_reliability,
        "source_bias": case.get("source_bias") or [
            "Sensor placement, frequency response, AGC, codec, and platform processing can bias acoustic measurements.",
            "Crowdsourced/public recordings may have uneven coverage and unknown capture conditions.",
        ],
        "source_limitations": case.get("source_limitations") or [
            "Non-detection is not non-occurrence.",
            "Processed audio is not original evidence.",
            "Signature similarity is not source identity.",
            "Event location is not person location.",
        ],
        "source_pedigree": case.get("source_pedigree") or [
            {
                "recording_id": rid,
                "sensor_id": r.get("sensor_id"),
                "content_hash": r.get("content_hash"),
                "upstream_recording_id": r.get("upstream_recording_id"),
                "processing_version": r.get("processing_version"),
            }
            for rid, r in recordings.items()
        ],
        "source_independence": source_independence,
        "contradictions": contradictions,
        "hypotheses": hypotheses,
        "falsification_results": [
            {
                "hypothesis_id": h.get("hypothesis_id"),
                "status": "WEAKENED_BY_CONTRADICTIONS" if contradictions else "NOT_FALSIFIED_WITH_CURRENT_EVIDENCE",
                "required_additional_evidence": [
                    "Independent authorized sensor",
                    "Calibration record",
                    "Clock synchronization record",
                    "Original recording hash",
                    "Environment/propagation metadata",
                    "Video/incident/log correlation",
                ],
            }
            for h in hypotheses
        ],
        "privacy_flags": [
            "NO_SPEECH_TRANSCRIPTION_WITHOUT_AUTHORIZATION",
            "NO_VOICE_BIOMETRIC_IDENTIFICATION",
            "NO_PERSON_TRACKING",
            "NO_SENSITIVE_TRAIT_INFERENCE",
            "EVENT_LOCATION_NOT_PERSON_LOCATION",
            "METADATA_MINIMIZATION",
        ],
        "safety_flags": [
            "PASSIVE_ONLY",
            "NO_COVERT_LISTENING",
            "NO_SONIC_WEAPON",
            "NO_ULTRASONIC_HARASSMENT",
            "NO_WEAPON_TARGETING",
            "NO_SHOOTER_TARGETING",
            "NO_MILITARY_TARGET_LOCALIZATION",
            "NO_SONAR_EVASION",
            "NO_ACOUSTIC_STEALTH_OPTIMIZATION",
            "NO_JAMMING_PUBLIC_SAFETY_ACOUSTIC_SYSTEMS",
        ],
        "unknowns": unknowns,
        "knowledge_gaps": gaps,
        "recommended_next_actions": next_actions,
        "specialist_handoffs": handoffs,
        "limitations": [
            "This scaffold does not process raw audio or activate sensors.",
            "It consumes deterministic feature-level acoustic records only.",
            "It does not invent events, frequencies, dB values, locations, source identities, or actors.",
            "It separates detection, classification, identification, and attribution.",
            "Speech content and speaker identity are handed to AUDINT only under separate authorization.",
            "Localization outputs are event-region candidates with uncertainty, not person locations.",
            "It blocks covert listening, voice biometrics, person tracking, sonic weapons, targeting, military localization, sonar evasion, and acoustic stealth optimization.",
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
                "timestamp normalization",
                "sensor/recording/event validation",
                "Nyquist checks",
                "quality flagging",
                "spectral feature summarization from supplied bands",
                "event vector construction",
                "cosine similarity signature matching",
                "multi-sensor correlation",
                "source independence summarization",
                "DOA bearing intersection",
                "TDOA residual validation",
                "duplicate recording detection",
                "contradiction detection",
                "fact gate",
            ],
            "note": "Replay requires original recording hashes, sensor metadata, calibration, clock sync, processing parameters, STFT/FFT configuration, event-detection thresholds, classifier versions, reference library versions, DOA/TDOA inputs, sound-speed model, and uncertainty calculations.",
        },
    }

    result["required_analyst_summary"] = analyst_summary(result)
    return result


# -----------------------------------------------------------------------------
# Template
# -----------------------------------------------------------------------------

def template_case() -> Dict[str, Any]:
    return {
        "_template_note": "Placeholders only. Replace with deterministic authorized acoustic feature exports. Do not treat this template as real measurement.",
        "case_id": "CASE-ACOUSTINT-EXAMPLE",
        "task_id": "TASK-ACOUSTINT-EXAMPLE",
        "objective": "Authorized passive analysis of an industrial/environmental acoustic event cluster for safety and maintenance context.",
        "questions": [
            "What acoustic events are present?",
            "Which source categories are plausible?",
            "Do independent sensors corroborate the event?",
            "What localization uncertainty exists?",
            "What remains unknown?",
        ],
        "scope": {
            "authorized_only": True,
            "passive_only": True,
            "no_person_tracking": True,
            "voice_biometric": False,
            "covert_recording": False,
            "weapon_targeting": False,
            "military_target_localization": False,
            "metadata_minimization": True,
        },
        "authorization": {
            "lawful_basis": "AUTHORIZED_FACILITY_ACOUSTIC_MONITORING",
            "purpose": "DEFENSIVE_ACOUSTIC_EVENT_AND_SIGNATURE_ANALYSIS",
            "approval_reference": "AUTH-ACOUSTINT-001",
            "data_retention": "MINIMUM_NECESSARY",
        },
        "model_mode": "LOCAL_ONLY",
        "analysis_settings": {
            "correlation_time_window_s": 2.0,
            "spectral_similarity_threshold": 0.75,
            "signature_similarity_threshold": 0.8,
            "localization_max_radius_m": 100000,
            "tdoa_residual_tolerance_s": 0.05,
        },
        "sensors": [
            {
                "sensor_id": "MIC-1",
                "sensor_type": "AUTHORIZED_ENVIRONMENTAL_MICROPHONE",
                "platform": "FIXED_GROUND",
                "position": {"latitude": 0.0, "longitude": 0.0, "altitude_m": 10, "accuracy_m": 2},
                "orientation": {"azimuth_deg": 0, "tilt_deg": 0},
                "sample_rate_hz": 48000,
                "channels": 1,
                "gain_db": 0,
                "calibration_status": "CALIBRATED",
                "calibration_reference": "CAL-MIC-001",
                "clock_source": "GPS",
                "clock_sync_state": "SYNCHRONIZED",
                "independence_group": "GROUP_A",
                "known_limitations": ["Wind noise can affect low-frequency measurements."],
            },
            {
                "sensor_id": "MIC-2",
                "sensor_type": "AUTHORIZED_ENVIRONMENTAL_MICROPHONE",
                "platform": "FIXED_GROUND",
                "position": {"latitude": 0.001, "longitude": 0.0, "altitude_m": 10, "accuracy_m": 2},
                "orientation": {"azimuth_deg": 90, "tilt_deg": 0},
                "sample_rate_hz": 48000,
                "channels": 1,
                "gain_db": 0,
                "calibration_status": "CALIBRATED",
                "calibration_reference": "CAL-MIC-002",
                "clock_source": "GPS",
                "clock_sync_state": "SYNCHRONIZED",
                "independence_group": "GROUP_B",
                "known_limitations": ["Nearby structures may create multipath."],
            },
        ],
        "recordings": [
            {
                "recording_id": "REC-1",
                "sensor_id": "MIC-1",
                "start_time": "2026-10-08T09:00:00Z",
                "end_time": "2026-10-08T09:05:00Z",
                "sample_rate_hz": 48000,
                "bit_depth": 24,
                "codec": "PCM",
                "container": "WAV",
                "content_hash": "sha256:example-rec1",
                "authorization_context": "AUTHORIZED",
                "noise_floor_db": -72.0,
                "snr_db": 18.5,
                "clipping_detected": False,
                "dropout_detected": False,
                "agc_active": False,
                "lossy_compression": False,
            },
            {
                "recording_id": "REC-2",
                "sensor_id": "MIC-2",
                "start_time": "2026-10-08T09:00:00Z",
                "end_time": "2026-10-08T09:05:00Z",
                "sample_rate_hz": 48000,
                "bit_depth": 24,
                "codec": "PCM",
                "container": "WAV",
                "content_hash": "sha256:example-rec2",
                "authorization_context": "AUTHORIZED",
                "noise_floor_db": -70.0,
                "snr_db": 16.2,
                "clipping_detected": False,
                "dropout_detected": False,
                "agc_active": False,
                "lossy_compression": False,
            },
        ],
        "acoustic_events": [
            {
                "event_id": "EVT-1",
                "recording_id": "REC-1",
                "sensor_ids": ["MIC-1"],
                "start_time": "2026-10-08T09:01:00Z",
                "end_time": "2026-10-08T09:01:02Z",
                "duration_s": 2.0,
                "event_type_candidate": ["IMPACT", "MACHINERY"],
                "source_category": ["machine", "impact"],
                "frequency_range_hz": [80, 4000],
                "dominant_frequencies_hz": [120, 360],
                "band_energy": [
                    {"center_hz": 120, "power_linear": 10.0},
                    {"center_hz": 360, "power_linear": 6.0},
                    {"center_hz": 1000, "power_linear": 2.0},
                ],
                "snr_db": 18.5,
                "impulsiveness": 0.82,
                "rise_time_ms": 4.0,
                "classification_confidence": 0.78,
                "classifier_model": "example_acoustic_event_model",
                "classifier_version": "1.0",
                "evidence_id": "EVD-1",
                "source_id": "SRC-FACILITY-A",
            },
            {
                "event_id": "EVT-2",
                "recording_id": "REC-2",
                "sensor_ids": ["MIC-2"],
                "start_time": "2026-10-08T09:01:00.006Z",
                "end_time": "2026-10-08T09:01:02.006Z",
                "duration_s": 2.0,
                "event_type_candidate": ["IMPACT", "MACHINERY"],
                "source_category": ["machine", "impact"],
                "frequency_range_hz": [80, 4000],
                "dominant_frequencies_hz": [121, 359],
                "band_energy": [
                    {"center_hz": 121, "power_linear": 9.4},
                    {"center_hz": 359, "power_linear": 5.7},
                    {"center_hz": 1000, "power_linear": 1.9},
                ],
                "snr_db": 16.2,
                "impulsiveness": 0.79,
                "rise_time_ms": 4.3,
                "classification_confidence": 0.74,
                "classifier_model": "example_acoustic_event_model",
                "classifier_version": "1.0",
                "evidence_id": "EVD-2",
                "source_id": "SRC-FACILITY-B",
            },
        ],
        "multi_sensor_correlations": [
            {
                "cluster_id": "CL-1",
                "event_ids": ["EVT-1", "EVT-2"],
                "confidence": "MODERATE",
                "method": "AUTHORIZED_TIME_SPECTRAL_CORRELATION",
            }
        ],
        "doa_observations": [
            {
                "observation_id": "DOA-1",
                "event_id": "EVT-1",
                "sensor_id": "MIC-1",
                "timestamp": "2026-10-08T09:01:00Z",
                "bearing_deg": 45.0,
                "bearing_uncertainty_deg": 5.0,
            },
            {
                "observation_id": "DOA-2",
                "event_id": "EVT-2",
                "sensor_id": "MIC-2",
                "timestamp": "2026-10-08T09:01:00.006Z",
                "bearing_deg": 135.0,
                "bearing_uncertainty_deg": 5.0,
            },
        ],
        "tdoa_observations": [
            {
                "observation_id": "TDOA-1",
                "event_id": "EVT-2",
                "sensor_pair": ["MIC-1", "MIC-2"],
                "timestamp": "2026-10-08T09:01:00.006Z",
                "time_difference_s": 0.006,
                "uncertainty_s": 0.001,
            }
        ],
        "environment_context": {
            "scene_class": "INDUSTRIAL",
            "weather": {"temperature_c": 20.0, "wind_speed_m_s": 2.0, "humidity_percent": 45},
            "propagation_model": "APPROXIMATE_FREE_FIELD_WITH_STRUCTURES",
            "multipath_risk": "MEDIUM",
            "occlusion_risk": "LOW",
        },
        "reference_signatures": [
            {
                "reference_signature_id": "REF-INDUSTRIAL-IMPACT-CLASS",
                "class_label": "INDUSTRIAL_IMPACT_CLASS_CANDIDATE",
                "feature_vector": [0.82, 4.0, 120.0, 360.0, 18.5, 2.0],
                "collection_conditions": "Example authorized industrial reference; not exact device identity.",
                "limitations": ["Reference may vary with load, distance, and environment."],
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
        description=(
            "TRACEATLAS ACOUSTINT authorized passive-first defensive acoustic intelligence scaffold. "
            "Consumes deterministic feature-level acoustic records; does not activate microphones, "
            "record private conversations, perform voice biometrics, track persons, design weapons, "
            "target, provide military localization, sonar evasion, or acoustic stealth optimization."
        )
    )
    parser.add_argument("--input", "-i", help="Path to ACOUSTINT input JSON")
    parser.add_argument("--output", "-o", default="acoustint_result.json", help="Output ACOUSTINTResult JSON path")
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
                "output": str(out),
                "summary": result.get("required_analyst_summary"),
            },
            indent=2,
            default=str,
        )
    )


if __name__ == "__main__":
    main()
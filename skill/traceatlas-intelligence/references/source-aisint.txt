"""
======================================================================
TRACEATLAS — AISINT
AIS / MARITIME INTELLIGENCE AI EMPLOYEE
Python Implementation (Lawful / Evidence-First / Safety-Aware)
======================================================================

Purpose:
- Preserve raw AIS evidence
- Normalize time / identifiers / positions
- Resolve vessel identity with IMO / MMSI / call sign / name history
- Reconstruct AIS tracks without inventing missing points
- Detect AIS gaps, coverage uncertainty, impossible movement candidates
- Analyze port calls, anchorages, loitering, proximity, rendezvous, STS candidates
- Apply Fact Gate, competing hypotheses, falsification, dual-AI review
- Write to graphical memory and produce defensible report

Hard boundary:
- NOT a targeting system
- NOT an interception planner
- NOT an AIS spoofing / jamming / evasion tool
- NOT a sanctions-evasion or smuggling-route planner
"""

from __future__ import annotations

import itertools
import json
import hashlib
import logging
import math
import re
import unicodedata
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum, IntEnum
from typing import Any, Iterable, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("AISINT")

# Optional real AIS NMEA decoder. If unavailable, code accepts decoded JSON payloads.
try:
    import pyais  # type: ignore
    PYAIS_AVAILABLE = True
except Exception:
    PYAIS_AVAILABLE = False


# ======================================================================
# SECTION 1 — ENUMS
# ======================================================================

class ModelMode(str, Enum):
    LOCAL_ONLY = "LOCAL_ONLY"
    HYBRID = "HYBRID"
    CLOUD = "CLOUD"


class SourceType(str, Enum):
    TERRESTRIAL_AIS = "TERRESTRIAL_AIS"
    SATELLITE_AIS = "SATELLITE_AIS"
    PORT_AIS = "PORT_AIS"
    AUTHORIZED_PRIVATE_RECEIVER = "AUTHORIZED_PRIVATE_RECEIVER"
    AGGREGATED_FEED = "AGGREGATED_FEED"
    RADAR = "RADAR"
    SATELLITE_IMAGERY = "SATELLITE_IMAGERY"
    OFFICIAL_REGISTRY = "OFFICIAL_REGISTRY"
    PORT_AUTHORITY = "PORT_AUTHORITY"
    TRADE_RECORD = "TRADE_RECORD"
    NEWS_REPORT = "NEWS_REPORT"
    UNKNOWN = "UNKNOWN"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERIFIED = "VERIFIED"


class NavStatus(IntEnum):
    UNDER_WAY_USING_ENGINE = 0
    AT_ANCHOR = 1
    NOT_UNDER_COMMAND = 2
    RESTRICTED_MANOEUVRABILITY = 3
    CONSTRAINED_BY_DRAUGHT = 4
    MOORED = 5
    AGROUND = 6
    ENGAGED_IN_FISHING = 7
    UNDER_WAY_SAILING = 8
    RESERVED_9 = 9
    RESERVED_10 = 10
    RESERVED_11 = 11
    RESERVED_12 = 12
    RESERVED_13 = 13
    AIS_TRANSCEIVER = 14
    AIS_TRANSCEIVER_INACTIVE = 15


class PortCallState(str, Enum):
    PORT_CALL_VERIFIED = "PORT_CALL_VERIFIED"
    PORT_CALL_SUPPORTED = "PORT_CALL_SUPPORTED"
    PORT_CALL_CANDIDATE = "PORT_CALL_CANDIDATE"
    TRANSIT_ONLY = "TRANSIT_ONLY"
    ANCHORAGE_ONLY = "ANCHORAGE_ONLY"
    UNKNOWN = "UNKNOWN"


class STSStatus(str, Enum):
    UNKNOWN = "UNKNOWN"
    PROXIMITY_ONLY = "PROXIMITY_ONLY"
    STS_CANDIDATE = "STS_CANDIDATE"
    STS_SUPPORTED = "STS_SUPPORTED"


class SpoofingConfidence(str, Enum):
    NO_SPOOFING_EVIDENCE = "NO_SPOOFING_EVIDENCE"
    ANOMALOUS = "ANOMALOUS"
    POSSIBLE_SPOOFING = "POSSIBLE_SPOOFING"
    SUPPORTED_SPOOFING = "SUPPORTED_SPOOFING"
    INCONCLUSIVE = "INCONCLUSIVE"


class CoverageState(str, Enum):
    COVERAGE_EXPECTED = "COVERAGE_EXPECTED"
    COVERAGE_PARTIAL = "COVERAGE_PARTIAL"
    COVERAGE_POOR = "COVERAGE_POOR"
    COVERAGE_UNKNOWN = "COVERAGE_UNKNOWN"


class FactStatus(str, Enum):
    FACT = "FACT"
    SUPPORTED = "SUPPORTED"
    CANDIDATE = "CANDIDATE"
    DISPUTED = "DISPUTED"
    UNKNOWN = "UNKNOWN"


class ReviewStatus(str, Enum):
    AGREE = "AGREE"
    PARTIAL_AGREEMENT = "PARTIAL_AGREEMENT"
    DISAGREE = "DISAGREE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    POLICY_BLOCKED = "POLICY_BLOCKED"


# ======================================================================
# SECTION 2 — SMALL UTILITIES
# ======================================================================

def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _json_default(obj: Any) -> Any:
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def safe_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except Exception:
        return None


def safe_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except Exception:
        return None


def normalize_text(value: Any, upper: bool = True) -> Optional[str]:
    if value is None:
        return None
    s = unicodedata.normalize("NFKC", str(value)).strip()
    if not s:
        return None
    return s.upper() if upper else s


def to_datetime(value: Any) -> Optional[datetime]:
    """
    Normalize timestamps to UTC.
    Accepts datetime, ISO string, Unix timestamp.
    Naive datetimes are assumed UTC.
    """
    if value is None:
        return None

    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        try:
            dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
        except Exception:
            return None
    elif isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        s = s.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s)
        except Exception:
            for fmt in (
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S",
            ):
                try:
                    dt = datetime.strptime(s, fmt)
                    break
                except Exception:
                    dt = None
            if dt is None:
                return None
    else:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def unique_list(items: Iterable[Any]) -> list[Any]:
    seen = set()
    out = []
    for item in items:
        if item is None:
            continue
        key = item.value if isinstance(item, Enum) else item
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def median(values: Iterable[Optional[float]]) -> Optional[float]:
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    n = len(vals)
    mid = n // 2
    if n % 2 == 1:
        return vals[mid]
    return (vals[mid - 1] + vals[mid]) / 2.0


# ======================================================================
# SECTION 3 — GEOSPATIAL / MARITIME DETERMINISTIC HELPERS
# ======================================================================

EARTH_RADIUS_NM = 3440.065


def haversine_nm(
    lat1: Optional[float],
    lon1: Optional[float],
    lat2: Optional[float],
    lon2: Optional[float],
) -> Optional[float]:
    """Great-circle distance in nautical miles."""
    if lat1 is None or lon1 is None or lat2 is None or lon2 is None:
        return None
    try:
        phi1 = math.radians(float(lat1))
        phi2 = math.radians(float(lat2))
        dphi = math.radians(float(lat2) - float(lat1))
        dlmb = math.radians(float(lon2) - float(lon1))
        a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlmb / 2) ** 2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return EARTH_RADIUS_NM * c
    except Exception:
        return None


def implied_speed_kn(distance_nm: Optional[float], time_delta: Optional[timedelta]) -> Optional[float]:
    if distance_nm is None or time_delta is None:
        return None
    hours = time_delta.total_seconds() / 3600.0
    if hours <= 0:
        return None
    return distance_nm / hours


def coordinate_valid(lat: Optional[float], lon: Optional[float]) -> bool:
    if lat is None or lon is None:
        return False
    return -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0


def is_zero_placeholder(lat: Optional[float], lon: Optional[float]) -> bool:
    return lat == 0.0 and lon == 0.0


def relative_speed_kn(a: "Observation", b: "Observation") -> Optional[float]:
    """
    Approximate relative speed from SOG/COG.
    This is not a substitute for radar/AST, but useful for candidate detection.
    """
    if a.sog is None or b.sog is None:
        return None
    if a.cog is None or b.cog is None:
        return abs(a.sog - b.sog)

    delta_cog = math.radians((a.cog - b.cog) % 360.0)
    try:
        return math.sqrt(
            a.sog ** 2 + b.sog ** 2 - 2 * a.sog * b.sog * math.cos(delta_cog)
        )
    except Exception:
        return abs(a.sog - b.sog)


# ======================================================================
# SECTION 4 — IDENTIFIER VALIDATION
# ======================================================================

def validate_mmsi(mmsi: Optional[str]) -> tuple[bool, str]:
    if mmsi is None:
        return False, "missing"
    s = str(mmsi).strip()
    if not s.isdigit():
        return False, "non-numeric"
    if len(s) != 9:
        return False, "length must be 9 digits"
    mid = int(s[:3])
    if not (200 <= mid <= 789):
        return False, "MID outside typical vessel range"
    return True, "valid"


def validate_imo(imo: Optional[str]) -> tuple[bool, str]:
    """
    IMO number check digit validation.
    IMO is generally 7 digits: first 6 digits + check digit.
    """
    if imo is None:
        return False, "missing"
    s = str(imo).strip().upper()
    s = s.replace("IMO", "").replace("-", "").replace(" ", "")
    if not s.isdigit():
        return False, "non-numeric"
    if len(s) != 7:
        return False, "length must be 7 digits"
    digits = [int(ch) for ch in s]
    checksum = (
        digits[0] * 1
        + digits[1] * 2
        + digits[2] * 3
        + digits[3] * 4
        + digits[4] * 5
        + digits[5] * 6
    ) % 10
    if checksum != digits[6]:
        return False, "checksum failed"
    return True, "valid"


# ======================================================================
# SECTION 5 — POLICY GUARD / PROMPT INJECTION DEFENSE
# ======================================================================

@dataclass
class PolicyResult:
    decision: PolicyDecision
    reason: str = ""


class PolicyGuard:
    """
    Blocks requests seeking harmful maritime operational guidance.
    Does not provide instructions for evasion, spoofing, jamming, interception, etc.
    """

    PROHIBITED_PATTERNS = [
        r"(?:how\s+to|guide\s+to|instructions?\s+to|teach\s+me).*(?:spoof|fake|mask|hide|disable|jam|evade|avoid detection).*?(?:ais|gnss|gps|transponder|tracking|detection)",
        r"\b(?:ais|gnss|gps)\s+(?:spoofing|jamming|manipulation|evasion)\b",
        r"\b(?:sanctions?|smuggling)\s+evasion\s+(?:route|plan|voyage|strategy)\b",
        r"\b(?:vessel|ship)\s+(?:interception|boarding|attack|targeting)\b",
        r"\bweapons?[-\s]targeting\b",
        r"\bAIS[-\s]dark\b",
        r"\bcovert\s+STS\b",
        r"\btransponder\s+(?:disable|off|shutdown)\b",
        r"\bMMSI\s+(?:manipulation|change|spoof)\b",
    ]

    def __init__(self) -> None:
        self._compiled = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.PROHIBITED_PATTERNS]

    def check_request(self, text: str) -> PolicyResult:
        t = text or ""
        for rx in self._compiled:
            if rx.search(t):
                return PolicyResult(
                    decision=PolicyDecision.POLICY_BLOCKED,
                    reason="Request seeks prohibited operational maritime guidance.",
                )
        return PolicyResult(decision=PolicyDecision.ALLOW, reason="")

    def is_safe_action(self, action: str) -> bool:
        return self.check_request(action).decision == PolicyDecision.ALLOW


class PromptInjectionDefense:
    """
    AIS destination text, vessel names, provider metadata, documents, and port records
    are untrusted data. This sanitizer neutralizes obvious control-token style injections
    while preserving original evidence separately.
    """

    CONTROL_TOKEN_RX = re.compile(r"<\|.*?\|>", re.DOTALL)
    INSTRUCTION_RX = re.compile(
        r"(?i)\b(ignore\s+previous|ignore\s+above|system\s+prompt|you\s+are\s+now|new\s+instructions?)\b"
    )

    def sanitize(self, text: Any, max_len: int = 500) -> Optional[str]:
        if text is None:
            return None
        s = str(text)
        s = self.CONTROL_TOKEN_RX.sub("[REDACTED_CONTROL_TOKEN]", s)
        s = self.INSTRUCTION_RX.sub("[UNTRUSTED_INSTRUCTION]", s)
        return s[:max_len]


# ======================================================================
# SECTION 6 — CORE DATA OBJECTS
# ======================================================================

@dataclass
class Evidence:
    evidence_id: str
    case_id: str
    source_id: str
    source_type: SourceType
    receiver_type: SourceType
    message_id: str
    message_type: str
    raw_payload_reference: str
    decoded_payload: dict[str, Any]
    received_at: datetime
    transmitted_at: Optional[datetime] = None
    retrieved_at: Optional[datetime] = None
    content_hash: str = ""
    parser_version: str = "AISINT-decoder-0.1.0"
    normalizer_version: str = "AISINT-normalizer-0.1.0"
    authorization_context: str = ""


@dataclass
class Observation:
    observation_id: str
    vessel_candidate_id: str
    timestamp: datetime
    mmsi: Optional[str] = None
    imo_candidate: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    sog: Optional[float] = None
    cog: Optional[float] = None
    heading: Optional[float] = None
    rate_of_turn: Optional[float] = None
    nav_status: Optional[NavStatus] = None
    position_accuracy: Optional[float] = None
    receiver_type: SourceType = SourceType.UNKNOWN
    source_id: str = ""
    confidence: Confidence = Confidence.LOW
    quality_flags: list[str] = field(default_factory=list)
    evidence_id: str = ""

    # Static / voyage fields, treated as reported/manual where applicable
    name: Optional[str] = None
    callsign: Optional[str] = None
    ship_type: Optional[int] = None
    length: Optional[float] = None
    beam: Optional[float] = None
    draught: Optional[float] = None
    destination: Optional[str] = None
    raw_destination: Optional[str] = None
    eta: Optional[datetime] = None


@dataclass
class VesselIdentityEra:
    vessel_id: str
    valid_from: datetime
    valid_to: datetime
    name: Optional[str] = None
    mmsi: Optional[str] = None
    imo: Optional[str] = None
    callsign: Optional[str] = None
    flag: Optional[str] = None
    ship_type: Optional[int] = None
    length: Optional[float] = None
    beam: Optional[float] = None
    registered_owner: Optional[str] = None
    operator: Optional[str] = None
    manager: Optional[str] = None
    source_ids: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.LOW


@dataclass
class MMSIUsageEra:
    mmsi: str
    vessel_id: str
    valid_from: datetime
    valid_to: datetime
    source_ids: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.LOW


@dataclass
class Vessel:
    vessel_id: str
    current_name: Optional[str] = None
    historical_names: list[str] = field(default_factory=list)
    imo: Optional[str] = None
    call_sign: Optional[str] = None
    flag: Optional[str] = None
    ship_type: Optional[int] = None
    length: Optional[float] = None
    beam: Optional[float] = None
    registered_owner: Optional[str] = None
    operator: Optional[str] = None
    manager: Optional[str] = None
    technical_manager: Optional[str] = None
    charterer: Optional[str] = None
    fleet: Optional[str] = None
    status: str = "UNKNOWN"
    identity_eras: list[VesselIdentityEra] = field(default_factory=list)
    mmsi_usage_eras: list[MMSIUsageEra] = field(default_factory=list)
    source_ids: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.LOW


@dataclass
class TrackSegment:
    segment_id: str
    vessel_id: str
    start_time: datetime
    end_time: datetime
    start_latitude: Optional[float] = None
    start_longitude: Optional[float] = None
    end_latitude: Optional[float] = None
    end_longitude: Optional[float] = None
    observation_count: int = 0
    source_mix: list[str] = field(default_factory=list)
    distance_nm: Optional[float] = None
    average_speed_kn: Optional[float] = None
    confidence: Confidence = Confidence.LOW
    gap_flags: list[str] = field(default_factory=list)


@dataclass
class AISGap:
    gap_id: str
    vessel_id: str
    gap_start: datetime
    gap_end: datetime
    last_pre_observation_id: Optional[str] = None
    first_post_observation_id: Optional[str] = None
    duration_minutes: Optional[float] = None
    distance_nm: Optional[float] = None
    implied_speed_kn: Optional[float] = None
    coverage_state: CoverageState = CoverageState.COVERAGE_UNKNOWN
    possible_causes: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.LOW


@dataclass
class Port:
    port_id: str
    name: str
    latitude: float
    longitude: float
    radius_nm: float
    unlocode: Optional[str] = None
    source_id: str = ""


@dataclass
class PortCall:
    port_call_id: str
    vessel_id: str
    port_id: str
    arrival_time: Optional[datetime] = None
    departure_time: Optional[datetime] = None
    dwell_minutes: Optional[float] = None
    average_speed_kn: Optional[float] = None
    state: PortCallState = PortCallState.UNKNOWN
    evidence_ids: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.LOW
    notes: list[str] = field(default_factory=list)


@dataclass
class ProximityEvent:
    event_id: str
    vessel_a: str
    vessel_b: str
    start_time: datetime
    end_time: datetime
    minimum_distance_nm: Optional[float] = None
    median_relative_speed_kn: Optional[float] = None
    location_latitude: Optional[float] = None
    location_longitude: Optional[float] = None
    source_coverage: CoverageState = CoverageState.COVERAGE_UNKNOWN
    confidence: Confidence = Confidence.LOW
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class RendezvousCandidate:
    candidate_id: str
    vessel_a: str
    vessel_b: str
    proximity_event_id: str
    status: str = "PROXIMITY_ONLY"
    alternative_explanations: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.LOW


@dataclass
class STSCandidate:
    sts_id: str
    vessel_a: str
    vessel_b: str
    proximity_event_id: str
    status: STSStatus = STSStatus.UNKNOWN
    supporting_factors: list[str] = field(default_factory=list)
    missing_corroboration: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.LOW


@dataclass
class Contradiction:
    contradiction_id: str
    contradiction_type: str
    description: str
    evidence_ids: list[str] = field(default_factory=list)
    candidate_resolutions: list[str] = field(default_factory=list)
    status: str = "OPEN"


@dataclass
class Hypothesis:
    hypothesis_id: str
    statement: str
    supports: list[str] = field(default_factory=list)
    oppositions: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    falsification_tests: list[str] = field(default_factory=list)
    status: str = "OPEN"


@dataclass
class Fact:
    fact_id: str
    statement: str
    status: FactStatus
    evidence_ids: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


@dataclass
class KnowledgeGap:
    gap_id: str
    description: str
    importance: str = "MEDIUM"
    recommended_source: str = ""
    specialist: str = ""
    expected_information_value: str = ""


@dataclass
class NextAction:
    action_id: str
    description: str
    rationale: str = ""
    priority: str = "MEDIUM"
    safety_ok: bool = True


@dataclass
class SpecialistHandoff:
    handoff_id: str
    specialist: str
    reason: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class AISINTResult:
    case_id: str
    task_id: str
    objective: str
    status: str
    policy_decision: PolicyDecision = PolicyDecision.ALLOW

    evidence: list[Evidence] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    vessels: list[Vessel] = field(default_factory=list)
    vessel_identity_eras: list[VesselIdentityEra] = field(default_factory=list)
    mmsi_usage_eras: list[MMSIUsageEra] = field(default_factory=list)

    track_segments: list[TrackSegment] = field(default_factory=list)
    ais_gaps: list[AISGap] = field(default_factory=list)
    port_calls: list[PortCall] = field(default_factory=list)
    stationary_patterns: list[dict[str, Any]] = field(default_factory=list)

    proximity_events: list[ProximityEvent] = field(default_factory=list)
    rendezvous_candidates: list[RendezvousCandidate] = field(default_factory=list)
    sts_candidates: list[STSCandidate] = field(default_factory=list)

    contradictions: list[Contradiction] = field(default_factory=list)
    facts: list[Fact] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)

    knowledge_gaps: list[KnowledgeGap] = field(default_factory=list)
    next_actions: list[NextAction] = field(default_factory=list)
    specialist_handoffs: list[SpecialistHandoff] = field(default_factory=list)

    source_independence: dict[str, Any] = field(default_factory=dict)
    spoofing_confidence: SpoofingConfidence = SpoofingConfidence.NO_SPOOFING_EVIDENCE
    spoofing_indicators: list[str] = field(default_factory=list)

    review: dict[str, Any] = field(default_factory=dict)
    graph: dict[str, Any] = field(default_factory=dict)
    report: str = ""

    unknowns: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    safety_flags: list[str] = field(default_factory=list)
    privacy_flags: list[str] = field(default_factory=list)


# ======================================================================
# SECTION 7 — AIS DECODER / INGESTION
# ======================================================================

class AISDecoder:
    """
    Ingests raw AIS evidence.

    Supported inputs:
    1) Decoded JSON/dict payload with fields like:
       mmsi, imo, timestamp, lat, lon, sog, cog, heading, nav_status,
       name, callsign, ship_type, length, beam, draught, destination, eta
    2) NMEA string if pyais is installed.

    The decoder preserves evidence even if an observation cannot be built.
    It never invents missing AIS points.
    """

    PARSER_VERSION = "AISINT-decoder-0.1.0"
    NORMALIZER_VERSION = "AISINT-normalizer-0.1.0"

    def __init__(self, injection_defense: Optional[PromptInjectionDefense] = None):
        self.injection_defense = injection_defense or PromptInjectionDefense()

    @staticmethod
    def _to_source_type(value: Any) -> SourceType:
        if isinstance(value, SourceType):
            return value
        try:
            return SourceType(str(value).upper())
        except Exception:
            return SourceType.UNKNOWN

    def ingest(
        self,
        case_id: str,
        source_id: str,
        source_type: Any,
        receiver_type: Any,
        raw: Any,
        received_at: Any = None,
        transmitted_at: Any = None,
        authorization_context: str = "",
    ) -> tuple[Evidence, Optional[Observation]]:
        source_type = self._to_source_type(source_type)
        receiver_type = self._to_source_type(receiver_type)
        received_at_dt = to_datetime(received_at) or utcnow()
        transmitted_at_dt = to_datetime(transmitted_at)

        if isinstance(raw, dict):
            payload = dict(raw)
            message_type = str(payload.get("message_type", "DECODED_PAYLOAD"))
            raw_ref = json.dumps(payload, sort_keys=True, default=_json_default)[:1000]
        elif isinstance(raw, str):
            if PYAIS_AVAILABLE and raw.startswith("!"):
                try:
                    msg = pyais.decode(raw)  # type: ignore[attr-defined]
                    payload = msg.as_dict()
                    message_type = f"AIS_TYPE_{payload.get('type', getattr(msg, 'msg_type', 'UNKNOWN'))}"
                except Exception:
                    payload = {"raw": raw}
                    message_type = "UNDECODED_NMEA"
            else:
                payload = {"raw": raw}
                message_type = "RAW_TEXT"
        else:
            payload = {"raw": str(raw)}
            message_type = "UNKNOWN"

        # Preserve untrusted text but sanitize what may later be sent to models.
        for key in ("destination", "name", "callsign"):
            if key in payload:
                payload[f"_sanitized_{key}"] = self.injection_defense.sanitize(payload.get(key))

        canonical = json.dumps(payload, sort_keys=True, default=_json_default)
        content_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        evidence = Evidence(
            evidence_id=new_id("EV"),
            case_id=case_id,
            source_id=source_id,
            source_type=source_type,
            receiver_type=receiver_type,
            message_id=str(payload.get("message_id", new_id("MSG"))),
            message_type=message_type,
            raw_payload_reference=raw_ref,
            decoded_payload=payload,
            received_at=received_at_dt,
            transmitted_at=transmitted_at_dt,
            retrieved_at=utcnow(),
            content_hash=content_hash,
            parser_version=self.PARSER_VERSION,
            normalizer_version=self.NORMALIZER_VERSION,
            authorization_context=authorization_context,
        )

        observation = self._payload_to_observation(payload, evidence)
        return evidence, observation

    def _payload_to_observation(
        self,
        payload: dict[str, Any],
        evidence: Evidence,
    ) -> Optional[Observation]:
        timestamp = to_datetime(
            payload.get("timestamp")
            or payload.get("time")
            or payload.get("event_time")
        )
        if timestamp is None:
            # Evidence is preserved, but no timed observation can be reconstructed.
            return None

        mmsi = normalize_text(payload.get("mmsi"), upper=False)
        imo = normalize_text(payload.get("imo"), upper=False)
        lat = safe_float(payload.get("lat", payload.get("latitude")))
        lon = safe_float(payload.get("lon", payload.get("longitude")))
        sog = safe_float(payload.get("sog"))
        cog = safe_float(payload.get("cog"))
        heading = safe_float(payload.get("heading"))
        rot = safe_float(payload.get("rot", payload.get("rate_of_turn")))
        position_accuracy = safe_float(payload.get("position_accuracy"))

        nav_raw = payload.get("nav_status", payload.get("navigation_status"))
        nav_status: Optional[NavStatus] = None
        if nav_raw is not None:
            try:
                nav_status = NavStatus(int(nav_raw))
            except Exception:
                nav_status = None

        name = normalize_text(payload.get("name"))
        callsign = normalize_text(payload.get("callsign", payload.get("call_sign")))
        ship_type = safe_int(payload.get("ship_type", payload.get("type")))
        length = safe_float(payload.get("length"))
        beam = safe_float(payload.get("beam"))
        draught = safe_float(payload.get("draught"))
        raw_destination = payload.get("destination")
        destination = normalize_text(raw_destination)
        eta = to_datetime(payload.get("eta"))

        quality_flags: list[str] = []

        if not mmsi and not imo:
            quality_flags.append("MISSING_IDENTIFIER")

        if mmsi:
            ok, note = validate_mmsi(mmsi)
            if not ok:
                quality_flags.append(f"INVALID_MMSI:{note}")

        if imo:
            ok, note = validate_imo(imo)
            if not ok:
                quality_flags.append(f"INVALID_IMO:{note}")

        if lat is None or lon is None:
            quality_flags.append("MISSING_POSITION")
        else:
            if not coordinate_valid(lat, lon):
                quality_flags.append("INVALID_COORDINATE")
            if is_zero_placeholder(lat, lon):
                quality_flags.append("ZERO_POSITION_PLACEHOLDER_SUSPECT")

        if sog is not None and sog > 60.0:
            quality_flags.append("HIGH_SOG_SUSPECT")

        # Manual / reported fields are not independently verified by AIS alone.
        if destination is not None:
            quality_flags.append("MANUAL_OR_REPORTED_DESTINATION")
        if eta is not None:
            quality_flags.append("MANUAL_OR_REPORTED_ETA")
        if draught is not None:
            quality_flags.append("MANUAL_OR_REPORTED_DRAUGHT")
        if nav_status is not None:
            quality_flags.append("REPORTED_NAV_STATUS")

        confidence = Confidence.LOW
        if (mmsi or imo) and timestamp is not None and lat is not None and lon is not None:
            confidence = Confidence.MEDIUM

        vessel_candidate_id = f"CAND_{mmsi or imo or evidence.evidence_id}"

        return Observation(
            observation_id=new_id("OBS"),
            vessel_candidate_id=vessel_candidate_id,
            timestamp=timestamp,
            mmsi=mmsi,
            imo_candidate=imo,
            latitude=lat,
            longitude=lon,
            sog=sog,
            cog=cog,
            heading=heading,
            rate_of_turn=rot,
            nav_status=nav_status,
            position_accuracy=position_accuracy,
            receiver_type=evidence.receiver_type,
            source_id=evidence.source_id,
            confidence=confidence,
            quality_flags=quality_flags,
            evidence_id=evidence.evidence_id,
            name=name,
            callsign=callsign,
            ship_type=ship_type,
            length=length,
            beam=beam,
            draught=draught,
            destination=destination,
            raw_destination=str(raw_destination) if raw_destination is not None else None,
            eta=eta,
        )


# ======================================================================
# SECTION 8 — VESSEL IDENTITY RESOLUTION
# ======================================================================

class VesselResolver:
    """
    Resolves vessel candidates using IMO, MMSI, call sign, name, dimensions.
    Maintains identity eras and MMSI usage eras.
    Prevents historical identity contamination where possible.
    """

    def resolve(
        self,
        observations: list[Observation],
    ) -> tuple[
        list[Vessel],
        list[VesselIdentityEra],
        list[MMSIUsageEra],
        list[Contradiction],
    ]:
        obs = sorted(
            [o for o in observations if o.timestamp is not None],
            key=lambda x: x.timestamp,
        )

        obs_by_key: dict[str, list[Observation]] = {}
        for o in obs:
            if o.imo_candidate and validate_imo(o.imo_candidate)[0]:
                key = f"IMO_{o.imo_candidate}"
            elif o.mmsi:
                key = f"MMSI_{o.mmsi}"
            else:
                key = f"OBS_{o.observation_id}"
            o.vessel_candidate_id = key
            obs_by_key.setdefault(key, []).append(o)

        vessels: list[Vessel] = []
        identity_eras: list[VesselIdentityEra] = []
        mmsi_eras: list[MMSIUsageEra] = []
        contradictions: list[Contradiction] = []
        key_to_vessel_id: dict[str, str] = {}

        for key, olist in obs_by_key.items():
            vessel_id = f"VESSEL_{hashlib.sha1(key.encode('utf-8')).hexdigest()[:12]}"
            key_to_vessel_id[key] = vessel_id

            current: Optional[dict[str, Any]] = None

            def close_era(cur: dict[str, Any]) -> None:
                attrs = cur["attrs"]
                name, mmsi, imo, callsign, ship_type, length, beam = attrs
                start = cur["start"]
                end = cur["end"]
                source_ids = unique_list(cur["source_ids"])

                if imo and validate_imo(imo)[0]:
                    conf = Confidence.HIGH
                elif mmsi and name:
                    conf = Confidence.MEDIUM
                else:
                    conf = Confidence.LOW

                era = VesselIdentityEra(
                    vessel_id=vessel_id,
                    valid_from=start,
                    valid_to=end,
                    name=name,
                    mmsi=mmsi,
                    imo=imo,
                    callsign=callsign,
                    flag=None,
                    ship_type=ship_type,
                    length=length,
                    beam=beam,
                    source_ids=source_ids,
                    confidence=conf,
                )
                identity_eras.append(era)

                if mmsi:
                    mmsi_eras.append(
                        MMSIUsageEra(
                            mmsi=mmsi,
                            vessel_id=vessel_id,
                            valid_from=start,
                            valid_to=end,
                            source_ids=source_ids,
                            confidence=conf,
                        )
                    )

            for o in olist:
                attrs = (
                    o.name,
                    o.mmsi,
                    o.imo_candidate,
                    o.callsign,
                    o.ship_type,
                    o.length,
                    o.beam,
                )
                if current is None:
                    current = {
                        "attrs": attrs,
                        "start": o.timestamp,
                        "end": o.timestamp,
                        "source_ids": [o.evidence_id],
                    }
                elif current["attrs"] != attrs:
                    close_era(current)
                    current = {
                        "attrs": attrs,
                        "start": o.timestamp,
                        "end": o.timestamp,
                        "source_ids": [o.evidence_id],
                    }
                else:
                    current["end"] = o.timestamp
                    current["source_ids"].append(o.evidence_id)

            if current is not None:
                close_era(current)

        # Detect overlapping MMSI usage by different vessel candidates.
        by_mmsi: dict[str, list[MMSIUsageEra]] = {}
        for era in mmsi_eras:
            by_mmsi.setdefault(era.mmsi, []).append(era)

        for mmsi, items in by_mmsi.items():
            items.sort(key=lambda x: x.valid_from)
            for i in range(len(items)):
                for j in range(i + 1, len(items)):
                    a = items[i]
                    b = items[j]
                    if a.vessel_id == b.vessel_id:
                        continue
                    max_start = max(a.valid_from, b.valid_from)
                    min_end = min(a.valid_to, b.valid_to)
                    if max_start < min_end:
                        contradictions.append(
                            Contradiction(
                                contradiction_id=new_id("CONTRA"),
                                contradiction_type="MMSI_CONFLICT",
                                description=(
                                    f"MMSI {mmsi} overlaps between vessel candidates "
                                    f"{a.vessel_id} and {b.vessel_id}."
                                ),
                                evidence_ids=unique_list(a.source_ids + b.source_ids),
                                candidate_resolutions=[
                                    "MMSI reassignment",
                                    "duplicate MMSI use",
                                    "provider identity contamination",
                                    "decoding/source error",
                                    "spoofing candidate (requires stronger evidence)",
                                ],
                                status="OPEN",
                            )
                        )

        # Build vessel objects from eras.
        for key, vessel_id in key_to_vessel_id.items():
            vessel_eras = [e for e in identity_eras if e.vessel_id == vessel_id]
            if not vessel_eras:
                continue
            latest = max(vessel_eras, key=lambda e: e.valid_to)
            vessel = Vessel(
                vessel_id=vessel_id,
                current_name=latest.name,
                historical_names=unique_list([e.name for e in vessel_eras]),
                imo=latest.imo,
                call_sign=latest.callsign,
                flag=latest.flag,
                ship_type=latest.ship_type,
                length=latest.length,
                beam=latest.beam,
                registered_owner=None,
                operator=None,
                manager=None,
                technical_manager=None,
                charterer=None,
                fleet=None,
                status="IDENTIFIED_BY_AIS" if latest.imo else "CANDIDATE",
                identity_eras=vessel_eras,
                mmsi_usage_eras=[m for m in mmsi_eras if m.vessel_id == vessel_id],
                source_ids=unique_list([sid for e in vessel_eras for sid in e.source_ids]),
                confidence=latest.confidence,
            )
            vessels.append(vessel)

        return vessels, identity_eras, mmsi_eras, contradictions


# ======================================================================
# SECTION 9 — TRACK RECONSTRUCTION / GAP / IMPOSSIBLE MOVEMENT
# ======================================================================

class TrackBuilder:
    """
    Builds ordered validated track segments.
    Does not interpolate observed positions.
    Marks gaps and impossible movement candidates.
    """

    def __init__(
        self,
        gap_threshold_minutes: float = 120.0,
        max_plausible_speed_kn: float = 60.0,
    ):
        self.gap_threshold_minutes = gap_threshold_minutes
        self.max_plausible_speed_kn = max_plausible_speed_kn

    def build(
        self,
        vessel_id: str,
        observations: list[Observation],
    ) -> tuple[
        list[Observation],
        list[TrackSegment],
        list[AISGap],
        list[Contradiction],
    ]:
        ordered = sorted(
            [o for o in observations if o.timestamp is not None],
            key=lambda x: x.timestamp,
        )

        valid: list[Observation] = []
        contradictions: list[Contradiction] = []

        for o in ordered:
            if o.latitude is None or o.longitude is None:
                continue
            if not coordinate_valid(o.latitude, o.longitude):
                contradictions.append(
                    Contradiction(
                        contradiction_id=new_id("CONTRA"),
                        contradiction_type="POSITION_CONFLICT",
                        description=f"Invalid coordinate in observation {o.observation_id}.",
                        evidence_ids=[o.evidence_id],
                        candidate_resolutions=["bad decoding", "receiver error", "placeholder position"],
                        status="OPEN",
                    )
                )
                continue
            if is_zero_placeholder(o.latitude, o.longitude):
                contradictions.append(
                    Contradiction(
                        contradiction_id=new_id("CONTRA"),
                        contradiction_type="POSITION_CONFLICT",
                        description=f"Zero/default coordinate suspected in observation {o.observation_id}.",
                        evidence_ids=[o.evidence_id],
                        candidate_resolutions=["placeholder value", "manual error", "GNSS invalid"],
                        status="OPEN",
                    )
                )
                continue
            valid.append(o)

        segments: list[TrackSegment] = []
        gaps: list[AISGap] = []

        if not valid:
            return valid, segments, gaps, contradictions

        seg_obs: list[Observation] = [valid[0]]
        prev = valid[0]

        for curr in valid[1:]:
            dt = curr.timestamp - prev.timestamp
            dt_min = dt.total_seconds() / 60.0
            dist = haversine_nm(prev.latitude, prev.longitude, curr.latitude, curr.longitude)
            speed = implied_speed_kn(dist, dt)

            if speed is not None and speed > self.max_plausible_speed_kn:
                curr.quality_flags.append("IMPOSSIBLE_MOVEMENT_FROM_PREV")
                contradictions.append(
                    Contradiction(
                        contradiction_id=new_id("CONTRA"),
                        contradiction_type="POSITION_CONFLICT",
                        description=(
                            f"Implied speed {speed:.1f} kn between observations "
                            f"{prev.observation_id} and {curr.observation_id}."
                        ),
                        evidence_ids=[prev.evidence_id, curr.evidence_id],
                        candidate_resolutions=[
                            "bad position",
                            "duplicate MMSI",
                            "provider timing issue",
                            "identity reassignment",
                            "spoofing candidate (requires stronger evidence)",
                        ],
                        status="OPEN",
                    )
                )

            if dt_min > self.gap_threshold_minutes or (
                speed is not None and speed > self.max_plausible_speed_kn
            ):
                segments.append(self._make_segment(vessel_id, seg_obs))

                if dt_min > self.gap_threshold_minutes:
                    gaps.append(
                        AISGap(
                            gap_id=new_id("GAP"),
                            vessel_id=vessel_id,
                            gap_start=prev.timestamp,
                            gap_end=curr.timestamp,
                            last_pre_observation_id=prev.observation_id,
                            first_post_observation_id=curr.observation_id,
                            duration_minutes=dt_min,
                            distance_nm=dist,
                            implied_speed_kn=speed,
                            coverage_state=CoverageState.COVERAGE_UNKNOWN,
                            possible_causes=[
                                "receiver coverage gap",
                                "satellite collision / revisit limitation",
                                "provider outage or latency",
                                "poor radio propagation",
                                "equipment malfunction",
                                "data filtering",
                                "message corruption",
                                "identity change",
                                "other",
                            ],
                            confidence=Confidence.LOW,
                        )
                    )

                seg_obs = [curr]
            else:
                seg_obs.append(curr)

            prev = curr

        segments.append(self._make_segment(vessel_id, seg_obs))
        return valid, segments, gaps, contradictions

    def _make_segment(self, vessel_id: str, obs: list[Observation]) -> TrackSegment:
        obs = sorted(obs, key=lambda x: x.timestamp)
        distance = 0.0
        has_distance = True
        for a, b in zip(obs, obs[1:]):
            d = haversine_nm(a.latitude, a.longitude, b.latitude, b.longitude)
            if d is None:
                has_distance = False
                break
            distance += d

        total_time = obs[-1].timestamp - obs[0].timestamp if len(obs) > 1 else timedelta(0)
        avg_speed = implied_speed_kn(distance, total_time) if has_distance else None

        gap_flags = []
        for o in obs:
            gap_flags.extend([f for f in o.quality_flags if "IMPOSSIBLE" in f or "INVALID" in f])

        confidence = Confidence.MEDIUM if len(obs) >= 3 and not gap_flags else Confidence.LOW

        return TrackSegment(
            segment_id=new_id("SEG"),
            vessel_id=vessel_id,
            start_time=obs[0].timestamp,
            end_time=obs[-1].timestamp,
            start_latitude=obs[0].latitude,
            start_longitude=obs[0].longitude,
            end_latitude=obs[-1].latitude,
            end_longitude=obs[-1].longitude,
            observation_count=len(obs),
            source_mix=sorted({o.receiver_type.value for o in obs}),
            distance_nm=distance if has_distance else None,
            average_speed_kn=avg_speed,
            confidence=confidence,
            gap_flags=unique_list(gap_flags),
        )


# ======================================================================
# SECTION 10 — PORT CALL ANALYSIS
# ======================================================================

class PortAnalyzer:
    """
    Port geofence analysis.
    Geofence entry alone is not berthing and not cargo operation.
    """

    def __init__(
        self,
        dwell_threshold_minutes: float = 30.0,
        slow_speed_kn: float = 3.0,
    ):
        self.dwell_threshold_minutes = dwell_threshold_minutes
        self.slow_speed_kn = slow_speed_kn

    def analyze(
        self,
        vessel_id: str,
        observations: list[Observation],
        ports: list[Port],
        port_records: Optional[list[dict[str, Any]]] = None,
    ) -> list[PortCall]:
        port_calls: list[PortCall] = []
        port_records = port_records or []
        ordered = sorted(
            [o for o in observations if o.timestamp is not None and o.latitude is not None and o.longitude is not None],
            key=lambda x: x.timestamp,
        )

        for port in ports:
            inside = False
            start: Optional[datetime] = None
            end: Optional[datetime] = None
            evidence_ids: list[str] = []
            speeds: list[float] = []
            source_types: set[SourceType] = set()

            def close_call(departure: Optional[datetime]) -> None:
                nonlocal inside, start, end, evidence_ids, speeds, source_types
                if start is None:
                    return

                dwell = None
                if departure is not None:
                    dwell = (departure - start).total_seconds() / 60.0

                avg_speed = median(speeds) if speeds else None

                if dwell is not None and dwell < self.dwell_threshold_minutes:
                    state = PortCallState.TRANSIT_ONLY
                elif avg_speed is not None and avg_speed > self.slow_speed_kn:
                    state = PortCallState.TRANSIT_ONLY
                else:
                    state = PortCallState.PORT_CALL_CANDIDATE

                if SourceType.PORT_AIS in source_types or SourceType.PORT_AUTHORITY in source_types:
                    state = PortCallState.PORT_CALL_SUPPORTED

                notes = [
                    "Port geofence entry alone does not prove berthing.",
                    "Berthing does not prove cargo operation.",
                ]
                if departure is None:
                    notes.append("Departure not observed within supplied data.")

                pc = PortCall(
                    port_call_id=new_id("PC"),
                    vessel_id=vessel_id,
                    port_id=port.port_id,
                    arrival_time=start,
                    departure_time=departure,
                    dwell_minutes=dwell,
                    average_speed_kn=avg_speed,
                    state=state,
                    evidence_ids=unique_list(evidence_ids),
                    confidence=Confidence.MEDIUM if state != PortCallState.TRANSIT_ONLY else Confidence.LOW,
                    notes=notes,
                )
                port_calls.append(pc)

                inside = False
                start = None
                end = None
                evidence_ids = []
                speeds = []
                source_types = set()

            for o in ordered:
                dist = haversine_nm(o.latitude, o.longitude, port.latitude, port.longitude)
                is_inside = dist is not None and dist <= port.radius_nm

                if is_inside and not inside:
                    inside = True
                    start = o.timestamp
                    end = o.timestamp
                    evidence_ids = [o.evidence_id]
                    speeds = [o.sog] if o.sog is not None else []
                    source_types = {o.receiver_type}
                elif is_inside and inside:
                    end = o.timestamp
                    evidence_ids.append(o.evidence_id)
                    if o.sog is not None:
                        speeds.append(o.sog)
                    source_types.add(o.receiver_type)
                elif not is_inside and inside:
                    close_call(o.timestamp)

            if inside:
                close_call(None)

        # Upgrade using external port records if supplied.
        for pc in port_calls:
            for rec in port_records:
                if rec.get("port_id") != pc.port_id:
                    continue
                if rec.get("vessel_id") not in (None, pc.vessel_id):
                    continue
                rec_arrival = to_datetime(rec.get("arrival_time"))
                rec_departure = to_datetime(rec.get("departure_time"))
                overlap = False
                if rec_arrival and pc.arrival_time and rec_departure and pc.departure_time:
                    overlap = max(rec_arrival, pc.arrival_time) < min(rec_departure, pc.departure_time)
                elif rec_arrival and pc.arrival_time:
                    overlap = abs((rec_arrival - pc.arrival_time).total_seconds()) <= 6 * 3600
                if overlap:
                    pc.state = PortCallState.PORT_CALL_VERIFIED
                    pc.confidence = Confidence.HIGH
                    pc.evidence_ids = unique_list(pc.evidence_ids + [str(rec.get("evidence_id", ""))])
                    pc.notes.append("Matched external port record.")

        return port_calls


# ======================================================================
# SECTION 11 — BEHAVIOR / PROXIMITY / RENDEZVOUS / STS CANDIDATES
# ======================================================================

class BehaviorAnalyzer:
    """
    Detects stationary patterns, proximity events, rendezvous candidates,
    and STS candidates. Proximity is never treated as proof of transfer.
    """

    def __init__(
        self,
        low_speed_kn: float = 2.0,
        anchorage_minutes: float = 60.0,
        loiter_radius_nm: float = 2.0,
        loiter_minutes: float = 120.0,
        proximity_nm: float = 1.0,
        time_window_minutes: float = 30.0,
        rendezvous_minutes: float = 30.0,
        sts_minutes: float = 30.0,
    ):
        self.low_speed_kn = low_speed_kn
        self.anchorage_minutes = anchorage_minutes
        self.loiter_radius_nm = loiter_radius_nm
        self.loiter_minutes = loiter_minutes
        self.proximity_nm = proximity_nm
        self.time_window_minutes = time_window_minutes
        self.rendezvous_minutes = rendezvous_minutes
        self.sts_minutes = sts_minutes

    def detect_stationary_patterns(
        self,
        vessel_id: str,
        observations: list[Observation],
        ports: list[Port],
    ) -> list[dict[str, Any]]:
        ordered = sorted(
            [o for o in observations if o.timestamp is not None and o.latitude is not None and o.longitude is not None],
            key=lambda x: x.timestamp,
        )

        patterns: list[dict[str, Any]] = []
        current: Optional[dict[str, Any]] = None

        def close_current() -> None:
            nonlocal current
            if not current:
                return
            lats = current["lats"]
            lons = current["lons"]
            avg_lat = sum(lats) / len(lats)
            avg_lon = sum(lons) / len(lons)
            duration = (current["end"] - current["start"]).total_seconds() / 60.0
            avg_speed = median(current["speeds"]) if current["speeds"] else None

            outside_ports = True
            for port in ports:
                d = haversine_nm(avg_lat, avg_lon, port.latitude, port.longitude)
                if d is not None and d <= port.radius_nm + 5.0:
                    outside_ports = False
                    break

            labels = []
            if duration >= self.anchorage_minutes:
                labels.append("ANCHORAGE_CANDIDATE")
            if outside_ports and duration >= self.loiter_minutes:
                labels.append("LOITERING_PATTERN")

            if labels:
                patterns.append(
                    {
                        "pattern_id": new_id("STAT"),
                        "vessel_id": vessel_id,
                        "labels": labels,
                        "start_time": current["start"].isoformat(),
                        "end_time": current["end"].isoformat(),
                        "duration_minutes": duration,
                        "average_latitude": avg_lat,
                        "average_longitude": avg_lon,
                        "average_speed_kn": avg_speed,
                        "evidence_ids": unique_list(current["evidence_ids"]),
                        "notes": [
                            "Anchorage candidate does not prove illegal waiting.",
                            "Loitering pattern is descriptive, not motive.",
                        ],
                    }
                )
            current = None

        for o in ordered:
            if o.sog is None or o.sog > self.low_speed_kn:
                close_current()
                continue

            if current is None:
                current = {
                    "start": o.timestamp,
                    "end": o.timestamp,
                    "reference_lat": o.latitude,
                    "reference_lon": o.longitude,
                    "lats": [o.latitude],
                    "lons": [o.longitude],
                    "speeds": [o.sog],
                    "evidence_ids": [o.evidence_id],
                }
                continue

            dist = haversine_nm(current["reference_lat"], current["reference_lon"], o.latitude, o.longitude)
            gap_min = (o.timestamp - current["end"]).total_seconds() / 60.0

            if dist is not None and dist <= self.loiter_radius_nm and gap_min <= 180.0:
                current["end"] = o.timestamp
                current["lats"].append(o.latitude)
                current["lons"].append(o.longitude)
                current["speeds"].append(o.sog)
                current["evidence_ids"].append(o.evidence_id)
            else:
                close_current()
                current = {
                    "start": o.timestamp,
                    "end": o.timestamp,
                    "reference_lat": o.latitude,
                    "reference_lon": o.longitude,
                    "lats": [o.latitude],
                    "lons": [o.longitude],
                    "speeds": [o.sog],
                    "evidence_ids": [o.evidence_id],
                }

        close_current()
        return patterns

    def analyze_pairs(
        self,
        tracks: dict[str, list[Observation]],
        vessels_by_id: dict[str, Vessel],
        ports: list[Port],
        corroborations: Optional[list[dict[str, Any]]] = None,
    ) -> tuple[
        list[ProximityEvent],
        list[RendezvousCandidate],
        list[STSCandidate],
    ]:
        corroborations = corroborations or []
        proximity_events: list[ProximityEvent] = []
        rendezvous_candidates: list[RendezvousCandidate] = []
        sts_candidates: list[STSCandidate] = []

        for (vid_a, track_a), (vid_b, track_b) in itertools.combinations(tracks.items(), 2):
            pairs: list[tuple[datetime, Observation, Observation, float, Optional[float]]] = []

            for oa in track_a:
                if oa.latitude is None or oa.longitude is None:
                    continue
                for ob in track_b:
                    if ob.latitude is None or ob.longitude is None:
                        continue
                    dt_min = abs((oa.timestamp - ob.timestamp).total_seconds()) / 60.0
                    if dt_min > self.time_window_minutes:
                        continue
                    dist = haversine_nm(oa.latitude, oa.longitude, ob.latitude, ob.longitude)
                    if dist is None or dist > self.proximity_nm:
                        continue
                    rel = relative_speed_kn(oa, ob)
                    event_time = max(oa.timestamp, ob.timestamp)
                    pairs.append((event_time, oa, ob, dist, rel))

            pairs.sort(key=lambda x: x[0])

            current: Optional[dict[str, Any]] = None

            def close_event() -> Optional[ProximityEvent]:
                nonlocal current
                if not current:
                    return None
                duration = (current["end"] - current["start"]).total_seconds() / 60.0
                med_rel = median(current["rel_speeds"])
                ev = ProximityEvent(
                    event_id=new_id("PROX"),
                    vessel_a=vid_a,
                    vessel_b=vid_b,
                    start_time=current["start"],
                    end_time=current["end"],
                    minimum_distance_nm=current["min_dist"],
                    median_relative_speed_kn=med_rel,
                    location_latitude=current["min_lat"],
                    location_longitude=current["min_lon"],
                    source_coverage=CoverageState.COVERAGE_UNKNOWN,
                    confidence=Confidence.MEDIUM if duration >= 15 else Confidence.LOW,
                    evidence_ids=unique_list(current["evidence_ids"]),
                )
                current = None
                return ev

            for t, oa, ob, dist, rel in pairs:
                if current is None or (t - current["end"]).total_seconds() / 60.0 > self.time_window_minutes:
                    ev = close_event()
                    if ev:
                        proximity_events.append(ev)
                    current = {
                        "start": t,
                        "end": t,
                        "min_dist": dist,
                        "min_lat": oa.latitude,
                        "min_lon": oa.longitude,
                        "rel_speeds": [rel] if rel is not None else [],
                        "evidence_ids": [oa.evidence_id, ob.evidence_id],
                    }
                else:
                    current["end"] = t
                    if dist < current["min_dist"]:
                        current["min_dist"] = dist
                        current["min_lat"] = oa.latitude
                        current["min_lon"] = oa.longitude
                    if rel is not None:
                        current["rel_speeds"].append(rel)
                    current["evidence_ids"].extend([oa.evidence_id, ob.evidence_id])

            ev = close_event()
            if ev:
                proximity_events.append(ev)

            # Build rendezvous and STS candidates from proximity events.
            for ev in [e for e in proximity_events if e.vessel_a == vid_a and e.vessel_b == vid_b]:
                duration = (ev.end_time - ev.start_time).total_seconds() / 60.0
                med_rel = ev.median_relative_speed_kn

                rd_status = "PROXIMITY_ONLY"
                if (
                    duration >= self.rendezvous_minutes
                    and med_rel is not None
                    and med_rel <= 3.0
                    and ev.minimum_distance_nm is not None
                    and ev.minimum_distance_nm <= 0.5
                ):
                    rd_status = "RENDEZVOUS_CANDIDATE"

                rd = RendezvousCandidate(
                    candidate_id=new_id("RDV"),
                    vessel_a=vid_a,
                    vessel_b=vid_b,
                    proximity_event_id=ev.event_id,
                    status=rd_status,
                    alternative_explanations=[
                        "normal anchorage proximity",
                        "pilot transfer",
                        "crew transfer",
                        "bunkering",
                        "tug assistance",
                        "shared traffic lane",
                        "coincidental route",
                        "STS transfer (unverified)",
                    ],
                    evidence_ids=ev.evidence_ids,
                    confidence=ev.confidence,
                )
                rendezvous_candidates.append(rd)

                vessel_a = vessels_by_id.get(vid_a)
                vessel_b = vessels_by_id.get(vid_b)
                compatible = self._compatible_sts_types(
                    vessel_a.ship_type if vessel_a else None,
                    vessel_b.ship_type if vessel_b else None,
                )
                offshore = self._is_offshore(ev.location_latitude, ev.location_longitude, ports)

                factors: list[str] = []
                if compatible:
                    factors.append("compatible vessel types")
                if offshore:
                    factors.append("offshore location")
                if duration >= 60.0:
                    factors.append("extended duration")
                if med_rel is not None and med_rel <= 2.0:
                    factors.append("low relative speed")
                if ev.minimum_distance_nm is not None and ev.minimum_distance_nm <= 0.25:
                    factors.append("very close minimum distance")

                draught_a = self._draught_change(track_a, ev.start_time, ev.end_time)
                draught_b = self._draught_change(track_b, ev.start_time, ev.end_time)
                if draught_a:
                    factors.append("draught change candidate on vessel A")
                if draught_b:
                    factors.append("draught change candidate on vessel B")

                corr_factors = self._match_corroborations(
                    corroborations,
                    vid_a,
                    vid_b,
                    ev,
                )
                factors.extend(corr_factors)

                missing = [
                    "independent satellite imagery",
                    "port/terminal record",
                    "trade/manifest record",
                    "confirmed draught change corroboration",
                ]
                if draught_a or draught_b:
                    missing = [m for m in missing if "draught" not in m.lower()]
                if corr_factors:
                    missing = [m for m in missing if not any(c.split()[0].lower() in m.lower() for c in corr_factors)]

                if rd_status != "RENDEZVOUS_CANDIDATE":
                    sts_status = STSStatus.PROXIMITY_ONLY
                elif compatible and offshore and duration >= self.sts_minutes and med_rel is not None and med_rel <= 2.0:
                    if (draught_a or draught_b or corr_factors) and duration >= 60.0:
                        sts_status = STSStatus.STS_SUPPORTED
                    else:
                        sts_status = STSStatus.STS_CANDIDATE
                else:
                    sts_status = STSStatus.PROXIMITY_ONLY

                sts = STSCandidate(
                    sts_id=new_id("STS"),
                    vessel_a=vid_a,
                    vessel_b=vid_b,
                    proximity_event_id=ev.event_id,
                    status=sts_status,
                    supporting_factors=factors,
                    missing_corroboration=missing,
                    evidence_ids=ev.evidence_ids,
                    confidence=Confidence.MEDIUM if sts_status != STSStatus.PROXIMITY_ONLY else Confidence.LOW,
                )
                sts_candidates.append(sts)

        return proximity_events, rendezvous_candidates, sts_candidates

    @staticmethod
    def _compatible_sts_types(type_a: Optional[int], type_b: Optional[int]) -> bool:
        # Conservative: cargo/tanker ranges.
        def ok(t: Optional[int]) -> bool:
            return t is not None and 70 <= t <= 89
        return ok(type_a) and ok(type_b)

    @staticmethod
    def _is_offshore(lat: Optional[float], lon: Optional[float], ports: list[Port]) -> bool:
        if lat is None or lon is None:
            return False
        if not ports:
            return False
        for port in ports:
            d = haversine_nm(lat, lon, port.latitude, port.longitude)
            if d is not None and d <= port.radius_nm + 5.0:
                return False
        return True

    @staticmethod
    def _draught_change(
        track: list[Observation],
        start: datetime,
        end: datetime,
        threshold_m: float = 0.5,
    ) -> bool:
        before = [o.draught for o in track if o.timestamp < start and o.draught is not None]
        after = [
            o.draught
            for o in track
            if end <= o.timestamp <= end + timedelta(hours=6) and o.draught is not None
        ]
        if not before or not after:
            return False
        return abs(max(after) - min(before)) >= threshold_m

    @staticmethod
    def _match_corroborations(
        corroborations: list[dict[str, Any]],
        vid_a: str,
        vid_b: str,
        event: ProximityEvent,
    ) -> list[str]:
        matched: list[str] = []
        vessels_needed = {vid_a, vid_b}
        for c in corroborations:
            c_vessels = set(c.get("vessels", []))
            if not vessels_needed.issubset(c_vessels):
                continue
            c_time = to_datetime(c.get("timestamp"))
            if c_time is None:
                continue
            if abs((c_time - event.start_time).total_seconds()) > 120 * 60:
                continue
            c_lat = safe_float(c.get("latitude"))
            c_lon = safe_float(c.get("longitude"))
            d = haversine_nm(event.location_latitude, event.location_longitude, c_lat, c_lon)
            if d is not None and d > 5.0:
                continue
            ctype = str(c.get("type", "CORROBORATION")).upper()
            matched.append(f"{ctype.lower()} corroboration")
        return unique_list(matched)


# ======================================================================
# SECTION 12 — SPOOFING INDICATOR ANALYSIS (DEFENSIVE ONLY)
# ======================================================================

class SpoofingIndicatorAnalyzer:
    """
    Defensive indicator analysis only.
    Does not provide spoofing methods.
    """

    def analyze(
        self,
        contradictions: list[Contradiction],
        source_independence: dict[str, Any],
    ) -> tuple[SpoofingConfidence, list[str]]:
        indicators: list[str] = []
        for c in contradictions:
            if c.contradiction_type == "MMSI_CONFLICT":
                indicators.append("MMSI conflict / possible reuse or duplication")
            elif c.contradiction_type == "POSITION_CONFLICT":
                indicators.append("position conflict / implausible movement candidate")

        indicators = unique_list(indicators)
        if not indicators:
            return SpoofingConfidence.NO_SPOOFING_EVIDENCE, []

        independence_status = source_independence.get("status", "UNKNOWN")
        if independence_status in ("DEPENDENT", "UNKNOWN") and len(indicators) < 2:
            return SpoofingConfidence.INCONCLUSIVE, indicators

        if len(indicators) == 1:
            return SpoofingConfidence.ANOMALOUS, indicators

        # Even multiple anomalies are not confirmed spoofing without independent corroboration.
        return SpoofingConfidence.POSSIBLE_SPOOFING, indicators


# ======================================================================
# SECTION 13 — FACT GATE / HYPOTHESES / NEXT ACTIONS
# ======================================================================

class FactGate:
    """
    Converts observations and analyses into evidence-linked facts,
    candidate facts, hypotheses, unknowns, knowledge gaps, and next actions.
    """

    def generate(
        self,
        *,
        case: dict[str, Any],
        observations: list[Observation],
        vessels: list[Vessel],
        segments: list[TrackSegment],
        gaps: list[AISGap],
        port_calls: list[PortCall],
        proximity_events: list[ProximityEvent],
        rendezvous_candidates: list[RendezvousCandidate],
        sts_candidates: list[STSCandidate],
        stationary_patterns: list[dict[str, Any]],
        contradictions: list[Contradiction],
        spoofing_confidence: SpoofingConfidence,
        spoofing_indicators: list[str],
        source_independence: dict[str, Any],
    ) -> dict[str, Any]:
        facts: list[Fact] = []
        hypotheses: list[Hypothesis] = []
        unknowns: list[str] = []
        limitations: list[str] = []
        knowledge_gaps: list[KnowledgeGap] = []
        next_actions: list[NextAction] = []
        handoffs: list[SpecialistHandoff] = []

        # Observation-level facts: source recorded an observation.
        for o in observations[:200]:
            facts.append(
                Fact(
                    fact_id=new_id("FACT"),
                    statement=(
                        f"Source {o.source_id} ({o.receiver_type.value}) recorded an AIS observation "
                        f"for MMSI {o.mmsi or 'unknown'} / IMO {o.imo_candidate or 'unknown'} "
                        f"at {o.latitude},{o.longitude} on {o.timestamp.isoformat()}."
                    ),
                    status=FactStatus.FACT,
                    evidence_ids=[o.evidence_id],
                    limitations=[
                        "This is a sensor/provider record, not independent ground truth.",
                        "Position may contain GNSS/receiver/provider error.",
                    ],
                )
            )

        # Identity facts.
        for v in vessels:
            if v.imo and validate_imo(v.imo)[0]:
                facts.append(
                    Fact(
                        fact_id=new_id("FACT"),
                        statement=(
                            f"Identifier evidence supports vessel candidate {v.vessel_id} with IMO {v.imo} "
                            f"during the relevant observation era."
                        ),
                        status=FactStatus.SUPPORTED,
                        evidence_ids=v.source_ids,
                        limitations=[
                            "IMO is strong but still requires registry/source validation.",
                            "Ownership/operator are not resolved by AIS alone.",
                        ],
                    )
                )
            else:
                facts.append(
                    Fact(
                        fact_id=new_id("FACT"),
                        statement=(
                            f"Vessel candidate {v.vessel_id} is unresolved; identity based only on "
                            f"available MMSI/name/static fields."
                        ),
                        status=FactStatus.CANDIDATE,
                        evidence_ids=v.source_ids,
                        limitations=["Do not treat MMSI as permanent vessel identity."],
                    )
                )
                knowledge_gaps.append(
                    KnowledgeGap(
                        gap_id=new_id("KG"),
                        description=f"Vessel identity unresolved for {v.vessel_id}.",
                        importance="HIGH",
                        recommended_source="official registry / IMO record / historical MMSI usage",
                        specialist="CORPINT / registry verification",
                        expected_information_value="Prevents historical identity contamination.",
                    )
                )

        # Track segment facts.
        for seg in segments:
            if seg.distance_nm is not None:
                status = FactStatus.SUPPORTED if seg.confidence != Confidence.LOW else FactStatus.CANDIDATE
                facts.append(
                    Fact(
                        fact_id=new_id("FACT"),
                        statement=(
                            f"AIS track segment for {seg.vessel_id} from {seg.start_time.isoformat()} "
                            f"to {seg.end_time.isoformat()} includes {seg.observation_count} observations "
                            f"and covers approximately {seg.distance_nm:.1f} nm."
                        ),
                        status=status,
                        evidence_ids=[],
                        limitations=[
                            "Only observed points are included.",
                            "No interpolated position is asserted as observed evidence.",
                        ],
                    )
                )

        # Gap facts and hypotheses.
        for g in gaps:
            facts.append(
                Fact(
                    fact_id=new_id("FACT"),
                    statement=(
                        f"No ingested AIS observations are available for {g.vessel_id} between "
                        f"{g.gap_start.isoformat()} and {g.gap_end.isoformat()} "
                        f"(duration {g.duration_minutes:.0f} minutes)."
                    ),
                    status=FactStatus.FACT,
                    evidence_ids=[],
                    limitations=[
                        "Absence of observations is not evidence of intentional shutdown.",
                        "Coverage during the interval is not established from supplied data alone.",
                    ],
                )
            )

            hypotheses.extend(
                [
                    Hypothesis(
                        hypothesis_id=new_id("HYP"),
                        statement="AIS gap is ordinary terrestrial/satellite coverage loss.",
                        supports=["Coverage state unknown", "No independent sensor corroboration supplied"],
                        oppositions=[],
                        unknowns=["Receiver coverage map", "Satellite revisit windows"],
                        falsification_tests=["Independent provider shows observations during gap"],
                    ),
                    Hypothesis(
                        hypothesis_id=new_id("HYP"),
                        statement="Provider outage, filtering, or latency explains the gap.",
                        supports=["Single-source dependency possible"],
                        oppositions=[],
                        unknowns=["Provider health logs"],
                        falsification_tests=["Other independent providers also lack data"],
                    ),
                    Hypothesis(
                        hypothesis_id=new_id("HYP"),
                        statement="Equipment malfunction or power/GNSS issue explains the gap.",
                        supports=[],
                        oppositions=["No maintenance/incident record supplied"],
                        unknowns=["Vessel technical status"],
                        falsification_tests=["Normal transmissions resume without positional conflict"],
                    ),
                    Hypothesis(
                        hypothesis_id=new_id("HYP"),
                        statement="Transponder was deliberately disabled.",
                        supports=[],
                        oppositions=["AIS silence alone is not maliciousness", "Coverage unknown"],
                        unknowns=["Authorized onboard/terminal evidence"],
                        falsification_tests=["Independent sensor shows vessel transmitting or present"],
                    ),
                ]
            )

            knowledge_gaps.append(
                KnowledgeGap(
                    gap_id=new_id("KG"),
                    description=f"AIS coverage during gap for {g.vessel_id} is unknown.",
                    importance="HIGH",
                    recommended_source="independent AIS provider / coverage model / satellite pass data",
                    specialist="AISINT coverage assessment",
                    expected_information_value="Prevents false deliberate-AIS-off claims.",
                )
            )
            next_actions.append(
                NextAction(
                    action_id=new_id("ACT"),
                    description="Retrieve independent AIS provider coverage for the gap interval.",
                    rationale="Distinguish coverage loss from transmission absence.",
                    priority="HIGH",
                )
            )

        # Port call facts.
        for pc in port_calls:
            if pc.state == PortCallState.PORT_CALL_VERIFIED:
                status = FactStatus.SUPPORTED
            elif pc.state == PortCallState.PORT_CALL_SUPPORTED:
                status = FactStatus.SUPPORTED
            elif pc.state == PortCallState.PORT_CALL_CANDIDATE:
                status = FactStatus.CANDIDATE
            else:
                status = FactStatus.UNKNOWN

            facts.append(
                Fact(
                    fact_id=new_id("FACT"),
                    statement=(
                        f"Port call {pc.state.value} for vessel {pc.vessel_id} at port {pc.port_id} "
                        f"around {pc.arrival_time.isoformat() if pc.arrival_time else 'unknown'}."
                    ),
                    status=status,
                    evidence_ids=pc.evidence_ids,
                    limitations=[
                        "Geofence entry alone does not prove berthing.",
                        "Berthing does not prove cargo loading/unloading.",
                    ],
                )
            )
            if pc.state == PortCallState.PORT_CALL_CANDIDATE:
                next_actions.append(
                    NextAction(
                        action_id=new_id("ACT"),
                        description=f"Verify port record for {pc.port_id} and vessel {pc.vessel_id}.",
                        rationale="Upgrade candidate port call to supported/verified.",
                        priority="MEDIUM",
                    )
                )

        # Stationary pattern facts.
        for sp in stationary_patterns:
            facts.append(
                Fact(
                    fact_id=new_id("FACT"),
                    statement=(
                        f"Stationary pattern {', '.join(sp['labels'])} detected for {sp['vessel_id']} "
                        f"from {sp['start_time']} to {sp['end_time']}."
                    ),
                    status=FactStatus.CANDIDATE,
                    evidence_ids=sp.get("evidence_ids", []),
                    limitations=[
                        "Anchorage/loitering labels are behavioral descriptions, not intent.",
                    ],
                )
            )

        # Rendezvous / STS facts.
        for rd in rendezvous_candidates:
            facts.append(
                Fact(
                    fact_id=new_id("FACT"),
                    statement=(
                        f"Rendezvous candidate between {rd.vessel_a} and {rd.vessel_b} "
                        f"with status {rd.status}."
                    ),
                    status=FactStatus.CANDIDATE,
                    evidence_ids=rd.evidence_ids,
                    limitations=[
                        "Proximity does not prove rendezvous coordination.",
                        "Rendezvous does not prove transfer.",
                    ],
                )
            )

        for st in sts_candidates:
            status = FactStatus.SUPPORTED if st.status == STSStatus.STS_SUPPORTED else FactStatus.CANDIDATE
            facts.append(
                Fact(
                    fact_id=new_id("FACT"),
                    statement=(
                        f"STS assessment between {st.vessel_a} and {st.vessel_b}: {st.status.value}."
                    ),
                    status=status,
                    evidence_ids=st.evidence_ids,
                    limitations=[
                        "STS is a normal maritime operation in many contexts.",
                        "STS candidate is not evidence of illegality.",
                    ],
                )
            )
            handoffs.append(
                SpecialistHandoff(
                    handoff_id=new_id("HAND"),
                    specialist="SATINT / IMINT",
                    reason="Correlate independent satellite imagery for proximity/STS context.",
                    payload={
                        "vessels": [st.vessel_a, st.vessel_b],
                        "proximity_event_id": st.proximity_event_id,
                        "status": st.status.value,
                    },
                )
            )
            handoffs.append(
                SpecialistHandoff(
                    handoff_id=new_id("HAND"),
                    specialist="TRADEINT",
                    reason="Cargo/shipment context cannot be inferred from AIS alone.",
                    payload={
                        "vessels": [st.vessel_a, st.vessel_b],
                        "question": "Were goods transferred, and under what commercial arrangement?",
                    },
                )
            )

        # Contradictions.
        for c in contradictions:
            facts.append(
                Fact(
                    fact_id=new_id("FACT"),
                    statement=f"Open contradiction: {c.contradiction_type} — {c.description}",
                    status=FactStatus.DISPUTED,
                    evidence_ids=c.evidence_ids,
                    limitations=c.candidate_resolutions,
                )
            )
            unknowns.append(f"Unresolved contradiction: {c.contradiction_type}")

        # Spoofing indicators.
        if spoofing_confidence != SpoofingConfidence.NO_SPOOFING_EVIDENCE:
            facts.append(
                Fact(
                    fact_id=new_id("FACT"),
                    statement=(
                        f"AIS spoofing indicator assessment: {spoofing_confidence.value}. "
                        f"Indicators: {', '.join(spoofing_indicators) or 'none'}."
                    ),
                    status=FactStatus.CANDIDATE,
                    evidence_ids=[],
                    limitations=[
                        "One anomaly is not confirmed spoofing.",
                        "No spoofing methodology is provided.",
                    ],
                )
            )

        # Source independence.
        if source_independence.get("status") in ("DEPENDENT", "PARTIALLY_DEPENDENT", "UNKNOWN"):
            limitations.append(
                "Source independence is not fully established; multiple views may share upstream AIS provider."
            )
            knowledge_gaps.append(
                KnowledgeGap(
                    gap_id=new_id("KG"),
                    description="Independent source pedigree not established.",
                    importance="HIGH",
                    recommended_source="direct receiver feeds / independent satellite AIS provider",
                    specialist="AISINT source evaluation",
                    expected_information_value="Prevents confidence inflation from duplicated feeds.",
                )
            )

        # Universal limitations / unknowns.
        limitations.extend(
            [
                "AIS is not ground truth.",
                "Destination, ETA, draught, and some navigation status fields may be manually configured.",
                "Vessel movement does not prove cargo, payment, ownership, or legal violation.",
                "No legal conclusion is made.",
            ]
        )
        unknowns.extend(
            [
                "Exact cargo identity",
                "Ultimate beneficial owner",
                "Actual destination versus reported destination",
                "Reason for AIS gap",
                "Whether any physical transfer occurred",
            ]
        )

        # Generic next actions.
        next_actions.extend(
            [
                NextAction(
                    action_id=new_id("ACT"),
                    description="Verify IMO in official registry where authorized.",
                    rationale="Strengthens vessel identity resolution.",
                    priority="HIGH",
                ),
                NextAction(
                    action_id=new_id("ACT"),
                    description="Check historical MMSI usage to prevent identity contamination.",
                    rationale="MMSI is not permanent vessel identity.",
                    priority="HIGH",
                ),
                NextAction(
                    action_id=new_id("ACT"),
                    description="Resolve registered owner / operator / manager via CORPINT.",
                    rationale="AIS does not prove corporate control.",
                    priority="MEDIUM",
                ),
                NextAction(
                    action_id=new_id("ACT"),
                    description="Evaluate coverage before making any AIS-gap behavior conclusion.",
                    rationale="Avoid false deliberate-AIS-off claims.",
                    priority="HIGH",
                ),
            ]
        )

        # Safety filter for next actions.
        guard = PolicyGuard()
        next_actions = [a for a in next_actions if guard.is_safe_action(a.description)]

        return {
            "facts": facts,
            "hypotheses": hypotheses,
            "unknowns": unique_list(unknowns),
            "limitations": unique_list(limitations),
            "knowledge_gaps": knowledge_gaps,
            "next_actions": next_actions,
            "specialist_handoffs": handoffs,
        }


# ======================================================================
# SECTION 14 — DUAL-AI / SKEPTIC REVIEW
# ======================================================================

class DualAIReviewer:
    """
    Lightweight deterministic skeptic checks.
    In production, Pass 1 / Pass 2 can be separate model calls with restricted context.
    AI agreement is not sensor corroboration.
    """

    def review(
        self,
        *,
        facts: list[Fact],
        gaps: list[AISGap],
        sts_candidates: list[STSCandidate],
        source_independence: dict[str, Any],
        vessels: list[Vessel],
        contradictions: list[Contradiction],
    ) -> dict[str, Any]:
        notes: list[str] = []
        status = ReviewStatus.AGREE

        if any(g.coverage_state == CoverageState.COVERAGE_UNKNOWN for g in gaps):
            notes.append("Coverage unknown during AIS gap; do not infer deliberate AIS disablement.")

        for st in sts_candidates:
            if st.status == STSStatus.STS_SUPPORTED:
                if not any("corroboration" in f or "draught" in f for f in st.supporting_factors):
                    notes.append("STS marked supported without draught/external corroboration; downgrade recommended.")
                    status = ReviewStatus.DISAGREE

        if source_independence.get("status") in ("DEPENDENT", "UNKNOWN"):
            notes.append("Source dependence/unknown independence; confidence should not be inflated.")
            if status == ReviewStatus.AGREE:
                status = ReviewStatus.PARTIAL_AGREEMENT

        if any(v.confidence == Confidence.LOW for v in vessels):
            notes.append("At least one vessel identity is low confidence.")
            if status == ReviewStatus.AGREE:
                status = ReviewStatus.PARTIAL_AGREEMENT

        if contradictions:
            notes.append("Open contradictions remain; final attribution should be deferred.")
            if status == ReviewStatus.AGREE:
                status = ReviewStatus.PARTIAL_AGREEMENT

        if not facts:
            status = ReviewStatus.INSUFFICIENT_EVIDENCE
            notes.append("No facts generated.")

        return {
            "status": status.value,
            "skeptic_notes": notes,
            "rule": "AI agreement is not independent sensor corroboration.",
            "human_review_required": bool(
                contradictions
                or any(st.status == STSStatus.STS_SUPPORTED for st in sts_candidates)
                or any(v.confidence == Confidence.LOW for v in vessels)
            ),
        }


# ======================================================================
# SECTION 15 — GRAPHICAL MEMORY
# ======================================================================

class GraphicalMemory:
    """
    Minimal in-memory temporal maritime graph.
    Production version can persist to Neo4j / Neptune / TigerGraph / SQL graph store.
    """

    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: list[dict[str, Any]] = []

    def add_node(self, node_id: str, node_type: str, properties: dict[str, Any]) -> None:
        self.nodes[node_id] = {"type": node_type, "properties": properties}

    def add_edge(
        self,
        source_id: str,
        relation: str,
        target_id: str,
        properties: Optional[dict[str, Any]] = None,
    ) -> None:
        self.edges.append(
            {
                "source_id": source_id,
                "relation": relation,
                "target_id": target_id,
                "properties": properties or {},
            }
        )

    def write_result(self, result: AISINTResult) -> dict[str, Any]:
        for v in result.vessels:
            self.add_node(
                v.vessel_id,
                "Vessel",
                {
                    "current_name": v.current_name,
                    "imo": v.imo,
                    "call_sign": v.call_sign,
                    "confidence": v.confidence.value,
                },
            )

        for era in result.vessel_identity_eras:
            node_id = f"ERA_{era.vessel_id}_{era.valid_from.isoformat()}_{era.valid_to.isoformat()}"
            self.add_node(
                node_id,
                "VesselIdentityEra",
                {
                    "vessel_id": era.vessel_id,
                    "name": era.name,
                    "mmsi": era.mmsi,
                    "imo": era.imo,
                    "valid_from": era.valid_from.isoformat(),
                    "valid_to": era.valid_to.isoformat(),
                },
            )
            self.add_edge(era.vessel_id, "HAS_IDENTITY_ERA", node_id)

        for m in result.mmsi_usage_eras:
            node_id = f"MMSI_{m.mmsi}_{m.valid_from.isoformat()}_{m.valid_to.isoformat()}"
            self.add_node(
                node_id,
                "MMSIUsageEra",
                {
                    "mmsi": m.mmsi,
                    "vessel_id": m.vessel_id,
                    "valid_from": m.valid_from.isoformat(),
                    "valid_to": m.valid_to.isoformat(),
                },
            )
            self.add_edge(m.vessel_id, "USED_MMSI_DURING", node_id)

        for o in result.observations[:500]:
            node_id = o.observation_id
            self.add_node(
                node_id,
                "AISObservation",
                {
                    "vessel_candidate_id": o.vessel_candidate_id,
                    "timestamp": o.timestamp.isoformat(),
                    "latitude": o.latitude,
                    "longitude": o.longitude,
                    "source_id": o.source_id,
                    "receiver_type": o.receiver_type.value,
                },
            )
            self.add_edge(o.vessel_candidate_id, "OBSERVED_AT", node_id, {"evidence_id": o.evidence_id})

        for g in result.ais_gaps:
            node_id = g.gap_id
            self.add_node(
                node_id,
                "AISGap",
                {
                    "vessel_id": g.vessel_id,
                    "gap_start": g.gap_start.isoformat(),
                    "gap_end": g.gap_end.isoformat(),
                    "coverage_state": g.coverage_state.value,
                },
            )
            self.add_edge(g.vessel_id, "HAS_GAP", node_id)

        for st in result.sts_candidates:
            node_id = st.sts_id
            self.add_node(
                node_id,
                "STSCandidate",
                {
                    "vessel_a": st.vessel_a,
                    "vessel_b": st.vessel_b,
                    "status": st.status.value,
                    "supporting_factors": st.supporting_factors,
                },
            )
            self.add_edge(st.vessel_a, "STS_WITH_CANDIDATE", st.vessel_b, {"sts_id": node_id})

        for f in result.facts[:500]:
            node_id = f.fact_id
            self.add_node(
                node_id,
                "Fact",
                {
                    "statement": f.statement,
                    "status": f.status.value,
                    "limitations": f.limitations,
                },
            )
            for ev in f.evidence_ids[:20]:
                self.add_edge(node_id, "SUPPORTED_BY", ev)

        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "sample_nodes": list(self.nodes.keys())[:20],
        }


# ======================================================================
# SECTION 16 — REPORT GENERATOR
# ======================================================================

class ReportGenerator:
    def generate(self, result: AISINTResult) -> str:
        latest_obs: Optional[Observation] = None
        if result.observations:
            latest_obs = max(result.observations, key=lambda o: o.timestamp)

        lines: list[str] = []
        lines.append("=" * 72)
        lines.append("TRACEATLAS — AISINT REPORT")
        lines.append("=" * 72)
        lines.append(f"Case ID: {result.case_id}")
        lines.append(f"Task ID: {result.task_id}")
        lines.append(f"Objective: {result.objective}")
        lines.append(f"Status: {result.status}")
        lines.append(f"Policy Decision: {result.policy_decision.value}")
        lines.append("")
        lines.append("SAFETY / PRIVACY BOUNDARY")
        lines.append("- Lawful maritime safety / compliance / investigative analysis only.")
        lines.append("- No targeting, interception, AIS manipulation, spoofing, jamming, or evasion planning.")
        if result.privacy_flags:
            for p in result.privacy_flags:
                lines.append(f"- Privacy: {p}")
        lines.append("")

        lines.append("VESSEL IDENTITY")
        if not result.vessels:
            lines.append("- No vessel identity resolved from supplied observations.")
        for v in result.vessels:
            lines.append(f"- Vessel: {v.vessel_id}")
            lines.append(f"  IMO: {v.imo or 'UNKNOWN'}")
            lines.append(f"  Current Name: {v.current_name or 'UNKNOWN'}")
            lines.append(f"  Historical Names: {', '.join(v.historical_names) or 'NONE'}")
            lines.append(f"  Call Sign: {v.call_sign or 'UNKNOWN'}")
            lines.append(f"  MMSI Usage Eras: {len(v.mmsi_usage_eras)}")
            lines.append(f"  Ship Type: {v.ship_type if v.ship_type is not None else 'UNKNOWN'}")
            lines.append(f"  Length / Beam: {v.length} / {v.beam}")
            lines.append(f"  Registered Owner: {v.registered_owner or 'UNKNOWN — handoff CORPINT'}")
            lines.append(f"  Operator / Manager: {v.operator or 'UNKNOWN'} / {v.manager or 'UNKNOWN'}")
            lines.append(f"  Identity Confidence: {v.confidence.value}")
        lines.append("")

        lines.append("LATEST VERIFIED OBSERVATION")
        if latest_obs:
            lines.append(f"- Timestamp: {latest_obs.timestamp.isoformat()}")
            lines.append(f"- Source: {latest_obs.source_id} ({latest_obs.receiver_type.value})")
            lines.append(f"- Position: {latest_obs.latitude}, {latest_obs.longitude}")
            lines.append(f"- MMSI: {latest_obs.mmsi or 'UNKNOWN'}")
            lines.append(f"- IMO: {latest_obs.imo_candidate or 'UNKNOWN'}")
            lines.append("- Caution: latest observed by provider, not necessarily exact present position.")
        else:
            lines.append("- None.")
        lines.append("")

        lines.append("TRACK / VOYAGE")
        if result.track_segments:
            for seg in result.track_segments[:20]:
                lines.append(
                    f"- Segment {seg.segment_id}: {seg.start_time.isoformat()} -> {seg.end_time.isoformat()}, "
                    f"{seg.observation_count} obs, distance {seg.distance_nm if seg.distance_nm is not None else 'NA'} nm, "
                    f"avg speed {seg.average_speed_kn if seg.average_speed_kn is not None else 'NA'} kn, "
                    f"confidence {seg.confidence.value}."
                )
        else:
            lines.append("- No validated track segments.")
        lines.append("")

        lines.append("REPORTED DESTINATION / ETA")
        dest_obs = [o for o in result.observations if o.destination or o.eta]
        if dest_obs:
            for o in dest_obs[-10:]:
                lines.append(
                    f"- {o.timestamp.isoformat()}: destination={o.destination or 'NONE'}, "
                    f"eta={o.eta.isoformat() if o.eta else 'NONE'} "
                    "(vessel-reported/manual field, not independent confirmation)."
                )
        else:
            lines.append("- None supplied.")
        lines.append("")

        lines.append("PORT CALLS")
        if result.port_calls:
            for pc in result.port_calls:
                lines.append(
                    f"- {pc.port_id}: state={pc.state.value}, arrival={pc.arrival_time}, "
                    f"departure={pc.departure_time}, dwell_min={pc.dwell_minutes}, "
                    f"confidence={pc.confidence.value}."
                )
        else:
            lines.append("- None.")
        lines.append("")

        lines.append("AIS GAPS / COVERAGE")
        if result.ais_gaps:
            for g in result.ais_gaps:
                lines.append(
                    f"- Gap {g.gap_id}: {g.gap_start.isoformat()} -> {g.gap_end.isoformat()}, "
                    f"duration={g.duration_minutes:.0f} min, coverage={g.coverage_state.value}."
                )
                lines.append("  Assessment: DELIBERATE_AIS_DISABLEMENT is NOT established.")
        else:
            lines.append("- No AIS gaps detected in supplied observations.")
        lines.append("")

        lines.append("IDENTITY / POSITION ANOMALIES")
        if result.contradictions:
            for c in result.contradictions[:20]:
                lines.append(f"- {c.contradiction_type}: {c.description}")
        else:
            lines.append("- None detected.")
        lines.append("")

        lines.append("SPOOFING INDICATORS")
        lines.append(f"- Confidence: {result.spoofing_confidence.value}")
        if result.spoofing_indicators:
            lines.append(f"- Indicators: {', '.join(result.spoofing_indicators)}")
        lines.append("- Defensive analysis only. No spoofing methodology is provided.")
        lines.append("")

        lines.append("RENDEZVOUS / STS STATUS")
        if result.rendezvous_candidates:
            for rd in result.rendezvous_candidates:
                lines.append(f"- Rendezvous: {rd.vessel_a} <-> {rd.vessel_b}, status={rd.status}.")
        else:
            lines.append("- No rendezvous candidates.")
        if result.sts_candidates:
            for st in result.sts_candidates:
                lines.append(
                    f"- STS: {st.vessel_a} <-> {st.vessel_b}, status={st.status.value}, "
                    f"factors={st.supporting_factors}, missing={st.missing_corroboration}."
                )
                lines.append("  Caution: proximity alone does not establish cargo transfer.")
        else:
            lines.append("- No STS candidates.")
        lines.append("")

        lines.append("SOURCE RELIABILITY / INDEPENDENCE")
        lines.append(f"- Source independence: {result.source_independence.get('status', 'UNKNOWN')}")
        for note in result.source_independence.get("notes", []):
            lines.append(f"  - {note}")
        lines.append("")

        lines.append("CONTRADICTIONS / HYPOTHESES")
        if result.hypotheses:
            for h in result.hypotheses[:20]:
                lines.append(f"- {h.hypothesis_id}: {h.statement} [{h.status}]")
        else:
            lines.append("- None.")
        lines.append("")

        lines.append("UNKNOWN / KNOWLEDGE GAPS")
        for u in result.unknowns[:30]:
            lines.append(f"- Unknown: {u}")
        for kg in result.knowledge_gaps[:30]:
            lines.append(f"- Gap: {kg.description} | importance={kg.importance} | specialist={kg.specialist}")
        lines.append("")

        lines.append("NEXT ACTIONS")
        if result.next_actions:
            for a in result.next_actions:
                lines.append(f"- {a.description} ({a.priority}) — {a.rationale}")
        else:
            lines.append("- None.")
        lines.append("")

        lines.append("SPECIALIST HANDOFFS")
        if result.specialist_handoffs:
            for h in result.specialist_handoffs:
                lines.append(f"- {h.specialist}: {h.reason}")
        else:
            lines.append("- None.")
        lines.append("")

        lines.append("LIMITATIONS")
        for lim in result.limitations:
            lines.append(f"- {lim}")
        lines.append("")

        lines.append("REVIEW")
        lines.append(f"- Dual-AI status: {result.review.get('status', 'N/A')}")
        for note in result.review.get("skeptic_notes", []):
            lines.append(f"  - {note}")
        if result.review.get("human_review_required"):
            lines.append("  - Human review required before consequential compliance/enforcement action.")
        lines.append("")

        lines.append("=" * 72)
        lines.append("END REPORT")
        lines.append("=" * 72)
        return "\n".join(lines)


# ======================================================================
# SECTION 17 — AISINT EMPLOYEE / ORCHESTRATOR
# ======================================================================

class AISIntelligenceEmployee:
    """
    Main AISINT AI Employee orchestrator.
    """

    def __init__(self, mode: ModelMode = ModelMode.LOCAL_ONLY):
        self.mode = mode
        self.policy = PolicyGuard()
        self.injection_defense = PromptInjectionDefense()
        self.decoder = AISDecoder(injection_defense=self.injection_defense)
        self.resolver = VesselResolver()
        self.track_builder = TrackBuilder()
        self.port_analyzer = PortAnalyzer()
        self.behavior_analyzer = BehaviorAnalyzer()
        self.spoofing_analyzer = SpoofingIndicatorAnalyzer()
        self.fact_gate = FactGate()
        self.reviewer = DualAIReviewer()
        self.memory = GraphicalMemory()
        self.reporter = ReportGenerator()

    def run_case(self, case: dict[str, Any]) -> AISINTResult:
        case_id = str(case.get("case_id", new_id("CASE")))
        task_id = str(case.get("task_id", new_id("TASK")))
        objective = str(case.get("objective", ""))
        questions = case.get("questions", [])
        authorization = str(case.get("authorization", ""))

        request_text = objective + "\n" + "\n".join(str(q) for q in questions)
        policy = self.policy.check_request(request_text)

        if policy.decision == PolicyDecision.POLICY_BLOCKED:
            return AISINTResult(
                case_id=case_id,
                task_id=task_id,
                objective=objective,
                status="POLICY_BLOCKED",
                policy_decision=PolicyDecision.POLICY_BLOCKED,
                report=(
                    "POLICY_BLOCKED\n\n"
                    "This request seeks prohibited maritime operational guidance. "
                    "Lawful alternative: public/authorized vessel identity, AIS track, "
                    "coverage-aware gap analysis, port-call verification, and compliance "
                    "context without targeting, interception, spoofing, jamming, evasion, "
                    "or smuggling-route planning."
                ),
                safety_flags=[
                    "No interception/targeting/evasion guidance provided.",
                    "Human lawful compliance analysis only.",
                ],
                limitations=[policy.reason],
            )

        evidence: list[Evidence] = []
        observations: list[Observation] = []

        for msg in case.get("ais_messages", []):
            if not isinstance(msg, dict):
                continue
            source_id = str(msg.get("source_id", "unknown_source"))
            source_type = msg.get("source_type", SourceType.UNKNOWN)
            receiver_type = msg.get("receiver_type", source_type)

            if "raw_nmea" in msg:
                raw = msg["raw_nmea"]
            else:
                raw = {
                    k: v
                    for k, v in msg.items()
                    if k not in ("source_id", "source_type", "receiver_type", "received_at")
                }

            ev, obs = self.decoder.ingest(
                case_id=case_id,
                source_id=source_id,
                source_type=source_type,
                receiver_type=receiver_type,
                raw=raw,
                received_at=msg.get("received_at"),
                transmitted_at=msg.get("timestamp"),
                authorization_context=authorization,
            )
            evidence.append(ev)
            if obs is not None:
                observations.append(obs)

        vessels, identity_eras, mmsi_eras, identity_contradictions = self.resolver.resolve(observations)
        vessels_by_id = {v.vessel_id: v for v in vessels}

        obs_by_vessel: dict[str, list[Observation]] = {}
        for o in observations:
            obs_by_vessel.setdefault(o.vessel_candidate_id, []).append(o)

        all_segments: list[TrackSegment] = []
        all_gaps: list[AISGap] = []
        all_track_contradictions: list[Contradiction] = []
        valid_tracks: dict[str, list[Observation]] = {}

        for vid, olist in obs_by_vessel.items():
            valid, segs, gaps, contras = self.track_builder.build(vid, olist)
            valid_tracks[vid] = valid
            all_segments.extend(segs)
            all_gaps.extend(gaps)
            all_track_contradictions.extend(contras)

        ports = [self._make_port(p) for p in case.get("ports", [])]
        port_records = case.get("port_records", [])

        all_port_calls: list[PortCall] = []
        stationary_patterns: list[dict[str, Any]] = []

        for vid, valid in valid_tracks.items():
            all_port_calls.extend(self.port_analyzer.analyze(vid, valid, ports, port_records))
            stationary_patterns.extend(self.behavior_analyzer.detect_stationary_patterns(vid, valid, ports))

        corroborations = list(case.get("corroborations", [])) + list(case.get("satellite_context", []))
        proximity_events, rendezvous_candidates, sts_candidates = self.behavior_analyzer.analyze_pairs(
            valid_tracks,
            vessels_by_id,
            ports,
            corroborations,
        )

        source_independence = self._assess_source_independence(evidence)
        contradictions = identity_contradictions + all_track_contradictions
        spoofing_confidence, spoofing_indicators = self.spoofing_analyzer.analyze(
            contradictions,
            source_independence,
        )

        fact_out = self.fact_gate.generate(
            case=case,
            observations=observations,
            vessels=vessels,
            segments=all_segments,
            gaps=all_gaps,
            port_calls=all_port_calls,
            proximity_events=proximity_events,
            rendezvous_candidates=rendezvous_candidates,
            sts_candidates=sts_candidates,
            stationary_patterns=stationary_patterns,
            contradictions=contradictions,
            spoofing_confidence=spoofing_confidence,
            spoofing_indicators=spoofing_indicators,
            source_independence=source_independence,
        )

        review = self.reviewer.review(
            facts=fact_out["facts"],
            gaps=all_gaps,
            sts_candidates=sts_candidates,
            source_independence=source_independence,
            vessels=vessels,
            contradictions=contradictions,
        )

        status = "PARTIAL"
        if not observations:
            status = "INSUFFICIENT_DATA"
        elif not vessels:
            status = "VESSEL_UNRESOLVED"
        elif review.get("human_review_required"):
            status = "PARTIAL_HUMAN_REVIEW_REQUIRED"

        privacy_flags = []
        if self.mode == ModelMode.LOCAL_ONLY:
            privacy_flags.append("LOCAL_ONLY mode selected; no external cloud transmission assumed.")
        elif self.mode == ModelMode.CLOUD:
            privacy_flags.append("CLOUD mode requires sanitized/public/policy-approved data only.")
        else:
            privacy_flags.append("HYBRID mode requires routing controls and tenant isolation.")

        result = AISINTResult(
            case_id=case_id,
            task_id=task_id,
            objective=objective,
            status=status,
            policy_decision=PolicyDecision.ALLOW,
            evidence=evidence,
            observations=observations,
            vessels=vessels,
            vessel_identity_eras=identity_eras,
            mmsi_usage_eras=mmsi_eras,
            track_segments=all_segments,
            ais_gaps=all_gaps,
            port_calls=all_port_calls,
            stationary_patterns=stationary_patterns,
            proximity_events=proximity_events,
            rendezvous_candidates=rendezvous_candidates,
            sts_candidates=sts_candidates,
            contradictions=contradictions,
            facts=fact_out["facts"],
            hypotheses=fact_out["hypotheses"],
            knowledge_gaps=fact_out["knowledge_gaps"],
            next_actions=fact_out["next_actions"],
            specialist_handoffs=fact_out["specialist_handoffs"],
            source_independence=source_independence,
            spoofing_confidence=spoofing_confidence,
            spoofing_indicators=spoofing_indicators,
            review=review,
            unknowns=fact_out["unknowns"],
            limitations=fact_out["limitations"],
            safety_flags=[
                "No targeting/interception/evasion guidance.",
                "AIS silence is not treated as maliciousness.",
                "STS/proximity is not treated as illegal activity.",
                "Human review required for consequential enforcement/compliance action.",
            ],
            privacy_flags=privacy_flags,
        )

        result.graph = self.memory.write_result(result)
        result.report = self.reporter.generate(result)
        return result

    @staticmethod
    def _make_port(p: dict[str, Any]) -> Port:
        lat = safe_float(p.get("latitude", p.get("lat")))
        lon = safe_float(p.get("longitude", p.get("lon")))
        if lat is None or lon is None:
            raise ValueError(f"Port {p.get('port_id')} missing latitude/longitude")
        return Port(
            port_id=str(p.get("port_id", new_id("PORT"))),
            name=str(p.get("name", "")),
            latitude=float(lat),
            longitude=float(lon),
            radius_nm=safe_float(p.get("radius_nm")) or 5.0,
            unlocode=p.get("unlocode"),
            source_id=str(p.get("source_id", "")),
        )

    @staticmethod
    def _assess_source_independence(evidence: list[Evidence]) -> dict[str, Any]:
        if not evidence:
            return {"status": "UNKNOWN", "notes": ["No evidence supplied."], "groups": {}}

        groups: dict[str, list[str]] = {}
        for e in evidence:
            upstream = e.decoded_payload.get("upstream_provider") or e.source_id
            groups.setdefault(str(upstream), []).append(e.evidence_id)

        if len(groups) == 1:
            status = "DEPENDENT"
            notes = [
                "All observations appear to originate from one upstream source/provider.",
                "Do not inflate confidence from duplicated feed data.",
            ]
        else:
            status = "PARTIALLY_DEPENDENT"
            notes = [
                "Multiple source identifiers exist, but full pedigree/independence is not proven.",
                "Verify upstream receiver/network/provider separation.",
            ]

        return {
            "status": status,
            "notes": notes,
            "groups": groups,
        }


# ======================================================================
# SECTION 18 — DEMO / SYNTHETIC EXAMPLE
# ======================================================================

def demo() -> None:
    """
    Synthetic demo only.
    No live AIS access. No real vessel accusation.
    """
    employee = AISIntelligenceEmployee(mode=ModelMode.LOCAL_ONLY)

    case = {
        "case_id": "DEMO-AISINT-001",
        "task_id": "DEMO-TASK-001",
        "objective": (
            "Lawful maritime compliance research: verify vessel identity, reconstruct AIS track, "
            "assess AIS gap and offshore proximity without alleging wrongdoing."
        ),
        "questions": [
            "Which vessel is observed?",
            "Is the AIS gap explained by coverage uncertainty?",
            "Is offshore proximity only a candidate or corroborated STS?",
        ],
        "authorization": "PUBLIC_DATA_LAWFUL_RESEARCH",
        "time_range": {
            "start": "2026-10-01T00:00:00Z",
            "end": "2026-10-01T14:00:00Z",
        },
        "ports": [
            {
                "port_id": "PORT_RTM_DEMO",
                "name": "Rotterdam Approach (Demo Geometry)",
                "latitude": 51.90,
                "longitude": 4.10,
                "radius_nm": 10.0,
                "source_id": "demo_port_geometry",
            }
        ],
        "ais_messages": [
            {
                "source_id": "public_ais_demo_1",
                "source_type": "TERRESTRIAL_AIS",
                "mmsi": "219000001",
                "imo": "9074723",
                "timestamp": "2026-10-01T00:00:00Z",
                "lat": 51.95,
                "lon": 4.05,
                "sog": 0.1,
                "cog": 0.0,
                "heading": 0.0,
                "nav_status": 5,
                "name": "DEMO VESSEL ALPHA",
                "callsign": "DEMOA",
                "ship_type": 70,
                "length": 180.0,
                "beam": 30.0,
                "draught": 10.5,
                "destination": "ROTTERDAM",
                "eta": "2026-10-01T06:00:00Z",
            },
            {
                "source_id": "public_ais_demo_1",
                "source_type": "TERRESTRIAL_AIS",
                "mmsi": "219000001",
                "imo": "9074723",
                "timestamp": "2026-10-01T06:00:00Z",
                "lat": 51.90,
                "lon": 4.10,
                "sog": 0.2,
                "cog": 0.0,
                "heading": 0.0,
                "nav_status": 5,
                "name": "DEMO VESSEL ALPHA",
                "callsign": "DEMOA",
                "ship_type": 70,
                "length": 180.0,
                "beam": 30.0,
                "draught": 10.5,
                "destination": "ROTTERDAM",
                "eta": "2026-10-01T06:00:00Z",
            },
            {
                "source_id": "public_ais_demo_1",
                "source_type": "TERRESTRIAL_AIS",
                "mmsi": "219000001",
                "imo": "9074723",
                "timestamp": "2026-10-01T13:00:00Z",
                "lat": 51.0000,
                "lon": 3.0000,
                "sog": 12.0,
                "cog": 250.0,
                "heading": 250.0,
                "nav_status": 0,
                "name": "DEMO VESSEL ALPHA",
                "callsign": "DEMOA",
                "ship_type": 70,
                "length": 180.0,
                "beam": 30.0,
                "draught": 10.5,
                "destination": "ANTWERP",
                "eta": "2026-10-01T18:00:00Z",
            },
            {
                "source_id": "public_ais_demo_1",
                "source_type": "TERRESTRIAL_AIS",
                "mmsi": "219000001",
                "imo": "9074723",
                "timestamp": "2026-10-01T13:15:00Z",
                "lat": 51.0005,
                "lon": 3.0005,
                "sog": 0.3,
                "cog": 0.0,
                "heading": 0.0,
                "nav_status": 0,
                "name": "DEMO VESSEL ALPHA",
                "callsign": "DEMOA",
                "ship_type": 70,
                "length": 180.0,
                "beam": 30.0,
                "draught": 10.5,
                "destination": "ANTWERP",
                "eta": "2026-10-01T18:00:00Z",
            },
            {
                "source_id": "public_ais_demo_1",
                "source_type": "TERRESTRIAL_AIS",
                "mmsi": "219000001",
                "imo": "9074723",
                "timestamp": "2026-10-01T13:30:00Z",
                "lat": 51.0010,
                "lon": 3.0010,
                "sog": 0.2,
                "cog": 0.0,
                "heading": 0.0,
                "nav_status": 0,
                "name": "DEMO VESSEL ALPHA",
                "callsign": "DEMOA",
                "ship_type": 70,
                "length": 180.0,
                "beam": 30.0,
                "draught": 10.5,
                "destination": "ANTWERP",
                "eta": "2026-10-01T18:00:00Z",
            },
            {
                "source_id": "public_ais_demo_1",
                "source_type": "TERRESTRIAL_AIS",
                "mmsi": "219000002",
                "imo": "9074739",
                "timestamp": "2026-10-01T13:00:00Z",
                "lat": 51.0010,
                "lon": 3.0010,
                "sog": 0.2,
                "cog": 0.0,
                "heading": 0.0,
                "nav_status": 1,
                "name": "DEMO VESSEL BRAVO",
                "callsign": "DEMOB",
                "ship_type": 80,
                "length": 120.0,
                "beam": 20.0,
                "draught": 8.0,
                "destination": "ANCHORAGE",
                "eta": "2026-10-01T13:00:00Z",
            },
            {
                "source_id": "public_ais_demo_1",
                "source_type": "TERRESTRIAL_AIS",
                "mmsi": "219000002",
                "imo": "9074739",
                "timestamp": "2026-10-01T13:15:00Z",
                "lat": 51.0010,
                "lon": 3.0010,
                "sog": 0.1,
                "cog": 0.0,
                "heading": 0.0,
                "nav_status": 1,
                "name": "DEMO VESSEL BRAVO",
                "callsign": "DEMOB",
                "ship_type": 80,
                "length": 120.0,
                "beam": 20.0,
                "draught": 8.0,
                "destination": "ANCHORAGE",
                "eta": "2026-10-01T13:00:00Z",
            },
            {
                "source_id": "public_ais_demo_1",
                "source_type": "TERRESTRIAL_AIS",
                "mmsi": "219000002",
                "imo": "9074739",
                "timestamp": "2026-10-01T13:30:00Z",
                "lat": 51.0010,
                "lon": 3.0010,
                "sog": 0.1,
                "cog": 0.0,
                "heading": 0.0,
                "nav_status": 1,
                "name": "DEMO VESSEL BRAVO",
                "callsign": "DEMOB",
                "ship_type": 80,
                "length": 120.0,
                "beam": 20.0,
                "draught": 8.0,
                "destination": "ANCHORAGE",
                "eta": "2026-10-01T13:00:00Z",
            },
        ],
        "satellite_context": [],
        "trade_context": [],
        "sanctions_context": [],
        "weather_context": [],
        "corroborations": [],
        "port_records": [],
    }

    result = employee.run_case(case)
    print(result.report)

    # Example: serialize compact result
    # print(json.dumps({"facts": [f.statement for f in result.facts]}, indent=2, default=_json_default))


if __name__ == "__main__":
    demo()
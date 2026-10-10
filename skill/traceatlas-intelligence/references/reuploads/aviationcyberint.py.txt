# TraceAtlas AviationCyberInt - Short Defensive Python Core
# Mode: LOCAL_ONLY / PASSIVE_FIRST / DEFENSIVE / AUTHORIZED / SAFETY-CRITICAL
# Does NOT hack aircraft, probe avionics, spoof GNSS/ADS-B, jam RF, or disrupt operations.

from __future__ import annotations

import json
import re
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Mode(str, Enum):
    LOCAL_ONLY = "LOCAL_ONLY"
    HYBRID = "HYBRID"
    CLOUD = "CLOUD"


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_HUMAN_REVIEW = "REQUIRE_HUMAN_REVIEW"


class Status(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED_POLICY = "BLOCKED_POLICY"
    BLOCKED_SAFETY = "BLOCKED_SAFETY"
    BLOCKED_AUTHORIZATION = "BLOCKED_AUTHORIZATION"


class SafetyImpact(str, Enum):
    NONE_IDENTIFIED = "NONE_IDENTIFIED"
    BUSINESS_ONLY = "BUSINESS_ONLY"
    OPERATIONAL = "OPERATIONAL"
    SAFETY_RELATED = "SAFETY_RELATED"
    POTENTIAL_SAFETY_IMPACT = "POTENTIAL_SAFETY_IMPACT"
    SAFETY_IMPACT_SUPPORTED = "SAFETY_IMPACT_SUPPORTED"
    UNKNOWN = "UNKNOWN"


class CauseState(str, Enum):
    CYBER_CONFIRMED = "CYBER_CONFIRMED"
    CYBER_SUPPORTED = "CYBER_SUPPORTED"
    CYBER_CANDIDATE = "CYBER_CANDIDATE"
    NON_CYBER = "NON_CYBER"
    CAUSE_UNKNOWN = "CAUSE_UNKNOWN"


@dataclass
class Evidence:
    evidence_id: str
    source: str
    source_type: str
    timestamp: str
    text: str
    url: Optional[str] = None
    reliability: float = 0.0


@dataclass
class Asset:
    asset_id: str
    asset_type: str
    name: Optional[str] = None
    organization: Optional[str] = None
    system_function: Optional[str] = None
    criticality: Optional[str] = None
    software_version: Optional[str] = None
    firmware_version: Optional[str] = None
    confidence: float = 0.5


@dataclass
class Finding:
    finding_id: str
    statement: str
    category: str
    evidence_ids: list[str]
    confidence: float
    safety_impact: SafetyImpact
    limitations: list[str] = field(default_factory=list)


@dataclass
class Request:
    case_id: str
    objective: str
    scope: dict[str, Any] = field(default_factory=dict)
    authorization: dict[str, Any] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    time_range: dict[str, str] = field(default_factory=dict)


@dataclass
class Result:
    case_id: str
    status: Status
    policy_decision: PolicyDecision
    summary: str
    assets: list[Asset]
    findings: list[Finding]
    hypotheses: list[dict[str, Any]]
    knowledge_gaps: list[str]
    recommended_actions: list[str]
    specialist_handoffs: list[str]
    safety_review_required: bool
    privacy_flags: list[str]
    source_reliability: dict[str, float]
    limitations: list[str]
    created_at: str


class AviationCyberInt:
    """
    Short defensive aviation cyber-intelligence core.
    Full TraceAtlas would add graph DB, multi-agent orchestration,
    LLM adapters, authorized telemetry connectors, and human review workflow.
    """

    OFFENSIVE_PATTERNS = [
        r"\bhack\b.*\b(aircraft|avionics|atc|airport|airline)\b",
        r"\bexploit\b.*\b(avionics|aircraft|atc|flight[- ]control|efb)\b",
        r"\bspoof\b.*\b(gnss|gps|ads-b|adsb|mode-s)\b",
        r"\bjam\b.*\b(gnss|gps|rf|aviation|satcom)\b",
        r"\binject\b.*\b(ads-b|adsb|mode-s|acars|cpdlc)\b",
        r"\bmodify\b.*\b(flight[- ]plan|weight[- ]balance|maintenance record|dispatch|crew schedule)\b",
        r"\battack\b.*\b(airline|airport|baggage|reservation|dcs|efb|satcom|atc|avionics)\b",
        r"\bbypass\b.*\b(authentication|aircraft|avionics|airport)\b",
        r"\bdeploy\b.*\b(malware|ransomware)\b",
        r"\b(denial[- ]of[- ]service|ddos)\b",
        r"\bcredential\b.*\b(test|spray|use|access)\b",
        r"\baircraft[- ]targeting\b",
        r"\bflight[- ]control manipulation\b",
    ]

    SOURCE_WEIGHTS = {
        "official_aviation_authority": 0.95,
        "oem_advisory": 0.90,
        "cert_advisory": 0.90,
        "airline_official": 0.85,
        "airport_official": 0.85,
        "vendor_advisory": 0.85,
        "authorized_log": 0.90,
        "authorized_incident_response": 0.90,
        "public_aviation_data": 0.70,
        "security_research": 0.60,
        "commercial_cti": 0.65,
        "news": 0.50,
        "social": 0.30,
        "anonymous": 0.20,
    }

    STRONG_SAFETY_TERMS = [
        "flight safety",
        "safety impact",
        "loss of control",
        "flight control",
        "avionics compromise",
        "navigation integrity",
        "gnss spoofing",
        "ads-b spoofing",
        "adsb spoofing",
        "atc compromise",
        "aircraft compromised",
    ]

    BUSINESS_TERMS = [
        "reservation",
        "ticketing",
        "check-in",
        "checkin",
        "baggage",
        "website",
        "mobile app",
        "loyalty",
        "customer account",
        "corporate it",
    ]

    def __init__(self, mode: Mode = Mode.LOCAL_ONLY):
        self.mode = mode
        self.memory: list[dict[str, Any]] = []

    @staticmethod
    def _hash(*parts: Any) -> str:
        raw = "|".join(str(p) for p in parts)
        return hashlib.sha256(raw.encode()).hexdigest()[:12]

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def policy_check(self, req: Request) -> tuple[PolicyDecision, str]:
        blob = " ".join(
            [
                req.objective,
                json.dumps(req.scope, default=str),
                json.dumps(req.authorization, default=str),
            ]
        ).lower()

        for pattern in self.OFFENSIVE_PATTERNS:
            if re.search(pattern, blob):
                return PolicyDecision.BLOCK, f"Offensive aviation action detected: {pattern}"

        if (
            re.search(r"\b(active|intrusive)\s+(scan|test|validation|exploitation)\b", blob)
            and not req.scope.get("authorized_test_environment")
        ):
            return (
                PolicyDecision.BLOCK,
                "Active testing requires isolated, authorized, non-operational environment.",
            )

        if req.authorization.get("authorized") is False:
            return PolicyDecision.BLOCK, "Authorization explicitly denied."

        return PolicyDecision.ALLOW, ""

    def score_evidence(self, ev: Evidence) -> float:
        base = self.SOURCE_WEIGHTS.get(ev.source_type.lower(), 0.50)
        if ev.url:
            base = min(1.0, base + 0.05)
        if "official" in ev.source.lower():
            base = min(1.0, base + 0.05)
        ev.reliability = round(base, 2)
        return ev.reliability

    def resolve_entities(self, req: Request) -> list[Asset]:
        assets: list[Asset] = []
        mapping = {
            "airlines": "AIRLINE",
            "airports": "AIRPORT",
            "aircraft_types": "AIRCRAFT_TYPE",
            "oems": "OEM",
            "mros": "MRO",
            "avionics_vendors": "AVIONICS_VENDOR",
            "systems": "SYSTEM",
            "software": "SOFTWARE",
            "firmware": "FIRMWARE",
            "cloud_services": "CLOUD_SERVICE",
            "satcom_services": "SATCOM_SERVICE",
            "navigation_services": "NAVIGATION_SERVICE",
        }

        for key, asset_type in mapping.items():
            values = req.scope.get(key, [])
            if isinstance(values, str):
                values = [values]

            for value in values:
                assets.append(
                    Asset(
                        asset_id=f"{asset_type.lower()}:{self._hash(asset_type, value)}",
                        asset_type=asset_type,
                        name=str(value),
                        organization=(
                            str(value)
                            if asset_type in {"AIRLINE", "AIRPORT", "OEM", "MRO", "AVIONICS_VENDOR"}
                            else None
                        ),
                        confidence=0.80,
                    )
                )

        return assets

    def fact_gate(
        self,
        statement: str,
        evidence_ids: list[str],
        evidence_by_id: dict[str, Evidence],
    ) -> tuple[bool, list[str]]:
        limits: list[str] = []

        if not evidence_ids:
            return False, ["No linked evidence."]

        missing = [eid for eid in evidence_ids if eid not in evidence_by_id]
        if missing:
            limits.append(f"Missing evidence IDs: {missing}")

        evs = [evidence_by_id[eid] for eid in evidence_ids if eid in evidence_by_id]
        if not evs:
            return False, ["Evidence not found."]

        avg_reliability = sum(e.reliability for e in evs) / len(evs)
        if avg_reliability < 0.55:
            limits.append(f"Average source reliability {avg_reliability:.2f} below fact threshold.")

        lowered = statement.lower()
        if any(term in lowered for term in self.STRONG_SAFETY_TERMS):
            if len({e.source for e in evs}) < 2:
                limits.append("Safety/avionics claim requires at least two independent sources.")
            if avg_reliability < 0.80:
                limits.append("Safety/avionics claim requires high-reliability evidence.")

        return (not limits), limits

    def build_hypotheses(self, blob: str) -> list[dict[str, Any]]:
        hypotheses: list[dict[str, Any]] = []

        if any(k in blob for k in ["outage", "incident", "ransomware", "breach", "down"]):
            hypotheses.extend(
                [
                    {"id": "H1", "claim": "Observed disruption resulted from cyber intrusion.", "status": "CANDIDATE"},
                    {"id": "H2", "claim": "Vendor/service outage caused operational disruption.", "status": "CANDIDATE"},
                    {"id": "H3", "claim": "Internal software/configuration failure caused outage.", "status": "CANDIDATE"},
                    {"id": "H4", "claim": "Public reports misclassified a non-cyber issue.", "status": "CANDIDATE"},
                ]
            )

        if any(k in blob for k in ["gnss", "gps", "jam", "spoof", "interference"]):
            hypotheses.extend(
                [
                    {"id": "H5", "claim": "Navigation anomaly reflects intentional interference.", "status": "CANDIDATE"},
                    {"id": "H6", "claim": "Unintentional RF interference occurred.", "status": "CANDIDATE"},
                    {"id": "H7", "claim": "Receiver/system issue explains anomaly.", "status": "CANDIDATE"},
                    {"id": "H8", "claim": "Atmospheric/multipath effects explain anomaly.", "status": "CANDIDATE"},
                ]
            )

        if any(k in blob for k in ["ads-b", "adsb", "mode-s", "track"]):
            hypotheses.extend(
                [
                    {"id": "H9", "claim": "ADS-B anomaly may be data-quality artifact.", "status": "CANDIDATE"},
                    {"id": "H10", "claim": "ADS-B anomaly may reflect receiver/time issue.", "status": "CANDIDATE"},
                    {"id": "H11", "claim": "ADS-B anomaly may reflect database mismatch.", "status": "CANDIDATE"},
                    {"id": "H12", "claim": "Spoofing candidate cannot be excluded without multi-source evidence.", "status": "CANDIDATE"},
                ]
            )

        if not hypotheses:
            hypotheses.append(
                {
                    "id": "H0",
                    "claim": "No adverse cyber event evidenced; maintain passive monitoring.",
                    "status": "DEFAULT",
                }
            )

        return hypotheses

    def build_recommendations(self) -> list[str]:
        return [
            "Verify exact asset, system, software/firmware version, and deployment configuration.",
            "Review OEM/vendor/CERT advisories through authorized channels.",
            "Confirm segmentation; do not assume reachability between airline IT/IFE/SATCOM and safety-critical avionics.",
            "Check authorized logs, IAM, third-party remote access, and patch status.",
            "Rotate exposed credentials only via approved identity processes; do not test credentials.",
            "Increase defensive monitoring for affected vendors, domains, cloud services, and aviation data dependencies.",
            "Escalate potential flight-safety relevance to aviation safety/security human review.",
        ]

    def build_handoffs(self, blob: str) -> list[str]:
        handoffs: list[str] = []

        if "cve" in blob or "vulnerability" in blob:
            handoffs.append("VULNINT")
        if "incident" in blob or "ransomware" in blob or "breach" in blob:
            handoffs.append("INCIDENTINT")
        if "credential" in blob:
            handoffs.append("CREDINT")
        if "sbom" in blob or "supply chain" in blob or "vendor" in blob:
            handoffs.append("SUPPLYCHAININT")
        if "ot" in blob or "baggage" in blob or "building management" in blob:
            handoffs.append("OTINT")
        if "gnss" in blob or "rf" in blob or "spectrum" in blob:
            handoffs.append("SIGINT/ELINT")
        if "ads-b" in blob or "adsb" in blob or "track" in blob:
            handoffs.append("TRANSPORTINT")

        return handoffs

    def analyze(self, req: Request) -> Result:
        decision, reason = self.policy_check(req)

        if decision == PolicyDecision.BLOCK:
            result = Result(
                case_id=req.case_id,
                status=Status.BLOCKED_POLICY,
                policy_decision=decision,
                summary=f"POLICY_BLOCKED: {reason}",
                assets=[],
                findings=[],
                hypotheses=[],
                knowledge_gaps=["Request outside defensive authorized scope."],
                recommended_actions=[
                    "Convert request into passive, authorized, defensive aviation cyber intelligence."
                ],
                specialist_handoffs=[],
                safety_review_required=False,
                privacy_flags=[],
                source_reliability={},
                limitations=[reason],
                created_at=self._now(),
            )
            self.memory.append(asdict(result))
            return result

        for ev in req.evidence:
            self.score_evidence(ev)

        evidence_by_id = {ev.evidence_id: ev for ev in req.evidence}
        assets = self.resolve_entities(req)
        findings: list[Finding] = []

        for ev in req.evidence:
            statement = f"Source {ev.source} ({ev.source_type}) reports: {ev.text[:220]}"
            ok, limits = self.fact_gate(statement, [ev.evidence_id], evidence_by_id)
            category = "SUPPORTED_FACT" if ok else "OBSERVATION"

            text = ev.text.lower()
            safety = SafetyImpact.UNKNOWN

            if any(term in text for term in self.STRONG_SAFETY_TERMS):
                safety = SafetyImpact.SAFETY_RELATED if ok else SafetyImpact.UNKNOWN
                limits.append(
                    "Safety-relevant language detected; direct flight-safety impact is not established "
                    "without architecture evidence, independent sources, and human aviation safety review."
                )
            elif any(term in text for term in self.BUSINESS_TERMS):
                safety = SafetyImpact.BUSINESS_ONLY
                limits.append("Business/operational impact possible; no avionics path established.")
            else:
                limits.append("Context requires asset/system/function resolution.")

            findings.append(
                Finding(
                    finding_id=self._hash("finding", ev.evidence_id),
                    statement=statement,
                    category=category,
                    evidence_ids=[ev.evidence_id],
                    confidence=ev.reliability,
                    safety_impact=safety,
                    limitations=limits or ["Single-source observation; verify source independence."],
                )
            )

        blob = " ".join([req.objective] + [e.text for e in req.evidence]).lower()
        hypotheses = self.build_hypotheses(blob)

        safety_review_required = (
            any(
                f.safety_impact
                in {
                    SafetyImpact.SAFETY_RELATED,
                    SafetyImpact.POTENTIAL_SAFETY_IMPACT,
                    SafetyImpact.SAFETY_IMPACT_SUPPORTED,
                }
                for f in findings
            )
            or any(term in blob for term in self.STRONG_SAFETY_TERMS)
        )

        if safety_review_required:
            overall_safety = SafetyImpact.SAFETY_RELATED
        elif any(f.safety_impact == SafetyImpact.BUSINESS_ONLY for f in findings):
            overall_safety = SafetyImpact.BUSINESS_ONLY
        elif req.evidence:
            overall_safety = SafetyImpact.NONE_IDENTIFIED
        else:
            overall_safety = SafetyImpact.UNKNOWN

        if req.evidence and all(f.category == "SUPPORTED_FACT" for f in findings):
            status = Status.SUCCEEDED
        elif req.evidence:
            status = Status.PARTIAL
        else:
            status = Status.INCONCLUSIVE

        knowledge_gaps: list[str] = []

        if not req.evidence:
            knowledge_gaps.append("No evidence supplied; cannot assert facts.")

        if not any(a.asset_type == "SYSTEM" for a in assets):
            knowledge_gaps.append("Affected system not resolved.")

        if not any(a.asset_type in {"SOFTWARE", "FIRMWARE"} for a in assets):
            knowledge_gaps.append("Software/firmware version/configuration unresolved.")

        if safety_review_required:
            knowledge_gaps.append("Safety relevance requires authoritative aviation safety review.")

        privacy_flags: list[str] = []
        if any(k in blob for k in ["passenger", "crew", "pii", "biometric", "loyalty"]):
            privacy_flags.append("PII/crew/passenger data minimization required.")

        limitations = [
            "Local rule-based skeleton; not a substitute for full multi-agent graph, "
            "live authorized telemetry, or human aviation safety review.",
            "No active scanning, no aircraft connection, no RF transmission, no exploitation.",
        ]

        if not req.evidence:
            limitations.append("No evidence supplied.")

        summary = (
            f"Defensive aviation cyber intelligence assessment for {req.case_id}. "
            f"Entities resolved: {len(assets)}. Evidence items: {len(req.evidence)}. "
            f"Findings: {len(findings)}. Overall safety relevance: {overall_safety.value}. "
            "No aircraft intrusion, avionics exploitation, GNSS/ADS-B spoofing, RF jamming, "
            "or operational disruption performed or assisted."
        )

        result = Result(
            case_id=req.case_id,
            status=status,
            policy_decision=PolicyDecision.ALLOW,
            summary=summary,
            assets=assets,
            findings=findings,
            hypotheses=hypotheses,
            knowledge_gaps=knowledge_gaps,
            recommended_actions=self.build_recommendations(),
            specialist_handoffs=self.build_handoffs(blob),
            safety_review_required=safety_review_required,
            privacy_flags=privacy_flags,
            source_reliability={ev.evidence_id: ev.reliability for ev in req.evidence},
            limitations=limitations,
            created_at=self._now(),
        )

        self.memory.append(asdict(result))
        return result


def demo() -> None:
    agent = AviationCyberInt(mode=Mode.LOCAL_ONLY)

    # 1) Allowed defensive intelligence case
    allowed_request = Request(
        case_id="ACI-001",
        objective="Assess third-party maintenance platform ransomware impact on Airline A operations",
        scope={
            "airlines": ["Airline A"],
            "mros": ["MRO-X"],
            "systems": ["MaintenanceTicketingPlatform"],
        },
        authorization={"authorized": True, "purpose": "defensive_risk_assessment"},
        evidence=[
            Evidence(
                evidence_id="EV1",
                source="MRO-X Security Advisory",
                source_type="vendor_advisory",
                timestamp="2026-10-01T00:00:00Z",
                text=(
                    "Ransomware affected corporate maintenance ticketing system. "
                    "No onboard avionics access reported. Maintenance workflows delayed."
                ),
                url="https://example.org/mro-x-advisory",
            )
        ],
        time_range={"start": "2026-09-30", "end": "2026-10-02"},
    )

    allowed_result = agent.analyze(allowed_request)
    print("=== ALLOWED DEFENSIVE CASE ===")
    print(json.dumps(asdict(allowed_result), indent=2, default=str))

    # 2) Blocked offensive request
    blocked_request = Request(
        case_id="ACI-002",
        objective="How to hack aircraft avionics and spoof GNSS",
        scope={},
        authorization={"authorized": False},
    )

    blocked_result = agent.analyze(blocked_request)
    print("\n=== BLOCKED OFFENSIVE CASE ===")
    print(json.dumps(asdict(blocked_result), indent=2, default=str))


if __name__ == "__main__":
    demo()
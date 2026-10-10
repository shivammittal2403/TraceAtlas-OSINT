# contradictionint_short_main.py
# Defensive CONTRADICTIONINT skeleton:
# detect / classify / explain / preserve contradictions.
# Never infer deception merely from conflict. Never force consensus.

import json
import re
import itertools
from datetime import datetime, timezone
from collections import OrderedDict

# -----------------------------
# Boundaries / helpers
# -----------------------------

NOW = lambda: datetime.now(timezone.utc).isoformat()

POLICY_BLOCK_PATTERNS = [
    r"\b(prove|declare|label|call)\b.*\b(liar|lying|deception|deceptive)\b",
    r"\bfind\b.*\b(liar|deception)\b",
    r"\bautomatic(ally)?\s*(accuse|blame)\b",
]

BOOL_TRUE = {"true", "yes", "1", "active", "enabled", "on"}
BOOL_FALSE = {"false", "no", "0", "inactive", "disabled", "off", "not_active"}

SYNONYMS = {
    "terminated": "employment_ended",
    "fired": "employment_ended",
    "laid_off": "employment_ended",
    "not_active": "inactive",
    "no_longer_active": "inactive",
    "live": "active",
    "operational": "active",
    "retired": "inactive",
    "deleted": "inactive",
    "dissolved": "inactive",
}

PREDICATE_SYNONYMS = {
    "is_active": "active",
    "active_status": "status",
    "has_director": "director",
    "revenue": "revenue",
}

STATUS_GROUPS = [
    {"active", "live", "operational", "enabled"},
    {"inactive", "disabled", "dissolved", "deleted", "retired", "not_active"},
]

MATERIAL_PREDICATES = {
    "owns", "owner", "director", "status", "active", "revenue",
    "control", "controls", "compromised", "malicious", "vulnerable",
}

UNIT_TO_FACTOR = {
    "kb": 1_000,
    "mb": 1_000_000,
    "gb": 1_000_000_000,
    "tb": 1_000_000_000_000,
}

SCALE_TO_FACTOR = {
    "k": 1_000,
    "m": 1_000_000,
    "million": 1_000_000,
    "b": 1_000_000_000,
    "billion": 1_000_000_000,
}

RANGE_RE = re.compile(
    r"^(?P<low>-?\d[\d,.]*)\s*(?:-|to|–)\s*(?P<high>-?\d[\d,.]*)$"
)

NUMBER_RE = re.compile(
    r"^(?P<approx>~|about|approximately|roughly|nearly|more than|less than)?"
    r"\s*(?P<num>-?\d[\d,.]*)\s*"
    r"(?P<scale>k|m|million|b|billion)?\s*"
    r"(?P<unit>%|usd|inr|kb|mb|gb|tb)?$",
    re.IGNORECASE,
)


def norm(value):
    value = str(value or "").strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    return value.strip("_")


def to_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def to_set(value):
    return set(str(x) for x in to_list(value))


def parse_dt(value):
    if not value:
        return None
    try:
        s = str(value)
        if len(s) == 10:
            s += "T00:00:00+00:00"
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def parse_object(value):
    if isinstance(value, bool):
        return {"kind": "bool", "value": value}

    if value is None:
        return {"kind": "text", "value": "unknown"}

    s = str(value).strip()
    low = s.lower()

    if low in BOOL_TRUE:
        return {"kind": "bool", "value": True}
    if low in BOOL_FALSE:
        return {"kind": "bool", "value": False}

    m = RANGE_RE.match(s)
    if m:
        return {
            "kind": "range",
            "low": float(m.group("low").replace(",", "")),
            "high": float(m.group("high").replace(",", "")),
            "unit": None,
            "approx": False,
        }

    m = NUMBER_RE.match(s)
    if m:
        approx = bool(m.group("approx"))
        num = float(m.group("num").replace(",", ""))
        scale = (m.group("scale") or "").lower()
        unit = (m.group("unit") or "").lower()

        if scale:
            num *= SCALE_TO_FACTOR.get(scale, 1)

        if unit:
            if unit in UNIT_TO_FACTOR:
                num *= UNIT_TO_FACTOR[unit]
                unit = "bytes"
            elif unit == "%":
                unit = "percent"
        else:
            unit = None

        return {"kind": "number", "value": num, "unit": unit, "approx": approx}

    return {"kind": "text", "value": SYNONYMS.get(norm(s), norm(s))}


def as_range(parsed):
    if parsed["kind"] == "number":
        return parsed["value"], parsed["value"]
    if parsed["kind"] == "range":
        return parsed["low"], parsed["high"]
    return None


def opposite_text(a, b):
    for i, g in enumerate(STATUS_GROUPS):
        for h in STATUS_GROUPS[i + 1:]:
            if (a in g and b in h) or (b in g and a in h):
                return True
    return False


def compare_objects(pa, pb):
    if pa["kind"] == "bool" and pb["kind"] == "bool":
        return "EQUIVALENT" if pa["value"] == pb["value"] else "INCOMPATIBLE"

    if pa["kind"] == "text" and pb["kind"] == "text":
        if pa["value"] == pb["value"]:
            return "EQUIVALENT"
        if opposite_text(pa["value"], pb["value"]):
            return "INCOMPATIBLE"
        return "UNKNOWN"

    if pa["kind"] in ("number", "range") and pb["kind"] in ("number", "range"):
        if pa.get("unit") != pb.get("unit"):
            return "UNKNOWN"

        if pa["kind"] == "number" and pb["kind"] == "number":
            a, b = pa["value"], pb["value"]
            if a == b:
                return "EQUIVALENT"

            tol = 0.10 if (pa.get("approx") or pb.get("approx")) else 0.01
            if abs(a - b) <= tol * max(abs(a), abs(b), 1.0):
                return "COMPATIBLE"

            if pa.get("approx") or pb.get("approx"):
                return "UNKNOWN"

            return "INCOMPATIBLE"

        ra, rb = as_range(pa), as_range(pb)
        if ra[1] < rb[0] or rb[1] < ra[0]:
            if pa.get("approx") or pb.get("approx"):
                return "UNKNOWN"
            return "INCOMPATIBLE"

        if ra == rb:
            return "EQUIVALENT"
        return "COMPATIBLE"

    return "UNKNOWN"


def align_entity(a, b):
    if a["predicate"] != b["predicate"]:
        return "UNKNOWN"

    if a.get("subject_entity_id") and b.get("subject_entity_id"):
        if a["subject_entity_id"] == b["subject_entity_id"]:
            return "SAME_VERIFIED"

    if norm(a.get("subject")) == norm(b.get("subject")):
        return "PROBABLE_SAME"

    return "UNKNOWN"


def get_interval(c):
    start = c.get("valid_from") or c.get("observed_at")
    end = c.get("valid_to") or c.get("observed_at")
    if start and not end:
        end = start
    return start, end


def align_temporal(a, b, case):
    a_start, a_end = get_interval(a)
    b_start, b_end = get_interval(b)

    if not (a_start and a_end and b_start and b_end):
        if case.get("assume_same_time_when_unspecified"):
            return "EXACT_OVERLAP"
        return "TIME_UNKNOWN"

    if a_end < b_start or b_end < a_start:
        return "NON_OVERLAPPING"

    if a_start == b_start and a_end == b_end:
        return "EXACT_OVERLAP"

    return "PARTIAL_OVERLAP"


def align_scope(a, b, case):
    qa = a.get("qualifiers") or {}
    qb = b.get("qualifiers") or {}

    if not qa and not qb:
        return "SAME_SCOPE" if case.get("assume_same_scope_when_unspecified") else "UNKNOWN"

    common = set(qa) & set(qb)
    if any(qa[k] != qb[k] for k in common):
        return "DIFFERENT_SCOPE"

    if not common:
        return "UNKNOWN"

    if set(qa) == set(qb):
        return "SAME_SCOPE"

    return "OVERLAPPING_SCOPE"


def align_unit(pa, pb):
    if pa["kind"] in ("number", "range") and pb["kind"] in ("number", "range"):
        if pa.get("unit") == pb.get("unit"):
            return "SAME_UNIT"
        return "UNIT_MISMATCH"
    return "UNKNOWN"


def source_independence(sa, sb, sources):
    if not sa or not sb:
        return "UNKNOWN"
    if sa == sb:
        return "DEPENDENT"

    a = sources.get(sa, {})
    b = sources.get(sb, {})

    if not a or not b:
        return "UNKNOWN"

    if (
        a.get("upstream_id") == b.get("source_id")
        or b.get("upstream_id") == a.get("source_id")
        or (a.get("upstream_id") and a.get("upstream_id") == b.get("upstream_id"))
    ):
        return "DEPENDENT"

    if set(to_list(a.get("cites"))) & set(to_list(b.get("cites"))):
        return "PARTIALLY_DEPENDENT"

    if a.get("family") and b.get("family") and a["family"] != b["family"]:
        return "INDEPENDENT"

    return "UNKNOWN"


def relation_between(a, b):
    if b["claim_id"] in a["supersedes"]:
        return "SUPERSEDES", a["claim_id"], b["claim_id"]
    if a["claim_id"] in b["supersedes"]:
        return "SUPERSEDES", b["claim_id"], a["claim_id"]

    if b["claim_id"] in a["corrects"]:
        return "CORRECTS", a["claim_id"], b["claim_id"]
    if a["claim_id"] in b["corrects"]:
        return "CORRECTS", b["claim_id"], a["claim_id"]

    if b["claim_id"] in a["retracts"]:
        return "RETRACTS", a["claim_id"], b["claim_id"]
    if a["claim_id"] in b["retracts"]:
        return "RETRACTS", b["claim_id"], a["claim_id"]

    if b["claim_id"] in a["replaces"] or a["claim_id"] in b["replaces"]:
        return "REPLACES", a["claim_id"], b["claim_id"]

    if b["claim_id"] in a["amends"] or a["claim_id"] in b["amends"]:
        return "AMENDS", a["claim_id"], b["claim_id"]

    return None


def confidence_label(entity, temporal, scope, semantic):
    score = 0
    score += {"SAME_VERIFIED": 2, "PROBABLE_SAME": 1}.get(entity, 0)
    score += {"EXACT_OVERLAP": 2, "PARTIAL_OVERLAP": 1}.get(temporal, 0)
    score += {"SAME_SCOPE": 2, "OVERLAPPING_SCOPE": 1}.get(scope, 0)
    score += {"INCOMPATIBLE": 2, "COMPATIBLE": 1, "EQUIVALENT": 1}.get(semantic, 0)

    if score >= 6:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def materiality_for(predicate, resolution, semantic):
    if resolution != "PERSISTENT_CONTRADICTION":
        return "COSMETIC"
    if predicate in MATERIAL_PREDICATES:
        return "MATERIAL"
    if semantic == "INCOMPATIBLE":
        return "MODERATE"
    return "MINOR"


def severity_for(materiality, independence, resolution):
    if resolution != "PERSISTENT_CONTRADICTION":
        return "INFORMATIONAL"
    if materiality == "MATERIAL" and independence == "INDEPENDENT":
        return "HIGH"
    if materiality == "MATERIAL":
        return "MEDIUM"
    return "LOW"


def subtype_for(pa, pb, semantic):
    if semantic != "INCOMPATIBLE":
        return "APPARENT_CONTRADICTION"
    if pa["kind"] == "bool" and pb["kind"] == "bool":
        return "DIRECT_LOGICAL_CONTRADICTION"
    if pa["kind"] in ("number", "range") and pb["kind"] in ("number", "range"):
        return "NUMERIC_CONTRADICTION"
    if pa["kind"] == "text" and pb["kind"] == "text" and opposite_text(pa["value"], pb["value"]):
        return "STATUS_CONTRADICTION"
    return "ATTRIBUTE_CONTRADICTION"


def required_evidence_for(entity, temporal, scope, unit, independence, subtype):
    out = ["Retrieve original/primary evidence for both claims."]
    if entity != "SAME_VERIFIED":
        out.append("Resolve subject entity using canonical IDs.")
    if temporal not in ("EXACT_OVERLAP", "PARTIAL_OVERLAP"):
        out.append("Normalize event time, validity interval, timezone, and observation time.")
    if scope not in ("SAME_SCOPE", "OVERLAPPING_SCOPE"):
        out.append("Clarify scope qualifiers: jurisdiction, environment, account type, population, etc.")
    if unit == "UNIT_MISMATCH":
        out.append("Normalize units, currency, scale, rounding, and measurement method.")
    if independence in ("UNKNOWN", "PARTIALLY_DEPENDENT", "DEPENDENT"):
        out.append("Trace source pedigree and determine independent evidence paths.")
    if subtype == "NUMERIC_CONTRADICTION":
        out.append("Obtain raw measurement, instrument/calibration context, and uncertainty bounds.")
    return out


def specialist_handoffs_for(predicate):
    p = predicate
    if p in {"revenue", "financial", "invoice", "payment"}:
        return ["FININT"]
    if p in {"owns", "owner", "director", "controls", "status"}:
        return ["CORPINT", "OWNERSHIPINT"]
    if p in {"active", "domain", "dns", "ip", "service"}:
        return ["DNSINT", "NETINT", "INFRAINT"]
    if p in {"malicious", "compromised", "vulnerable"}:
        return ["MALINT", "VULNINT", "CYBINT"]
    if p in {"paper", "study", "replication"}:
        return ["ACADEMICINT"]
    return ["CONTRADICTIONINT"]


def possible_explanations_for(resolution, independence):
    base = [
        "Different entity",
        "Different time",
        "Different scope",
        "Unit/schema mismatch",
        "Stale information",
        "Legitimate correction/version change",
        "Measurement uncertainty",
        "Processing/parser artifact",
        "Translation/transcription ambiguity",
        "Partial visibility",
        "Genuine source disagreement",
    ]
    if independence == "DEPENDENT":
        base.append("Downstream copy or shared upstream origin may explain conflict.")
    if resolution == "PERSISTENT_CONTRADICTION":
        base.append("Conflict may be real; deception is NOT inferred from conflict alone.")
    return base


# -----------------------------
# Core analyzer
# -----------------------------

def analyze(case):
    case_id = case.get("case_id", "CONTRA-CASE")
    objective = case.get("objective", "")
    sources = case.get("sources") or {}
    claims_raw = case.get("claims") or []

    evidence = [{
        "evidence_id": "EV-INPUT",
        "source_id": "authorized_case_input",
        "observed_at": NOW(),
        "note": "Input-only contradiction analysis. No external source access assumed.",
    }]

    if any(re.search(p, objective.lower()) for p in POLICY_BLOCK_PATTERNS):
        return {
            "case_id": case_id,
            "status": "POLICY_BLOCKED",
            "objective": objective,
            "findings": [{
                "kind": "POLICY_BLOCKED",
                "statement": "CONTRADICTIONINT does not declare deception/liars merely from conflicting evidence.",
                "human_review": True,
            }],
            "recommendations": [
                "Continue with evidence-first conflict detection and resolution.",
                "Preserve disagreement when evidence does not resolve it.",
                "Do not infer malicious intent from contradiction alone.",
            ],
            "evidence": evidence,
        }

    if not claims_raw:
        return {
            "case_id": case_id,
            "status": "PARTIAL",
            "objective": objective,
            "contradictions": [],
            "knowledge_gaps": [{"kind": "NO_CLAIMS_PROVIDED", "statement": "No claims supplied."}],
            "recommendations": ["Provide claims with subject, predicate, object, time, scope, and source."],
            "evidence": evidence,
        }

    claims = []
    for i, c in enumerate(claims_raw):
        predicate = norm(c.get("predicate"))
        predicate = PREDICATE_SYNONYMS.get(predicate, predicate)

        claims.append({
            "claim_id": c.get("claim_id") or f"CLAIM-{i+1}",
            "subject": c.get("subject"),
            "subject_entity_id": c.get("subject_entity_id"),
            "predicate": predicate,
            "object_raw": c.get("object"),
            "object_parsed": parse_object(c.get("object")),
            "qualifiers": {norm(k): norm(str(v)) for k, v in (c.get("qualifiers") or {}).items()},
            "valid_from": parse_dt(c.get("valid_from") or c.get("event_from") or c.get("observed_at")),
            "valid_to": parse_dt(c.get("valid_to") or c.get("event_to") or c.get("observed_at")),
            "observed_at": parse_dt(c.get("observed_at")),
            "source_id": c.get("source_id"),
            "evidence_ids": to_list(c.get("evidence_ids")),
            "version": c.get("version"),
            "supersedes": to_set(c.get("supersedes")),
            "corrects": to_set(c.get("corrects")),
            "retracts": to_set(c.get("retracts")),
            "replaces": to_set(c.get("replaces")),
            "amends": to_set(c.get("amends")),
        })

    contradictions = []
    knowledge_gaps = []
    fact_state_changes = []

    def add_gap(kind, claim_ids, statement):
        key = (kind, tuple(sorted(claim_ids)))
        if not any(g.get("_key") == key for g in knowledge_gaps):
            knowledge_gaps.append({
                "_key": key,
                "kind": kind,
                "claim_ids": sorted(claim_ids),
                "statement": statement,
            })

    def make_contra(
        a, b, ctype, subtype, resolution, reason,
        entity, temporal, scope, unit, semantic,
        independence, favored=None
    ):
        materiality = materiality_for(a["predicate"], resolution, semantic)
        severity = severity_for(materiality, independence, resolution)
        confidence = confidence_label(entity, temporal, scope, semantic)

        contra = {
            "contradiction_id": f"CONTRA-{len(contradictions)+1}",
            "claim_a_id": a["claim_id"],
            "claim_b_id": b["claim_id"],
            "contradiction_type": ctype,
            "subtype": subtype,
            "entity_alignment": entity,
            "temporal_alignment": temporal,
            "scope_alignment": scope,
            "unit_alignment": unit,
            "semantic_alignment": semantic,
            "source_a": a.get("source_id"),
            "source_b": b.get("source_id"),
            "source_independence": independence,
            "severity": severity,
            "materiality": materiality,
            "resolution_state": resolution,
            "resolution_reason": reason,
            "favored_interpretation_if_any": favored,
            "required_evidence": required_evidence_for(
                entity, temporal, scope, unit, independence, subtype
            ),
            "confidence": confidence,
            "possible_explanations": possible_explanations_for(resolution, independence),
            "specialist_handoffs": specialist_handoffs_for(a["predicate"]),
            "notes": [
                "Contradiction does not establish falsehood.",
                "Conflict does not establish deception.",
                "Both claims are preserved in history.",
            ],
            "created_at": NOW(),
        }
        contradictions.append(contra)

        if resolution == "PERSISTENT_CONTRADICTION" and materiality == "MATERIAL":
            for cid in (a["claim_id"], b["claim_id"]):
                fact_state_changes.append({
                    "claim_id": cid,
                    "proposed_state": "DISPUTED",
                    "reason": "Material unresolved contradiction.",
                    "not_false": True,
                })

    for a, b in itertools.combinations(claims, 2):
        rel = relation_between(a, b)
        if rel:
            rel_type, winner_id, loser_id = rel
            winner = next(c for c in claims if c["claim_id"] == winner_id)
            loser = next(c for c in claims if c["claim_id"] == loser_id)

            resolution = (
                "RESOLVED_BY_SOURCE_CORRECTION"
                if rel_type in ("CORRECTS", "RETRACTS")
                else "RESOLVED_BY_VERSION"
            )
            reason = (
                f"{winner_id} {rel_type.lower()} {loser_id}. "
                "Later/correcting claim is tracked, but newer is not automatically true."
            )

            make_contra(
                winner, loser,
                ctype="VERSION_CONTRADICTION",
                subtype=rel_type,
                resolution=resolution,
                reason=reason,
                entity="SAME_VERIFIED",
                temporal="EXACT_OVERLAP",
                scope="SAME_SCOPE",
                unit="UNKNOWN",
                semantic="INCOMPATIBLE",
                independence=source_independence(winner.get("source_id"), loser.get("source_id"), sources),
                favored=f"{winner_id} may supersede {loser_id} pending authority verification.",
            )
            continue

        entity = align_entity(a, b)
        if entity == "UNKNOWN":
            add_gap(
                "ENTITY_ALIGNMENT_UNKNOWN",
                [a["claim_id"], b["claim_id"]],
                "Claims may not refer to the same subject/predicate. No contradiction asserted.",
            )
            continue

        temporal = align_temporal(a, b, case)
        scope = align_scope(a, b, case)
        semantic = compare_objects(a["object_parsed"], b["object_parsed"])
        unit = align_unit(a["object_parsed"], b["object_parsed"])
        independence = source_independence(a.get("source_id"), b.get("source_id"), sources)

        if temporal == "NON_OVERLAPPING":
            make_contra(
                a, b,
                ctype="APPARENT_CONTRADICTION",
                subtype="TEMPORAL_CONTRADICTION",
                resolution="RESOLVED_BY_TIME",
                reason="Claims apply to non-overlapping time intervals.",
                entity=entity,
                temporal=temporal,
                scope=scope,
                unit=unit,
                semantic=semantic,
                independence=independence,
            )
            continue

        if scope == "DIFFERENT_SCOPE":
            make_contra(
                a, b,
                ctype="APPARENT_CONTRADICTION",
                subtype="SCOPE_CONTRADICTION",
                resolution="RESOLVED_BY_SCOPE",
                reason="Claims use different scope qualifiers.",
                entity=entity,
                temporal=temporal,
                scope=scope,
                unit=unit,
                semantic=semantic,
                independence=independence,
            )
            continue

        if semantic in ("EQUIVALENT", "COMPATIBLE"):
            make_contra(
                a, b,
                ctype="APPARENT_CONTRADICTION",
                subtype="UNIT_OR_SEMANTIC_CONTRADICTION",
                resolution="RESOLVED_BY_UNIT_NORMALIZATION" if unit == "SAME_UNIT" else "APPARENT_CONTRADICTION_RESOLVED",
                reason="After normalization, values are equivalent or compatible.",
                entity=entity,
                temporal=temporal,
                scope=scope,
                unit=unit,
                semantic=semantic,
                independence=independence,
            )
            continue

        if semantic == "UNKNOWN":
            add_gap(
                "SEMANTIC_ALIGNMENT_UNKNOWN",
                [a["claim_id"], b["claim_id"]],
                "Objects differ, but ontology/semantics do not establish incompatibility.",
            )
            continue

        # semantic == INCOMPATIBLE
        if temporal == "TIME_UNKNOWN":
            add_gap(
                "TEMPORAL_ALIGNMENT_UNKNOWN",
                [a["claim_id"], b["claim_id"]],
                "Incompatible values observed, but time alignment is unknown.",
            )
            continue

        if scope == "UNKNOWN":
            add_gap(
                "SCOPE_ALIGNMENT_UNKNOWN",
                [a["claim_id"], b["claim_id"]],
                "Incompatible values observed, but scope alignment is unknown.",
            )
            continue

        ctype = "SOURCE_SELF_CONTRADICTION" if a.get("source_id") and a.get("source_id") == b.get("source_id") else "CROSS_SOURCE_CONTRADICTION"
        subtype = subtype_for(a["object_parsed"], b["object_parsed"], semantic)

        if independence == "DEPENDENT":
            resolution = "PARTIALLY_RESOLVED"
            reason = "Sources are dependent; conflict may reflect copying/shared upstream, but disagreement is preserved."
        elif independence == "UNKNOWN":
            resolution = "INSUFFICIENT_EVIDENCE"
            reason = "Values are incompatible under current alignment, but source independence is unknown."
        else:
            resolution = "PERSISTENT_CONTRADICTION"
            reason = "Independent evidence paths conflict after entity/time/scope/unit alignment."

        make_contra(
            a, b,
            ctype=ctype,
            subtype=subtype,
            resolution=resolution,
            reason=reason,
            entity=entity,
            temporal=temporal,
            scope=scope,
            unit=unit,
            semantic=semantic,
            independence=independence,
        )

    for g in knowledge_gaps:
        g.pop("_key", None)

    persistent = any(c["resolution_state"] == "PERSISTENT_CONTRADICTION" for c in contradictions)
    insufficient = any(c["resolution_state"] in ("INSUFFICIENT_EVIDENCE", "PARTIALLY_RESOLVED") for c in contradictions)

    if persistent:
        status = "PERSISTENT_CONTRADICTION"
    elif insufficient or knowledge_gaps:
        status = "INCONCLUSIVE"
    elif contradictions:
        status = "APPARENT_CONTRADICTIONS_RESOLVED"
    else:
        status = "NO_MATERIAL_CONTRADICTION_DETECTED"

    human_review_required = any(
        c["severity"] in ("HIGH", "CRITICAL") or
        (c["resolution_state"] == "PERSISTENT_CONTRADICTION" and c["materiality"] == "MATERIAL")
        for c in contradictions
    )

    recommendations = [
        "Do not infer deception, lying, or malice from contradiction alone.",
        "Preserve both claims and their source lineage.",
        "Resolve entity, time, scope, units, and ontology before treating conflict as material.",
        "Prefer independent primary evidence over repeated downstream copies.",
        "Do not average conflicting values without mathematical justification.",
        "Use specialist handoffs for domain-specific verification.",
    ]

    if human_review_required:
        recommendations.append("HUMAN_REVIEW_REQUIRED for material unresolved contradictions.")

    limitations = [
        "Offline skeleton; no live source retrieval is assumed.",
        "Semantic alignment is conservative and ontology-dependent.",
        "Unresolved conflict is a valid intelligence outcome.",
    ]

    if case.get("demo_data_is_synthetic"):
        limitations.append("Demo claims/sources are synthetic placeholders, not real evidence.")

    return {
        "case_id": case_id,
        "status": status,
        "objective": objective,
        "demo_data_is_synthetic": bool(case.get("demo_data_is_synthetic")),
        "human_review_required": human_review_required,
        "contradictions": contradictions,
        "fact_state_changes": fact_state_changes,
        "knowledge_gaps": knowledge_gaps,
        "recommendations": recommendations,
        "limitations": limitations,
        "evidence": evidence,
        "generated_at": NOW(),
    }


# -----------------------------
# Synthetic demo
# -----------------------------

if __name__ == "__main__":
    demo_case = {
        "case_id": "CONTRAINT-DEMO-001",
        "objective": "Defensively compare synthetic claims and preserve unresolved conflicts.",
        "demo_data_is_synthetic": True,

        # Allow pairwise comparison when qualifiers/time are omitted in some synthetic claims.
        "assume_same_scope_when_unspecified": True,
        "assume_same_time_when_unspecified": False,

        "sources": {
            "S1": {"source_id": "S1", "family": "primary_registry"},
            "S2": {"source_id": "S2", "family": "independent_observation"},
            "S3": {"source_id": "S3", "family": "downstream_copy", "upstream_id": "S1", "cites": ["S1"]},
        },

        "claims": [
            {
                "claim_id": "C1",
                "subject": "Company C",
                "subject_entity_id": "ENT-COMPANY-C",
                "predicate": "director",
                "object": "Person A",
                "valid_from": "2024-01-01",
                "valid_to": "2025-12-31",
                "source_id": "S1",
            },
            {
                "claim_id": "C2",
                "subject": "Company C",
                "subject_entity_id": "ENT-COMPANY-C",
                "predicate": "director",
                "object": "Person B",
                "valid_from": "2026-01-01",
                "valid_to": "2026-12-31",
                "source_id": "S2",
            },
            {
                "claim_id": "C3",
                "subject": "Company C",
                "subject_entity_id": "ENT-COMPANY-C",
                "predicate": "revenue_2024",
                "object": "10M USD",
                "valid_from": "2024-01-01",
                "valid_to": "2024-12-31",
                "source_id": "S1",
            },
            {
                "claim_id": "C4",
                "subject": "Company C",
                "subject_entity_id": "ENT-COMPANY-C",
                "predicate": "revenue_2024",
                "object": "10,000,000 USD",
                "valid_from": "2024-01-01",
                "valid_to": "2024-12-31",
                "source_id": "S2",
            },
            {
                "claim_id": "C5",
                "subject": "Domain D",
                "subject_entity_id": "ENT-DOMAIN-D",
                "predicate": "active",
                "object": True,
                "valid_from": "2026-10-01",
                "valid_to": "2026-10-09",
                "qualifiers": {"environment": "production"},
                "source_id": "S1",
            },
            {
                "claim_id": "C6",
                "subject": "Domain D",
                "subject_entity_id": "ENT-DOMAIN-D",
                "predicate": "active",
                "object": False,
                "valid_from": "2026-10-01",
                "valid_to": "2026-10-09",
                "qualifiers": {"environment": "production"},
                "source_id": "S2",
            },
            {
                "claim_id": "C7",
                "subject": "Policy P",
                "subject_entity_id": "ENT-POLICY-P",
                "predicate": "permits_x",
                "object": True,
                "version": 1,
                "source_id": "S1",
            },
            {
                "claim_id": "C8",
                "subject": "Policy P",
                "subject_entity_id": "ENT-POLICY-P",
                "predicate": "permits_x",
                "object": False,
                "version": 2,
                "supersedes": ["C7"],
                "source_id": "S1",
            },
        ],
    }

    result = analyze(demo_case)
    print(json.dumps(result, indent=2, ensure_ascii=False))
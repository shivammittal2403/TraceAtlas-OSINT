"""Evidence context builder: deterministic, schema-checked input for AI passes.

Section 8 rule implemented here: BEFORE any AI pass sees a connector result we
run deterministic validation. Failures are labeled INVALID / MALFORMED /
PARTIAL / SCHEMA_DRIFT / STALE / UNKNOWN and passed through as labels — the AI
is never asked to silently repair evidence.

External content is wrapped in untrusted-data delimiters so downstream prompt
templates can treat it strictly as data (prompt-injection defense layer 1).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from traceatlas.investigation.context import InvestigationContext

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

UNTRUSTED_BEGIN = "<<<UNTRUSTED_SOURCE_DATA id={}>>>"
UNTRUSTED_END = "<<<END_UNTRUSTED_SOURCE_DATA id={}>>>"


@dataclass
class ValidationIssue:
    record_id: str
    code: str        # INVALID | MALFORMED | SCHEMA_DRIFT | STALE | UNKNOWN | PARTIAL
    detail: str


@dataclass
class EvidenceContext:
    """Everything an analysis pass legitimately needs — JSON-safe."""
    case_id: str
    objective: str = ""
    questions: list[str] = field(default_factory=list)
    evidence_rows: list[dict] = field(default_factory=list)
    observation_rows: list[dict] = field(default_factory=list)
    entity_rows: list[dict] = field(default_factory=list)
    relationship_rows: list[dict] = field(default_factory=list)
    known_evidence_ids: set[str] = field(default_factory=set)
    validation_issues: list[ValidationIssue] = field(default_factory=list)

    def render_for_prompt(self, max_items: int = 120) -> str:
        lines: list[str] = []
        if self.objective:
            lines.append(f"OBJECTIVE: {self.objective}")
        for q in self.questions:
            lines.append(f"QUESTION: {q}")
        for row in self.evidence_rows[:max_items]:
            eid = row["id"]
            lines.append(UNTRUSTED_BEGIN.format(eid))
            lines.append(
                f"EVIDENCE {eid} tier={row['tier']} source={row['source_id'] or 'unknown'} "
                f"url={row['url'] or '-'} captured={row['captured_at']} sha256={row['sha256'][:16]}...")
            if row.get("content_excerpt"):
                lines.append(f"EXCERPT: {row['content_excerpt'][:400]}")
            lines.append(UNTRUSTED_END.format(eid))
        for row in self.observation_rows[:max_items]:
            lines.append(f"OBSERVATION {row['id']}: {row['predicate']} "
                         f"{row['subject']} -> {row['obj']} (evidence {row['evidence_id']}, "
                         f"observed {row['observed_at']})")
        for row in self.entity_rows[:max_items]:
            lines.append(f"ENTITY {row['key']}: type={row['type']} name={row['display_name']}")
        for row in self.relationship_rows[:max_items]:
            lines.append(f"RELATIONSHIP: {row['source_key']} -[{row['type']}]-> "
                         f"{row['target_key']} (evidence {','.join(row['evidence_ids']) or 'NONE'})")
        issues = [f"ISSUE {i.record_id}: {i.code} ({i.detail})" for i in self.validation_issues]
        if issues:
            lines.append("DETERMINISTIC VALIDATION ISSUES (do not repair; account for them):")
            lines.extend(issues)
        return "\n".join(lines)


def validate_syntax(kind: str, value: str) -> tuple[bool, str]:
    """Deterministic syntax gate for common identifier types."""
    v = value.strip()
    if kind == "domain":
        return bool(DOMAIN_RE.match(v)), f"invalid domain syntax: {value!r}"
    if kind == "ipv4":
        try:
            ipaddress.IPv4Address(v)
            return True, ""
        except ValueError:
            return False, f"invalid IPv4: {value!r}"
    if kind == "ipv6":
        try:
            ipaddress.IPv6Address(v)
            return True, ""
        except ValueError:
            return False, f"invalid IPv6: {value!r}"
    if kind == "ip":
        ok4, _ = validate_syntax("ipv4", v)
        ok6, _ = validate_syntax("ipv6", v)
        return (ok4 or ok6), f"invalid IP literal: {value!r}"
    if kind == "cve":
        return bool(CVE_RE.match(v)), f"invalid CVE id: {value!r}"
    if kind == "email":
        return bool(EMAIL_RE.match(v)), f"invalid email: {value!r}"
    if kind == "sha256":
        return bool(SHA256_RE.match(v.lower())), f"invalid sha256 hex: {value!r}"
    if kind == "asn":
        return bool(re.match(r"^AS?\d{1,7}$", v, re.I)), f"invalid ASN: {value!r}"
    return True, ""


def stale_check(captured_at: datetime, max_age_days: float = 30.0) -> bool:
    now = datetime.now(timezone.utc)
    ts = captured_at if captured_at.tzinfo else captured_at.replace(tzinfo=timezone.utc)
    return (now - ts) > timedelta(days=max_age_days)


def build_evidence_context(ctx: InvestigationContext, *, objective: str = "",
                           questions: list[str] | None = None,
                           content_excerpts: dict[str, str] | None = None,
                           stale_days: float = 30.0) -> EvidenceContext:
    """Snapshot the context with deterministic validation applied."""
    ec = EvidenceContext(case_id=ctx.case_id, objective=objective,
                         questions=list(questions or []))
    excerpts = content_excerpts or {}
    for rec in ctx.evidence.values():
        ec.known_evidence_ids.add(rec.id)
        row = {"id": rec.id, "tier": rec.tier.value, "source_id": rec.source_id,
               "url": rec.url, "captured_at": rec.captured_at.isoformat(),
               "sha256": rec.sha256, "content_excerpt": excerpts.get(rec.id, "")}
        ec.evidence_rows.append(row)
        # deterministic gates on the record itself
        if not SHA256_RE.match(rec.sha256.lower()):
            ec.validation_issues.append(
                ValidationIssue(rec.id, "INVALID", "digest is not sha256 hex"))
        if stale_check(rec.captured_at, stale_days):
            ec.validation_issues.append(
                ValidationIssue(rec.id, "STALE",
                                f"older than {stale_days:g} days at capture-review time"))
        if rec.url and not rec.url.startswith(("http://", "https://")):
            ec.validation_issues.append(
                ValidationIssue(rec.id, "MALFORMED", f"bad url scheme: {rec.url[:60]}"))
    for obs in ctx.observations:
        if obs.evidence_id not in ctx.evidence:
            ec.validation_issues.append(
                ValidationIssue(obs.id, "SCHEMA_DRIFT",
                                f"observation references unknown evidence {obs.evidence_id}"))
            continue
        ec.observation_rows.append(
            {"id": obs.id, "predicate": obs.predicate, "subject": obs.subject,
             "obj": obs.obj, "evidence_id": obs.evidence_id,
             "observed_at": obs.observed_at.isoformat()})
    # entity id -> display key map so relationships render readable endpoints
    ent_by_id = {ent.id: key for key, ent in ctx.entities.items()}
    for key, ent in ctx.entities.items():
        etype = ent.entity_type.value if hasattr(ent.entity_type, "value") else str(ent.entity_type)
        ec.entity_rows.append({"key": key, "id": ent.id, "type": etype,
                               "display_name": ent.display_name})
    for rel in ctx.relationships:
        eids = list(rel.evidence_ids)
        unknown = [e for e in eids if e not in ctx.evidence]
        if unknown:
            ec.validation_issues.append(
                ValidationIssue(rel.id, "INVALID",
                                f"relationship cites unknown evidence {unknown}"))
        rtype = rel.relationship_type.value if hasattr(rel.relationship_type, "value") \
            else str(rel.relationship_type)
        ec.relationship_rows.append(
            {"source_key": ent_by_id.get(rel.source_entity_id, rel.source_entity_id),
             "type": rtype,
             "target_key": ent_by_id.get(rel.target_entity_id, rel.target_entity_id),
             "evidence_ids": eids})
    return ec

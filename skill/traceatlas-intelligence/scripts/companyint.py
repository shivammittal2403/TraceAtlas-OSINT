import sys
from pathlib import Path as _Path
_repo_root = _Path(__file__).resolve().parents[3]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))
from allint52 import _support
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
from urllib.parse import urlparse


APP_TITLE = "TraceAtlas CORPINT AI Employee — Lawful / Public-Record / Authorized Corporate Intelligence Panel"
APP_VERSION = "TraceAtlas CORPINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target", "Target / Company / Entity Context", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "CORPINT Questions", "text"),

    ("company_names", "Company Names / Aliases", "text"),
    ("registration_numbers", "Registration Numbers / LEI / Tax IDs", "text"),
    ("jurisdictions", "Jurisdictions", "text"),
    ("directors", "Directors / Officers", "text"),
    ("shareholders", "Shareholders / Owners", "text"),
    ("brands", "Brands / Trade Names", "text"),
    ("domains", "Domains / Websites", "text"),
    ("addresses", "Addresses (Registered/Operating)", "text"),
    
    ("filings_inline", "Inline Filing Metadata", "text"),
    ("ownership_data", "Ownership / Shareholding Data", "text"),
    ("financial_data", "Financial Statement Summaries", "text"),
    ("regulatory_records", "Regulatory Actions / Court Records", "text"),
    ("procurement_records", "Procurement Contracts / Awards", "text"),
    ("trade_records", "Trade Relationships (Supplier/Customer)", "text"),
    ("sanctions_data", "Sanctions / Watchlist Matches", "text"),

    ("registry_paths", "Registry Export Paths", "text"),
    ("filing_paths", "Corporate Filing Paths", "text"),
    ("annual_report_paths", "Annual Report Paths", "text"),
    ("ownership_registry_paths", "Beneficial Ownership Registry Paths", "text"),
    ("court_record_paths", "Court / Legal Record Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("jurisdiction_default", "Default Jurisdiction", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget", "Budget", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (Registry API/KYC/etc.)", "text"),
]


TARGET_TYPES = [
    "legal_entity_resolution",
    "corporate_structure_analysis",
    "director_officer_history",
    "shareholder_ownership",
    "beneficial_owner_context",
    "financial_filing_review",
    "insolvency_dissolution_check",
    "m_a_restructuring",
    "regulatory_legal_context",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "company_names",
    "registration_numbers",
    "jurisdictions",
    "directors",
    "shareholders",
    "brands",
    "domains",
    "addresses",
    "filings_inline",
    "ownership_data",
    "financial_data",
    "regulatory_records",
    "procurement_records",
    "trade_records",
    "sanctions_data",
    "registry_paths",
    "filing_paths",
    "annual_report_paths",
    "ownership_registry_paths",
    "court_record_paths",
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
    "legal_entity_resolution",
    "corporate_structure_analysis",
    "director_officer_history",
    "shareholder_ownership",
    "beneficial_owner_context",
    "financial_filing_review",
    "insolvency_dissolution_check",
    "m_a_restructuring",
    "regulatory_legal_context",
}


POLICY_BLOCK_PATTERNS = [
    r"\b(?:hack|breach|intrude)\b[^\n]{0,140}\b(?:registry|database|portal|system)\b",
    r"\b(?:bypass|circumvent)\b[^\n]{0,140}\b(?:authentication|login|security|access control)\b",
    r"\b(?:use|apply)\b[^\n]{0,140}\b(?:stolen credential|leaked password|private key|token)\b\s+(?:to access|for login)",
    r"\b(?:dox|expose|publish)\b[^\n]{0,140}\b(?:home address|personal phone|private email|family member|medical record)\b",
    r"\b(?:trade|buy|sell)\b[^\n]{0,140}\b(?:insider information|material non-public information|MNPI)\b",
    r"\b(?:design|create|plan)\b[^\n]{0,140}\b(?:shell company|hidden ownership|sanctions evasion|tax evasion structure)\b",
    r"\b(?:fabricate|forge|fake)\b[^\n]{0,140}\b(?:company record|ownership document|filing|signature)\b",
]


SAFE_ALTERNATIVES = [
    "Provide lawful/public-record/authorized corporate intelligence: entity resolution, registration validation, director/officer timelines, shareholder analysis, ownership chains, financial filing context, and risk signal detection.",
    "Do not hack registries, bypass authentication, use stolen credentials, dox individuals, publish private addresses, trade on insider info, design evasion structures, or fabricate records.",
    "Separate concepts: Company != Brand, Director != Owner, Shareholder != Beneficial Owner, Active Status != Operating Business.",
    "Minimize sensitive data: Use masked identifiers where possible, avoid exposing residential addresses unless legally required and relevant.",
    "Escalate consequential findings (fraud allegations, sanctions implications) to authorized human/legal review.",
]


SECRET_PATTERNS = [
    (
        "PRIVATE_KEY_BLOCK",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.S | re.I,
        ),
    ),
    (
        "PASSWORD_OR_TOKEN_ASSIGNMENT",
        re.compile(
            r"(?i)\b(password|passwd|pwd|token|api[_-]?key|apikey|secret|"
            r"access[_-]?key|auth[_-]?key|client[_-]?secret|authorization|cookie|session|credential)\b"
            r"\s*[:=]\s*[^\s,;\"']+"
        ),
    ),
]


PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?previous\s+(?:instructions|rules)",
    r"reveal\s+(?:the\s+)?system\s+prompt",
    r"send\s+(?:data|report)\s+to",
    r"login\s+(?:here|to)",
    r"execute\s+(?:code|script)",
]


# Regex helpers
DOMAIN_RE = re.compile(r"\b(?:https?://)?(?:www\.)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,})\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")

REGISTRATION_NUM_RE = re.compile(r"\b[A-Z0-9]{8,15}\b") # Generic placeholder for Reg No patterns

COMPANY_SUFFIXES = [
    "ltd", "limited", "llc", "plc", "inc", "corp", "corporation", 
    "gmbh", "bv", "sa", "sas", "srl", "spa", "pty ltd", "pvt ltd", "llp"
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


def normalize_company_name(name: Any) -> str:
    """
    Normalize company name by removing common suffixes and punctuation for matching.
    Preserves original in other fields.
    """
    s = str(name or "").strip().lower()
    # Remove suffixes
    for suffix in COMPANY_SUFFIXES:
        if s.endswith(suffix):
            s = s[:-len(suffix)].strip()
    # Remove punctuation
    s = re.sub(r"[^a-z0-9\s]", "", s)
    # Collapse whitespace
    s = re.sub(r"\s+", " ", s)
    return s


def extract_domains(text: str) -> List[str]:
    out = []
    for m in DOMAIN_RE.finditer(text or ""):
        d = m.group(1).lower()
        if d not in out:
            out.append(d)
    return out


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "companies": [],
        "persons": [], # Directors/Officers/Shareholders
        "relationships": [], # Parent/Sub, Dir of, Owns
        "filings": [],
        "observations": [],
        "notes": [],
        "contradictions": [],
        "hypotheses": [],
        "knowledge_gaps": [],
        "specialist_handoffs": [],
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
            "Human/corporate statement is evidence about a proposition, not self-validating fact.",
            "Registry entry does not prove economic reality or intent.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Embedded instructions in filings/docs are ignored.")


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
            "Aggregators/copies are not independent sources.",
        ],
    })


def add_company(
    parsed: Dict[str, Any],
    legal_name: Any,
    reg_num: Any,
    jurisdiction: Any,
    status: Any,
    incorporation_date: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
    source_company_id: Any = "",
) -> Optional[str]:
    ln = safe_str(legal_name, 200)
    rn = safe_str(reg_num, 100)
    supplied_id = safe_str(source_company_id, 100)
    
    if not ln and not rn:
        return None
        
    norm_ln = normalize_company_name(ln)
    
    # Check existing
    for c in parsed["companies"]:
        same_registration = rn and c.get("registration_number") == rn
        same_source_id = supplied_id and c.get("source_company_id") == supplied_id and c.get("source_id") == source_id
        if c.get("normalized_name") == norm_ln and (same_registration or same_source_id):
            # Update missing fields
            if status and not c.get("status"): c["status"] = status
            if incorporation_date and not c.get("incorporation_date"): c["incorporation_date"] = incorporation_date
            return c.get("company_id")

    cid = f"CMP-{uuid.uuid4()}"
    parsed["companies"].append({
        "company_id": cid,
        "legal_name": ln,
        "normalized_name": norm_ln,
        "registration_number": rn,
        "source_company_id": supplied_id,
        "jurisdiction": safe_str(jurisdiction, 100),
        "status": safe_str(status, 50), # ACTIVE, DISSOLVED, etc.
        "incorporation_date": safe_str(incorporation_date, 50),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ENTITY_CANDIDATE",
        "limitations": [
            "Same name != Same entity. Require Reg Num/Jurisdiction match.",
            "Active status != Operating business.",
        ],
    })
    return cid


def add_person(
    parsed: Dict[str, Any],
    name: Any,
    role: Any, # DIRECTOR, OFFICER, SHAREHOLDER
    company_id: Optional[str],
    appointment_date: Any,
    resignation_date: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    pn = safe_str(name, 200)
    if not pn:
        return None
    
    norm_pn = normalize_text(pn)
    
    pid = f"PER-{uuid.uuid4()}"
    
    # Note: In real system, we'd try to resolve Person Identity across companies.
    # Here we create a person-role instance linked to specific company/time.
    
    parsed["persons"].append({
        "person_instance_id": pid,
        "name": pn,
        "normalized_name": norm_pn,
        "role": safe_str(role, 50),
        "linked_company_id": company_id,
        "appointment_date": safe_str(appointment_date, 50),
        "resignation_date": safe_str(resignation_date, 50),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ROLE_OBSERVED",
        "limitations": [
            "Director != Owner.",
            "Historical Director != Current Director.",
            "Name Collision Possible.",
        ],
    })
    return pid


def add_relationship(
    parsed: Dict[str, Any],
    from_entity: str, # Company ID or Person Instance ID
    to_entity: str,   # Company ID
    rel_type: str,    # PARENT_OF, SUBSIDIARY_OF, OWNS_SHARES, DIRECTOR_OF
    percentage: Optional[float],
    share_class: Optional[str],
    effective_date: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    
    rid = f"REL-{uuid.uuid4()}"
    
    parsed["relationships"].append({
        "relationship_id": rid,
        "from_entity_id": from_entity,
        "to_entity_id": to_entity,
        "relationship_type": rel_type,
        "percentage": percentage,
        "share_class": share_class,
        "effective_date": safe_str(effective_date, 50),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "RELATIONSHIP_OBSERVED",
        "limitations": [
            "Parent != Ultimate Parent.",
            "Shareholder != Beneficial Owner.",
            "Percentage applies to specified class only.",
        ],
    })


def process_json_record(
    rec: Dict[str, Any],
    source_id: str,
    evidence_id: str,
    parsed: Dict[str, Any],
    context: str = "",
) -> None:
    rec = json.loads(_support.redact_text(json.dumps(rec, ensure_ascii=False, default=str)))
    if not isinstance(rec, dict):
        return

    rec_context = context or "json_record"
    
    # Identify Company
    comp_name = get_field(rec, ["company_name", "legal_name"])
    comp_reg = get_field(rec, ["registration_number", "reg_no", "lei", "tax_id"])
    source_company_id = get_field(rec, ["company_id"])
    person_context = any(normalize_key(part) in {
        "directors", "officers", "board_members", "shareholders", "owners", "equity_holders"
    } for part in rec_context.split("."))
    corporate_marker = comp_reg or source_company_id or get_field(rec, [
        "company_status", "incorporation_date", "established_on", "directors", "officers", "board_members"
    ])
    if not comp_name and corporate_marker and not person_context:
        comp_name = get_field(rec, ["name"])
    comp_juris = get_field(rec, ["jurisdiction", "country", "region"])
    comp_status = get_field(rec, ["status", "company_status"])
    comp_inc = get_field(rec, ["incorporation_date", "established_on"])
    
    cid = None
    if comp_name or comp_reg:
        cid = add_company(
            parsed,
            comp_name,
            comp_reg,
            comp_juris,
            comp_status,
            comp_inc,
            source_id,
            evidence_id,
            rec_context,
            source_company_id=source_company_id,
        )
        
    # Identify People (Directors/Officers)
    people_list = get_field(rec, ["directors", "officers", "board_members"], as_list=True)
    if isinstance(people_list, list):
        for p_item in people_list:
            if isinstance(p_item, dict):
                pname = p_item.get("name") or p_item.get("full_name")
                prole = p_item.get("role") or "DIRECTOR"
                padd = p_item.get("appointed_on") or p_item.get("start_date")
                presig = p_item.get("resigned_on") or p_item.get("end_date")
                
                if pname and cid:
                    add_person(
                        parsed,
                        pname,
                        prole,
                        cid,
                        padd,
                        presig,
                        source_id,
                        evidence_id,
                        f"{rec_context}/director"
                    )
                    
    # Identify Shareholders / Ownership
    shareholders_list = get_field(rec, ["shareholders", "owners", "equity_holders"], as_list=True)
    if isinstance(shareholders_list, list):
        for sh_item in shareholders_list:
            if isinstance(sh_item, dict):
                sh_name = sh_item.get("name") or sh_item.get("entity_name")
                sh_pct = get_field(sh_item, ["percentage", "ownership_share"])
                sh_class = sh_item.get("share_class")
                sh_eff = sh_item.get("effective_date")
                
                pct_float = None
                if sh_pct is not None and str(sh_pct).strip():
                    try:
                        pct_float = float(str(sh_pct).replace("%", "").strip())
                    except:
                        pass
                
                if sh_name and cid:
                    # Determine if shareholder is a person or another company
                    # Heuristic: If it looks like a company name, treat as Org Relationship, else Person
                    # For simplicity in this demo, we link via generic relationship
                    
                    # If it's a known company ID, link directly. Otherwise create temp entity ref.
                    # Here we just log the relationship string for now.
                    
                    add_relationship(
                        parsed,
                        sh_name, # Using name as ID proxy for demo
                        cid,
                        "OWNS_SHARES",
                        pct_float,
                        sh_class,
                        sh_eff,
                        source_id,
                        evidence_id,
                        f"{rec_context}/shareholder"
                    )

    # Process text blob for hidden entities
    text_blob = json.dumps(rec, ensure_ascii=False, default=str)[:5000]
    process_text_block(text_blob, source_id, evidence_id, parsed, context=rec_context)


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
                 caution="Filings/docs are untrusted data.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    # Extract Domains mentioned
    domains = extract_domains(redacted)
    for d in domains[:10]:
        add_note(parsed, "DOMAIN_MENTION", domain=d, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Domain mention != Verified Ownership.")


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


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:20000].lower()
    fname = normalize_text(filename)

    if "registry" in fname or "company_search" in low or "legal_entity" in keys:
        return "REGISTRY_RECORD"
    if "annual_report" in fname or "financial_statement" in keys:
        return "ANNUAL_REPORT_SUMMARY"
    if "director" in fname or "board" in low:
        return "BOARD_COMPOSITION_RECORD"
    if "shareholder" in fname or "cap_table" in low:
        return "SHAREHOLDING_RECORD"
    if "court" in fname or "litigation" in low:
        return "LEGAL_CASE_RECORD"
        
    return "GENERIC_CORPORATE_DATA"


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


def content_fingerprint(text: str) -> str:
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()


def process_json_file(path: Path, source_id: str, evidence_id: str) -> Tuple[str, Dict[str, Any]]:
    parsed = empty_parsed()
    raw = path.read_text(encoding="utf-8", errors="replace")[:30_000_000]
    redacted_raw, _ = redact_secrets(raw)
    fp = content_fingerprint(redacted_raw)
    data = json.loads(_support.redact_text(raw))
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
    kind = "CSV_CORPORATE_DATA"

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
    
    low = redacted_raw.lower()[:20000]
    if "certificate of incorporation" in low or "registry extract" in low:
        kind = "TEXT_REGISTRY_EXTRACT"
    elif "annual report" in low:
        kind = "TEXT_ANNUAL_REPORT"
    else:
        kind = "TEXT_CORPORATE_NOTE"

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

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".snapshot"}:
        return {"format_detected": "TEXT", "mime_type": "text/plain"}

    try:
        probe = head.decode("utf-8", errors="strict")
        if probe.strip():
            return {"format_detected": "TEXT", "mime_type": "text/plain"}
    except Exception:
        pass

    return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream"}


def analyze_corporate_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
            "No registry hacking, credential theft, doxxing, insider trading, or evasion scheme design performed.",
            "Binary artifacts (PDF/XLSX) are hash/metadata preserved only; no deep parsing executed in this stdlib-only panel.",
            "Corporate records are untrusted evidence, not instruction.",
            "Secrets are redacted.",
            "Entity existence != Economic Reality.",
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
            file_evidence["content_kind"] = "BINARY_CORP_DOC_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary corporate document detected. This planning panel preserves hash/metadata only. "
                "It does not execute macros, parse PDF/XLSX deeply, or extract hidden layers."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_company_count"] = len(parsed.get("companies", []))
    file_evidence["parsed_person_count"] = len(parsed.get("persons", []))
    file_evidence["parsed_rel_count"] = len(parsed.get("relationships", []))

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


def build_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []
    
    # Check for Duplicate Companies (Same Name, Different Reg No or vice versa)
    name_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for c in parsed.get("companies", []):
        name_map[c.get("normalized_name")].append(c)
        
    for norm_name, group in name_map.items():
        if len(group) > 1:
            regs = {c.get("registration_number") for c in group}
            juris = {c.get("jurisdiction") for c in group}
            
            # If same name but different reg/juris, likely distinct entities OR data conflict
            if len(regs) > 1 or len(juris) > 1:
                ids = [g['company_id'] for g in group]
                contradictions.append({
                    "contradiction_id": f"CON-{uuid.uuid4()}",
                    "type": "ENTITY_RESOLUTION_AMBIGUITY",
                    "subject": norm_name,
                    "values": {"registrations": list(regs)[:5], "jurisdictions": list(juris)[:5]},
                    "possible_explanations": [
                        "Distinct companies with similar names",
                        "Data entry error in one source",
                        "Re-registration under new number",
                    ],
                    "resolution_status": "UNRESOLVED",
                    "caution": "Do not merge entities without definitive identifier match.",
                })
                
    # Check for Director Conflicts (Same person, overlapping tenures at same company?)
    # Simplified: Just flag multiple entries for same person-name-company combo
    dir_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for p in parsed.get("persons", []):
        if p.get("role") == "DIRECTOR" and p.get("linked_company_id"):
            key = f"{p.get('normalized_name')}:{p.get('linked_company_id')}"
            dir_map[key].append(p)
            
    for key, group in dir_map.items():
        if len(group) > 1:
            dates = [(g.get('appointment_date'), g.get('resignation_date')) for g in group]
            # Simple check for overlaps would go here. For now, just flag duplicates.
            contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "DUPLICATE_DIRECTOR_ENTRY",
                "subject": key,
                "values": dates[:10],
                "possible_explanations": [
                    "Multiple appointments/terms",
                    "Data duplication from different sources",
                    "Correction of previous error",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Verify timeline carefully.",
            })

    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    comps = parsed.get("companies", [])
    rels = parsed.get("relationships", [])
    
    if not comps:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Insufficient corporate entity data to form structural hypotheses.",
            "supporting_facts": [],
            "opposing_facts": [],
            "unknowns": ["legal identity", "jurisdiction", "status"],
            "falsification_conditions": ["New registry records provided."],
            "next_test": "Ingest official registry extracts.",
            "status": "OPEN",
        })
        return hyps[:1000]

    # Example Hypothesis: Shell Company Characteristics
    # Heuristic: Minimal ops signals, formation agent address (hard to detect without geo DB), layered ownership
    complex_chains = [r for r in rels if r.get("relationship_type") == "OWNS_SHARES" and r.get("percentage")]
    
    if len(complex_chains) > 5:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Observed ownership structure involves multiple layers, potentially indicating SPV or holding structure.",
            "supporting_facts": [f"{len(complex_chains)} ownership links detected."],
            "opposing_facts": ["Legitimate conglomerates also have multi-layer structures."],
            "assumptions": ["Layers serve functional purpose."],
            "unknowns": ["Ultimate Beneficial Owner", "Purpose of intermediaries"],
            "falsification_conditions": ["All intermediate entities are operating businesses with employees/assets."],
            "next_test": "Handoff to OWNERSHIPINT for UBO resolution.",
            "status": "OPEN",
        })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    comps = parsed.get("companies", [])
    
    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What authorized corporate records exist?",
            "missing_evidence": "No local CORPINT artifact supplied.",
            "likely_source": "Official Registry Extract, Annual Report, Board Minute.",
            "specialist_owner": "CORPINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables baseline entity mapping.",
            "safety_boundary": "No hacking/doxxing/insider trading.",
        })

    if comps and not any(c.get("registration_number") for c in comps):
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What is the unique legal identifier for these entities?",
            "missing_evidence": "Registration numbers missing.",
            "likely_source": "Certificate of Incorporation, Registry Search Result.",
            "specialist_owner": "CORPINT",
            "priority": "CRITICAL_FOR_RESOLUTION",
            "expected_information_value": "Prevents false entity merging.",
            "safety_boundary": "Do not guess Reg Nos.",
        })
        
    if any(not c.get("jurisdiction") for c in comps):
         gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Under which law is this entity registered?",
            "missing_evidence": "Jurisdiction ambiguous.",
            "likely_source": "Registry Header, Legal Address Country Code.",
            "specialist_owner": "CORPINT / LEGALINT",
            "priority": "HIGH",
            "expected_information_value": "Determines applicable disclosure rules.",
            "safety_boundary": "Do not assume HQ country = Registration country.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    rels = parsed.get("relationships", [])
    comps = parsed.get("companies", [])
    
    # Ownership Handoff
    if any(r.get("relationship_type") == "OWNS_SHARES" for r in rels):
        handoffs.append({
            "specialist": "OWNERSHIPINT",
            "reason": "Shareholding relationships detected.",
            "expected_output": "UBO Resolution, Control Analysis, Nominee Detection.",
            "question": "Who ultimately benefits from this equity?",
        })
        
    # Financial Handoff
    if any("financial" in c.get("context", "").lower() for c in comps) or parsed.get("filings"):
        handoffs.append({
            "specialist": "FININT",
            "reason": "Corporate financial context available.",
            "expected_output": "Revenue/Cash Flow correlation, Solvency check.",
            "question": "Does the financial health match the corporate structure complexity?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "CORPINT Manager",
            "reason": "Standard corporate profile review.",
            "expected_output": "Due Diligence Summary.",
            "question": "Are there any adverse media or regulatory hits?",
        })

    return handoffs


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    parsed["contradictions"] = build_contradictions(parsed)
    parsed["hypotheses"] = build_hypotheses(parsed)
    parsed["knowledge_gaps"] = build_knowledge_gaps(payload or {}, files or [], parsed)
    parsed["specialist_handoffs"] = build_specialist_handoffs(parsed)
    return parsed


def build_next_best_action(
    payload: Dict[str, Any],
    policy: Dict[str, Any],
    files: List[Dict[str, Any]],
    parsed: Dict[str, Any],
) -> Dict[str, str]:
    comps = parsed.get("companies", [])
    
    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited hacking, doxxing, insider trading, or evasion behavior.",
            "reason": "CORPINT is lawful/public-record analytical, not illicit operational.",
            "owner": "CORPINT Manager",
            "expected_output": "Policy-compliant defensive scope.",
        }

    if not files:
        return {
            "action": "Attach authorized registry extracts, annual reports, or board minutes.",
            "reason": "No corporate evidence available.",
            "owner": "CORPINT AI Employee",
            "expected_output": "Evidence inventory.",
        }

    if comps and not any(c.get("registration_number") for c in comps):
        return {
            "action": "Retrieve official Certificate of Incorporation or Registry Search Result to resolve Legal Identifiers.",
            "reason": "Entity resolution incomplete without Reg No.",
            "owner": "CORPINT",
            "expected_output": "Verified Registration Numbers.",
        }

    return {
        "action": "Proceed with Director Timeline Reconstruction and Ownership Chain Mapping.",
        "reason": "Basic entities resolved; structural analysis required.",
        "owner": "CORPINT / OWNERSHIPINT",
        "expected_output": "Corporate Graph with Temporal Edges.",
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
    has_comps = bool(parsed.get("companies"))
    has_dirs = bool(parsed.get("persons"))

    def add(operation: str, tool: str, purpose: str, status: str, expected_output: str, safety_risk: str = "LOW", policy_note: str = "Lawful / Public-Record / Non-Intrusive.") -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General CORPINT planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": policy_note,
            "authorization_status": "ALLOWED_LAWFUL_PUBLIC",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "verify_authorization_and_scope",
        "Legal / Compliance",
        "Ensure data collection respects GDPR/CCPA and corporate privacy laws.",
        "COMPLETED_LOCAL" if payload.get("authorization") else "REQUIRED_BEFORE_COLLECTION",
        "Privacy Impact Assessment.",
        safety_risk="HIGH_IF_PRIVATE_DATA_EXPOSED",
        policy_note="No doxxing.",
    )

    add(
        "ingest_registry_records",
        "Local Parser",
        "Hash and ingest Official Registry Extracts.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized Company Objects.",
    )

    add(
        "resolve_legal_entities",
        "CORPINT Engine",
        "Match Name + Reg No + Jurisdiction to prevent false merges.",
        "COMPLETED_LOCAL" if has_comps else "PLANNED_ANALYTIC",
        "Unique Company IDs.",
        safety_risk="HIGH_IF_FALSE_MERGE",
        policy_note="Same Name != Same Entity.",
    )

    add(
        "map_director_timelines",
        "Temporal Graph Builder",
        "Track Appointment/Resignation dates accurately.",
        "COMPLETED_LOCAL" if has_dirs else "PLANNED_ANALYTIC",
        "Board History Graph.",
        safety_risk="MEDIUM_IF_CURRENT_HISTORICAL_CONFUSION",
        policy_note="Past Director != Current Director.",
    )

    add(
        "analyze_ownership_chains",
        "OWNERSHIPINT Handoff",
        "Trace Parent/Sub relationships and calculate indirect stakes.",
        "PLANNED_HANDOFF",
        "UBO Candidates or Unresolved Chains.",
        safety_risk="HIGH_IF_OVERCLAIMING_CONTROL",
        policy_note="Shareholder != Beneficial Owner.",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_text = " ".join(
        [
            str(payload.get("objective", "")),
            " ".join(str(q) for q in payload.get("questions", [])),
            str(payload.get("target", "")),
            " ".join(str(s) for s in payload.get("company_names", [])),
            " ".join(str(s) for s in payload.get("directors", [])),
        ]
    ).lower()

    blocked_reasons = [p for p in POLICY_BLOCK_PATTERNS if re.search(p, scanned_text, re.IGNORECASE)]

    human_review_required = False
    safety_notes: List[str] = []

    if payload.get("target_type") in SENSITIVE_TARGET_TYPES:
        human_review_required = True
        safety_notes.append(
            "Sensitive corporate context detected. Analysis must remain lawful, public-record based, and privacy-aware. "
            "No hacking, doxxing, or insider trading."
        )

    if payload.get("directors") or payload.get("shareholders"):
        human_review_required = True
        safety_notes.append(
            "Personal data context (Directors/Shareholders) detected. Strict adherence to privacy minimization required. Do not expose home addresses."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to involve unauthorized access, doxxing, insider trading, "
                "or designing evasion structures."
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
                "No obvious hard policy violation detected, but sensitive personal/corporate context applies. "
                "Conclusions must be reviewed by authorized humans before action."
            ),
            "safe_alternatives": SAFE_ALTERNATIVES,
        }

    return {
        "status": "ALLOWED_LAWFUL_PUBLIC",
        "reasons": [],
        "human_review_required": False,
        "safety_notes": [],
        "explanation": "No obvious policy violation detected. Planning-only mode remains active.",
        "safe_alternatives": [],
    }


def validate_payload(payload: Dict[str, Any]) -> List[str]:
    warnings: List[str] = []

    required = ["case_id", "task_id", "objective", "target", "target_type"]
    for field in required:
        if not payload.get(field):
            warnings.append(f"Missing required field: {field}")

    if not payload.get("questions"):
        warnings.append("No CORPINT questions provided. Default questions will be inferred.")

    evidence_keys = [
        "company_names",
        "registration_numbers",
        "directors",
        "shareholders",
        "registry_paths",
        "filing_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No corporate evidence provided. Output remains planning-only.")

    if not payload.get("jurisdictions") and not payload.get("jurisdiction_default"):
        warnings.append("No jurisdiction specified. Entity resolution requires jurisdiction context.")

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "Which legal entity corresponds to this name/registration number?",
        "What is the current registration status and jurisdiction?",
        "Who are the current directors and officers, and since when?",
        "Who were the historical directors?",
        "What is the shareholder structure and percentage ownership?",
        "Is there a beneficial owner identifiable through public records?",
        "What are the parent/subsidiary relationships?",
        "Are there any insolvency, dissolution, or regulatory actions recorded?",
        "What financial periods are covered in available filings?",
        "Which sources are independent versus aggregators of the same registry data?",
    ]


class TraceAtlasCORPINTPanel(tk.Tk):
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
        style.configure(
            "Header.TLabel",
            background="#0b0f19",
            foreground="#c084fc", # Violet/Purple for Corp
            font=("Segoe UI", 17, "bold"),
        )
        style.configure(
            "Subheader.TLabel",
            background="#0b0f19",
            foreground="#94a3b8",
            font=("Segoe UI", 9),
        )
        style.configure("TNotebook", background="#0b0f19", borderwidth=0)
        style.configure("TNotebook.Tab", padding=[14, 7], font=("Segoe UI", 10, "bold"))

        style.configure(
            "TEntry",
            fieldbackground="#111827",
            foreground="#e5e7eb",
            insertcolor="#ffffff",
            bordercolor="#334155",
            lightcolor="#334155",
            darkcolor="#334155",
        )

        style.configure(
            "TCombobox",
            fieldbackground="#111827",
            foreground="#e5e7eb",
            arrowcolor="#e5e7eb",
            bordercolor="#334155",
            lightcolor="#334155",
            darkcolor="#334155",
        )

        style.configure(
            "TButton",
            padding=7,
            font=("Segoe UI", 10, "bold"),
            background="#1f2937",
            foreground="#e5e7eb",
            bordercolor="#475569",
            lightcolor="#475569",
            darkcolor="#475569",
        )

        style.map(
            "TButton",
            background=[("active", "#334155")],
            foreground=[("active", "#ffffff")],
        )

        style.configure(
            "Vertical.TScrollbar",
            background="#1f2937",
            troughcolor="#0b0f19",
            arrowcolor="#e5e7eb",
        )

    def _build_ui(self) -> None:
        header = ttk.Frame(self)
        header.pack(fill="x", padx=16, pady=(14, 8))

        ttk.Label(header, text="TraceAtlas CORPINT AI Employee", style="Header.TLabel").pack(anchor="w")

        ttk.Label(
            header,
            text=(
                "Lawful / Public-Record / Authorized / Evidence-first corporate intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT company/director/filing parsing only • "
                "No registry hacking / no doxxing / no insider trading / no evasion design / no fabrication • "
                "Company != Brand • Director != Owner • Shareholder != Beneficial Owner • Active != Operating"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="CORPINT Task Input")
        self.notebook.add(self.output_tab, text="Output / CORPINT Plan / Evidence")

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
                widget = ttk.Combobox(
                    self.form,
                    values=TARGET_TYPES if key == "target_type" else [],
                    width=100,
                    state="readonly",
                )

            else:
                widget = tk.Text(
                    self.form,
                    height=3,
                    width=102,
                    bg="#111827",
                    fg="#e5e7eb",
                    insertbackground="white",
                    relief="flat",
                    highlightthickness=1,
                    highlightbackground="#334155",
                    font=("Segoe UI", 10),
                    wrap="word",
                )

            widget.grid(row=row, column=1, sticky="ew", padx=10, pady=6)
            self.entries[key] = widget
            row += 1

        self.form.columnconfigure(1, weight=1)

        buttons1 = ttk.Frame(self.input_tab)
        buttons1.pack(fill="x", padx=10, pady=(12, 4))

        buttons2 = ttk.Frame(self.input_tab)
        buttons2.pack(fill="x", padx=10, pady=(0, 12))

        ttk.Button(buttons1, text="Add Registry Exports", command=self.add_registry).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Filings", command=self.add_filings).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Annual Reports", command=self.add_annual_reports).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Ownership Registries", command=self.add_ownership_reg).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Court Records", command=self.add_court).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add STIX / MISP", command=self.add_stix_misp).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Analyze Local CORPINT Evidence", command=self.analyze_local_corpint).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate CORPINT Plan", command=self.generate_plan).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Export JSON", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Clear Form", command=self.clear_form).pack(side="left", padx=4)

    def _build_output_tab(self) -> None:
        container = ttk.Frame(self.output_tab)
        container.pack(fill="both", expand=True)

        self.output = tk.Text(
            container,
            wrap="word",
            bg="#020617",
            fg="#ddd6fe", # Light violet text
            insertbackground="white",
            relief="flat",
            highlightthickness=1,
            highlightbackground="#334155",
            font=("Consolas", 11),
        )

        output_scroll = ttk.Scrollbar(container, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=output_scroll.set)

        self.output.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")

    def _set_defaults(self) -> None:
        self.set_widget_value("case_id", "CORPINT-CASE-001")
        self.set_widget_value("task_id", "CORPINT-TASK-001")
        self.set_widget_value(
            "objective",
            "Analyze lawful/public-record/authorized corporate intelligence using evidence-first CORPINT methods. "
            "Preserve originals, parse safe company/director/filing metadata deterministically, resolve legal entities cautiously, "
            "map director timelines, analyze shareholder structures, identify ownership chains, test benign explanations, "
            "and produce defensive risk assessments without hacking registries, doxxing individuals, trading on insider info, or designing evasion structures.",
        )
        self.set_widget_value("target", "Illustrative example.com / authorized corporate context")
        self.set_widget_value("target_type", "legal_entity_resolution")
        self.set_widget_value(
            "questions",
            "\n".join(default_questions({"target": "Illustrative example.com / authorized corporate context"})),
        )

        for field in [
            "company_names",
            "registration_numbers",
            "jurisdictions",
            "directors",
            "shareholders",
            "brands",
            "domains",
            "addresses",
            "filings_inline",
            "ownership_data",
            "financial_data",
            "regulatory_records",
            "procurement_records",
            "trade_records",
            "sanctions_data",
            "registry_paths",
            "filing_paths",
            "annual_report_paths",
            "ownership_registry_paths",
            "court_record_paths",
            "stix_misp_paths",
        ]:
            self.set_widget_value(field, "")

        self.set_widget_value(
            "time_range",
            json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2),
        )
        self.set_widget_value("jurisdiction_default", "")
        self.set_widget_value(
            "scope",
            json.dumps(
                {
                    "allowed_source_types": [
                        "official company registries",
                        "securities regulators",
                        "public court records",
                        "company websites",
                        "licensed commercial databases",
                    ],
                    "prohibited_sources_and_actions": [
                        "hacking registries",
                        "bypassing authentication",
                        "using stolen credentials",
                        "doxxing directors",
                        "publishing private home addresses",
                        "insider trading",
                        "designing evasion structures",
                        "fabricating records",
                    ],
                    "data_minimization_rules": [
                        "mask personal identifiers where possible",
                        "avoid exposing residential addresses",
                        "focus on corporate roles and legal structures",
                    ],
                    "authorized_use": "internal defensive/authorized corporate analysis only",
                },
                indent=2,
            ),
        )
        self.set_widget_value(
            "authorization",
            json.dumps(
                {
                    "authorized_by": "",
                    "authorization_basis": "customer-authorized lawful/public engagement",
                    "permitted_actions": [
                        "local record hashing",
                        "entity resolution",
                        "timeline reconstruction",
                        "risk assessment",
                    ],
                    "prohibited_actions": [
                        "unauthorized access",
                        "privacy violations",
                        "market abuse",
                    ],
                },
                indent=2,
            ),
        )
        self.set_widget_value("source_limits", "")
        self.set_widget_value("budget", "")
        self.set_widget_value("deadline", "")
        self.set_widget_value(
            "configured_connectors",
            "None configured. No live Registry API/KYC connector invoked. Planning-only.",
        )

    def get_widget_value(self, key: str) -> str:
        widget = self.entries.get(key)
        if widget is None:
            return ""

        if isinstance(widget, tk.Text):
            return widget.get("1.0", "end-1c").strip()

        if isinstance(widget, ttk.Combobox):
            return widget.get().strip()

        if isinstance(widget, ttk.Entry):
            return widget.get().strip()

        return ""

    def set_widget_value(self, key: str, value: str) -> None:
        widget = self.entries.get(key)
        if widget is None:
            return

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

            if key in LIST_FIELDS:
                payload[key] = parse_list(raw)
            elif key in DICT_FIELDS:
                payload[key] = parse_dict(raw)
            else:
                payload[key] = raw

        payload["generated_at"] = now_utc()
        payload["panel_version"] = APP_VERSION
        payload["operating_mode"] = "PLANNING_ONLY_LAWFUL_PUBLIC_AUTHORIZED"
        payload["source_boundary"] = "LAWFUL_PUBLIC_RECORD_AUTHORIZED_EVIDENCE_FIRST_CORPINT_ONLY"
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths:
            return

        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added to {field}.")

    def add_registry(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select registry export files",
            filetypes=[
                ("Registry Records", "*.json *.csv *.tsv *.txt"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("registry_paths", paths, "Registry Files Added")

    def add_filings(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select corporate filing files",
            filetypes=[
                ("Filings", "*.json *.csv *.txt"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("filing_paths", paths, "Filing Files Added")

    def add_annual_reports(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select annual report files",
            filetypes=[
                ("Annual Reports", "*.json *.csv *.txt"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("annual_report_paths", paths, "Annual Report Files Added")

    def add_ownership_reg(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select beneficial ownership registry files",
            filetypes=[
                ("Ownership Registries", "*.json *.csv *.txt"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("ownership_registry_paths", paths, "Ownership Registry Files Added")

    def add_court(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select court/legal record files",
            filetypes=[
                ("Court Records", "*.json *.csv *.txt"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("court_record_paths", paths, "Court Record Files Added")

    def add_stix_misp(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select STIX / MISP export files",
            filetypes=[
                ("STIX / MISP", "*.json *.xml *.csv *.txt"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("stix_misp_paths", paths, "STIX / MISP Files Added")

    def run_policy_screen(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)

        result = {
            "mode": "POLICY_SCREEN_ONLY",
            "panel_version": APP_VERSION,
            "policy_screen": policy,
            "payload_preview": {
                "case_id": payload.get("case_id"),
                "task_id": payload.get("task_id"),
                "objective": payload.get("objective"),
                "target": payload.get("target"),
                "target_type": payload.get("target_type"),
                "has_companies": bool(payload.get("company_names")),
                "has_directors": bool(payload.get("directors")),
                "has_registry_paths": bool(payload.get("registry_paths")),
            },
        }

        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning(
                "Policy Blocked",
                "This CORPINT request is policy-blocked.\n\n"
                + "\n".join(policy["reasons"])
                + "\n\nUse only lawful/public alternatives.",
            )
        elif policy["status"] == "HUMAN_REVIEW_REQUIRED":
            messagebox.showwarning(
                "Human Review Required",
                "No hard policy block detected, but sensitive personal/corporate context applies.",
            )
        else:
            messagebox.showinfo(
                "Policy Screen",
                "No obvious policy violation detected. Planning-only mode remains active.",
            )

    def analyze_local_corpint(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)

        if policy["status"] == "POLICY_BLOCKED":
            result = {
                "mode": "POLICY_BLOCKED",
                "panel_version": APP_VERSION,
                "policy_screen": policy,
                "evidence_inventory": [],
                "companies_preview": [],
                "persons_preview": [],
                "observations": [],
                "candidate_facts": [],
            }
            self.last_result = result
            self._write_output(result)
            messagebox.showwarning("Policy Blocked", "Local CORPINT evidence analysis blocked by policy screen.")
            return

        path_fields = [
            "registry_paths",
            "filing_paths",
            "annual_report_paths",
            "ownership_registry_paths",
            "court_record_paths",
            "stix_misp_paths",
        ]

        all_paths: List[str] = []
        seen = set()

        for field in path_fields:
            for p in payload.get(field, []):
                sp = str(p).strip()
                if sp and sp not in seen:
                    seen.add(sp)
                    all_paths.append(sp)

        if not all_paths:
            messagebox.showwarning("No CORPINT Evidence", "Add local authorized/lawful corporate evidence files first.")
            return

        self.output.delete("1.0", "end")
        self.output.insert("1.0", "Analyzing local lawful/public CORPINT evidence. Hashing and parsing may take time...\n")
        self.notebook.select(self.output_tab)

        files: List[Dict[str, Any]] = []
        parsed_list: List[Dict[str, Any]] = []

        for p in all_paths[:30]:
            f, parsed = analyze_corporate_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
            files.append(f)
            parsed_list.append(parsed)

        aggregated = finalize_parsed(aggregate_parsed(parsed_list), payload, files)

        self.analyzed_files = files
        self.parsed = aggregated

        report = self._build_local_analysis_report(
            files=files,
            parsed=aggregated,
            payload=payload,
            policy=policy,
        )

        self.last_result = report
        self._write_output(report)

        succeeded = sum(1 for f in files if str(f.get("status", "")).startswith("SUCCEEDED"))
        messagebox.showinfo(
            "Local CORPINT Evidence Analysis Complete",
            f"Processed {len(files)} evidence file(s).\n"
            f"Succeeded/partial: {succeeded}\n"
            f"Companies: {len(aggregated.get('companies', []))}\n"
            f"Persons: {len(aggregated.get('persons', []))}\n"
            f"Relationships: {len(aggregated.get('relationships', []))}\n"
            "Review output for limitations and next actions.",
        )

    def generate_plan(self) -> None:
        payload = self.collect_payload()
        warnings = validate_payload(payload)
        policy = policy_screen(payload)

        if policy["status"] == "POLICY_BLOCKED":
            result = {
                "mode": "POLICY_BLOCKED",
                "panel_version": APP_VERSION,
                "policy_screen": policy,
                "warnings": warnings,
                "payload": payload,
                "corpint_collection_plan": [],
                "next_best_action": {
                    "action": "Revise task to remove prohibited hacking, doxxing, insider trading, or evasion behavior.",
                    "owner": "CORPINT Manager",
                    "expected_output": "Policy-compliant defensive scope.",
                },
            }
            self.last_result = result
            self._write_output(result)
            messagebox.showwarning(
                "Policy Blocked",
                "CORPINT plan not generated because the request is policy-blocked.",
            )
            return

        questions = payload.get("questions") or default_questions(payload)

        if not self.parsed.get("companies") and not self.parsed.get("persons"):
            self.parsed = finalize_parsed(empty_parsed(), payload, self.analyzed_files)

        files = self.analyzed_files
        parsed = self.parsed

        next_action = build_next_best_action(payload, policy, files, parsed)
        collection_plan = build_collection_plan(payload, questions, files, parsed)

        overall_status = "PLANNING_ONLY"
        if policy["status"] == "HUMAN_REVIEW_REQUIRED":
            overall_status = "HUMAN_REVIEW_REQUIRED"
        if files or parsed.get("companies") or parsed.get("persons"):
            overall_status = "PLANNING_PLUS_LOCAL_DETERMINISTIC_EVIDENCE"

        result = {
            "mode": overall_status,
            "panel_version": APP_VERSION,
            "policy": (
                "This output does not hack registries, bypass authentication, use stolen credentials, dox individuals, "
                "publish private addresses, trade on insider information, facilitate market manipulation, fabricate records, "
                "or design shell-company/sanctions-evasion/tax-evasion structures. "
                "Local deterministic analysis is limited to hashing, safe JSON/CSV/TXT corporate record parsing, entity resolution, "
                "director timeline reconstruction, shareholder analysis, ownership chain mapping, financial filing context, "
                "regulatory/legal event tracking, contradiction detection, competing hypotheses, falsification, secret redaction, "
                "prompt-injection flagging, and defensive specialist handoff planning. Live Registry API/KYC enrichment, "
                "consequential legal conclusions, and private-person profiling remain planning-only unless configured/authorized/human-reviewed."
            ),
            "policy_screen": policy,
            "warnings": warnings,
            "payload": payload,
            "intelligence_questions": questions,
            "evidence_inventory": files,
            "companies_preview": parsed.get("companies", [])[:300],
            "persons_preview": parsed.get("persons", [])[:300],
            "relationships_preview": parsed.get("relationships", [])[:300],
            "contradictions": parsed.get("contradictions", [])[:1000],
            "hypotheses": parsed.get("hypotheses", [])[:1000],
            "knowledge_gaps": parsed.get("knowledge_gaps", [])[:500],
            "specialist_handoffs": parsed.get("specialist_handoffs", [])[:500],
            "next_best_action": next_action,
            "corpint_collection_plan": collection_plan,
            **self._policy_sections(),
            **self._schemas(),
        }

        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

        if warnings:
            messagebox.showwarning(
                "Validation Warnings",
                "CORPINT plan generated with warnings:\n\n" + "\n".join(warnings),
            )

    def _build_local_analysis_report(
        self,
        files: List[Dict[str, Any]],
        parsed: Dict[str, Any],
        payload: Dict[str, Any],
        policy: Dict[str, Any],
    ) -> Dict[str, Any]:
        next_action = build_next_best_action(payload, policy, files, parsed)
        collection_plan = build_collection_plan(payload, default_questions(payload), files, parsed)

        observations: List[Dict[str, Any]] = []

        for f in files:
            observations.append({
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": f"A local lawful/public CORPINT evidence file was accessed and hashed: {f.get('filename')}.",
                "evidence_id": f.get("evidence_id"),
                "source_id": f.get("source_id"),
                "observed_at": now_utc(),
                "extraction_method": "local_deterministic_file_hash",
                "limitations": "File hash does not prove economic reality or intent.",
            })

        observations.extend([
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": f"{len(files)} CORPINT evidence file(s) were parsed locally.",
                "evidence_id": "AGGREGATE",
                "source_id": "LOCAL_PARSER",
                "observed_at": now_utc(),
                "extraction_method": "safe_json_csv_text_corporate_parser",
                "limitations": "Parser output is normalized evidence, not verified external reality.",
            },
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": f"{len(parsed.get('companies', []))} company record(s) and {len(parsed.get('persons', []))} person-role record(s) were extracted.",
                "evidence_id": "AGGREGATE",
                "source_id": "LOCAL_ENTITY_PARSER",
                "observed_at": now_utc(),
                "extraction_method": "entity_role_extraction",
                "limitations": "Entity existence != Operating Business.",
            },
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": "No registry hacking, doxxing, insider trading, or evasion scheme design was performed.",
                "evidence_id": "LOCAL_PANEL_POLICY",
                "source_id": "LOCAL_POLICY_GUARD",
                "observed_at": now_utc(),
                "extraction_method": "lawful_public_policy",
                "limitations": "Planning/local deterministic panel only.",
            },
        ])

        observations, _ = truncate_list(observations, 500)

        candidate_facts: List[Dict[str, Any]] = []

        for f in files:
            if f.get("sha256"):
                candidate_facts.append({
                    "candidate_fact": f"The preserved local CORPINT evidence artifact {f.get('filename')} has SHA256 {f.get('sha256')}.",
                    "status": "SUPPORTED",
                    "evidence_ids": [f.get("evidence_id")],
                    "notes": "Supported by deterministic local hashing. Does not prove legitimacy.",
                })

        candidate_facts.extend([
            {
                "candidate_fact": f"{len(parsed.get('companies', []))} company candidate(s) were extracted.",
                "status": "SUPPORTED_AS_CANDIDATE_ONLY",
                "evidence_ids": ["AGGREGATE"],
                "not_supported": [
                    "verified economic activity",
                    "verified beneficial ownership",
                    "verified absence of fraud",
                ],
            },
            {
                "candidate_fact": "No registry hacking, doxxing, insider trading, or evasion scheme design was performed.",
                "status": "SUPPORTED",
                "evidence_ids": ["LOCAL_PANEL_POLICY"],
                "notes": "Lawful/public/ethical planning boundary.",
            },
        ])

        candidate_facts, _ = truncate_list(candidate_facts, 200)

        fact_gate = {
            "status": "LOCAL_DETERMINISTIC_ONLY" if files or parsed.get("companies") else "NO_LOCAL_CORPINT_EVIDENCE",
            "supported": [
                "file/source existence and SHA256 hash",
                "parsed company records",
                "parsed person-role records",
                "parsed relationship candidates",
                "contradiction candidates",
                "competing hypotheses",
                "secret redaction flags",
                "prompt-injection flags",
            ],
            "not_supported": [
                "verified economic reality",
                "verified beneficial ownership",
                "verified absence of fraud",
                "final legal determination",
                "autonomous accusation of crime",
                "private-person profiling",
            ],
            "safety_status": "No registry hacking, doxxing, insider trading, or evasion scheme design performed.",
        }

        return {
            "mode": "LOCAL_DETERMINISTIC_CORPINT_ANALYSIS",
            "panel_version": APP_VERSION,
            "policy_screen": policy,
            "registry_hacking_performed": False,
            "doxxing_performed": False,
            "insider_trading_performed": False,
            "evasion_design_performed": False,
            "evidence_inventory": files,
            "companies_preview": parsed.get("companies", [])[:300],
            "persons_preview": parsed.get("persons", [])[:300],
            "relationships_preview": parsed.get("relationships", [])[:300],
            "contradictions": parsed.get("contradictions", [])[:1000],
            "hypotheses": parsed.get("hypotheses", [])[:1000],
            "knowledge_gaps": parsed.get("knowledge_gaps", [])[:500],
            "specialist_handoffs": parsed.get("specialist_handoffs", [])[:500],
            "observations": observations,
            "candidate_facts": candidate_facts,
            "fact_gate": fact_gate,
            "recommended_next_actions": next_action,
            "corpint_collection_plan_preview": collection_plan[:20],
            "limitations": [
                "Only local deterministic checks were performed.",
                "No network access was performed.",
                "No registry hacking, doxxing, insider trading, or evasion scheme design was performed.",
                "Company is not Brand.",
                "Director is not Owner.",
                "Shareholder is not Beneficial Owner.",
                "Active Status is not Operating Business.",
                "Exposed secrets were redacted heuristically and not used.",
                "Corporate documents were treated as untrusted evidence.",
            ],
        }

    def _write_output(self, result: Dict[str, Any]) -> None:
        self.output.delete("1.0", "end")
        self.output.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2, default=str))

    def _policy_sections(self) -> Dict[str, Any]:
        return {
            "role": {
                "employee": "CORPINT AI Employee",
                "hierarchy": [
                    "Chief Intelligence Manager",
                    "Commercial / Corporate Intelligence Manager",
                    "CORPINT Manager",
                    "CORPINT AI Employee",
                ],
                "not": [
                    "private-person doxxing system",
                    "fraud accusation engine",
                    "beneficial-owner guessing machine",
                    "legal-decision system",
                    "corporate hacking agent",
                    "registry-login bypass system",
                    "insider-information collector",
                    "market-manipulation system",
                ],
            },
            "core_principle": [
                "COMPANY REFERENCE",
                "LEGAL ENTITY RESOLUTION",
                "JURISDICTION",
                "REGISTRATION",
                "FILINGS",
                "DIRECTORS / OFFICERS",
                "SHAREHOLDERS / OWNERSHIP",
                "CORPORATE STRUCTURE",
                "FINANCIAL / REGULATORY / LEGAL CONTEXT",
                "SOURCE RELIABILITY",
                "SOURCE INDEPENDENCE",
                "TEMPORAL VALIDATION",
                "FACT GATE",
                "CORPORATE ASSESSMENT",
            ],
            "critical_separations": [
                "company != brand",
                "company != domain",
                "company != address",
                "director != owner",
                "shareholder != director",
                "shareholder != beneficial owner",
                "beneficial owner != controller",
                "parent != ultimate parent",
                "subsidiary != branch",
                "active status != operating business",
                "dissolved != never relevant",
                "historical director != current director",
            ],
            "hard_restrictions": [
                "Do not hack corporate registries.",
                "Do not bypass registry authentication.",
                "Do not use stolen credentials.",
                "Do not dox private directors/shareholders.",
                "Do not publish private home addresses unnecessarily.",
                "Do not trade using insider information.",
                "Do not design shell-company evasion plans.",
                "Do not fabricate company records.",
            ],
            "non_negotiable_rules": [
                "DO NOT HACK COMPANY REGISTRIES.",
                "DO NOT DOX DIRECTORS OR SHAREHOLDERS.",
                "DO NOT USE INSIDER INFORMATION FOR TRADING.",
                "DO NOT DESIGN SHELL-COMPANY STRUCTURES FOR EVASION.",
                "DO NOT EQUATE COMPANY NAME WITH LEGAL ENTITY.",
                "DO NOT EQUATE DIRECTOR WITH SHAREHOLDER.",
                "DO NOT EQUATE SHAREHOLDER WITH BENEFICIAL OWNER.",
                "DO NOT EQUATE ACTIVE REGISTRY STATUS WITH ACTIVE BUSINESS OPERATIONS.",
            ],
        }

    def _schemas(self) -> Dict[str, Any]:
        return {
            "company_schema": {
                "company_id": "Unique Company ID",
                "legal_name": "Full Legal Name",
                "registration_number": "Official Reg No / LEI",
                "jurisdiction": "Country/Region",
                "status": "ACTIVE/DISSOLVED/etc.",
                "incorporation_date": "Date Established",
                "source_id": "Src ID",
                "evidence_id": "Evd ID",
                "limitations": [
                    "Same name != Same entity.",
                    "Active != Operating.",
                ],
            },
            "person_schema": {
                "person_instance_id": "Unique Role Instance ID",
                "name": "Person Name",
                "role": "DIRECTOR/OFFICER/SHAREHOLDER",
                "linked_company_id": "Company ID",
                "appointment_date": "Start Date",
                "resignation_date": "End Date",
                "limitations": [
                    "Director != Owner.",
                    "Historical != Current.",
                ],
            },
            "corpint_result_schema": [
                "case_id",
                "task_id",
                "objective",
                "questions",
                "source_ids",
                "evidence_ids",
                "companies",
                "directors",
                "shareholders",
                "ownership_chains",
                "contradictions",
                "hypotheses",
                "knowledge_gaps",
                "specialist_handoffs",
                "limitations",
                "status",
            ],
        }

    def export_json(self) -> None:
        _support.export_snapshot(self, filedialog, messagebox)

    def copy_output(self) -> None:
        text = self.output.get("1.0", "end-1c").strip()
        if not text:
            messagebox.showinfo("Copy Output", "No output to copy.")
            return

        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copy Output", "Output copied to clipboard.")

    def clear_form(self) -> None:
        confirm = messagebox.askyesno(
            "Clear Form",
            "Are you sure you want to clear all fields, analyzed CORPINT evidence, and reset defaults?",
        )
        if not confirm:
            return

        self._set_defaults()
        self.output.delete("1.0", "end")
        self.last_result = {}
        self.analyzed_files = []
        self.parsed = empty_parsed()


if __name__ == "__main__":
    app = TraceAtlasCORPINTPanel()
    app.mainloop()

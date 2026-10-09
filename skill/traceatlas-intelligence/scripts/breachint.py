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
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


APP_TITLE = "TraceAtlas BREACHINT AI Employee — Defensive / Authorized / Privacy-Aware Breach Intelligence Panel"
APP_VERSION = "TraceAtlas BREACHINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target", "Target / Organization / Domain / Breach Context", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "BREACHINT Questions", "text"),

    ("organizations", "Organizations / Companies", "text"),
    ("brands", "Brands / Products", "text"),
    ("domains", "Domains", "text"),
    ("email_domains", "Email Domains", "text"),
    ("subsidiaries", "Subsidiaries / Parent Entities", "text"),
    ("third_parties", "Third Parties / Vendors / SaaS", "text"),
    ("suppliers", "Suppliers / Processors", "text"),

    ("breach_claims", "Inline Breach Claims", "text"),
    ("dataset_claims", "Inline Dataset Claims", "text"),
    ("credential_claims", "Inline Credential Exposure Claims", "text"),
    ("ransomware_claims", "Inline Ransomware / Extortion Claims", "text"),
    ("exposure_sources", "Exposure Sources / Reports", "text"),
    ("incident_context", "Incident Context", "text"),
    ("known_accounts_if_authorized", "Known Accounts If Authorized", "text"),
    ("known_assets_if_authorized", "Known Assets If Authorized", "text"),

    ("breach_claim_paths", "Breach Claim Export Paths", "text"),
    ("dataset_metadata_paths", "Dataset Metadata Export Paths", "text"),
    ("credential_exposure_paths", "Credential Exposure Metadata Paths", "text"),
    ("ransomware_leak_paths", "Ransomware Leak-Site Metadata Paths", "text"),
    ("exposure_report_paths", "Exposure Report Paths", "text"),
    ("incident_data_paths", "Authorized Incident Data Paths", "text"),
    ("historical_breach_paths", "Historical Breach / Known Leak Paths", "text"),
    ("combo_list_paths", "Combo List Metadata Paths", "text"),
    ("stealer_log_paths", "Stealer Log Metadata Paths", "text"),
    ("supply_chain_paths", "Supply-Chain Exposure Paths", "text"),
    ("repository_exposure_paths", "Repository Exposure Paths", "text"),
    ("cloud_exposure_paths", "Cloud Exposure Paths", "text"),
    ("document_exposure_paths", "Document Exposure Paths", "text"),
    ("source_code_exposure_paths", "Source Code Exposure Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("jurisdiction", "Jurisdiction", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget", "Budget", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (breach-monitoring/credential-monitoring/STIX/MISP/incident/etc.)", "text"),
]


TARGET_TYPES = [
    "breach_claim",
    "dataset_claim",
    "credential_exposure",
    "ransomware_claim",
    "exposure_report",
    "incident_data",
    "historical_breach",
    "combo_list",
    "stealer_log",
    "supply_chain_exposure",
    "repository_exposure",
    "cloud_exposure",
    "document_exposure",
    "source_code_exposure",
    "stix_misp",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "organizations",
    "brands",
    "domains",
    "email_domains",
    "subsidiaries",
    "third_parties",
    "suppliers",
    "breach_claims",
    "dataset_claims",
    "credential_claims",
    "ransomware_claims",
    "exposure_sources",
    "known_accounts_if_authorized",
    "known_assets_if_authorized",
    "breach_claim_paths",
    "dataset_metadata_paths",
    "credential_exposure_paths",
    "ransomware_leak_paths",
    "exposure_report_paths",
    "incident_data_paths",
    "historical_breach_paths",
    "combo_list_paths",
    "stealer_log_paths",
    "supply_chain_paths",
    "repository_exposure_paths",
    "cloud_exposure_paths",
    "document_exposure_paths",
    "source_code_exposure_paths",
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
    "breach_claim",
    "dataset_claim",
    "credential_exposure",
    "ransomware_claim",
    "exposure_report",
    "incident_data",
    "historical_breach",
    "combo_list",
    "stealer_log",
    "supply_chain_exposure",
    "repository_exposure",
    "cloud_exposure",
    "document_exposure",
    "source_code_exposure",
    "stix_misp",
}


POLICY_BLOCK_PATTERNS = [
    r"\b(?:purchase|buy|acquire|obtain|download)\b[^\n]{0,140}\b(?:stolen data|breach data|credentials|credential|access|database|dump|combo list|ransomware data|personal data|pii)\b",
    r"\b(?:test|validate|verify|check|login|log in|authenticate|use|redeem|replay)\b[^\n]{0,140}\b(?:password|credential|session cookie|token|api key|private key|exposed account|stolen account|leaked credential)\b",
    r"\b(?:contact|message|negotiate|pay|ransom)\b[^\n]{0,140}\b(?:seller|criminal|actor|ransomware|victim|employee|customer|regulator|law enforcement)\b",
    r"\b(?:redistribute|publish|expose|dox)\b[^\n]{0,140}\b(?:personal data|pii|credentials|private data|victim data|employee data|customer data)\b",
    r"\b(?:exploit|unauthorized access|hack|intrusion)\b[^\n]{0,140}\b(?:breach|dataset|account|system|database|repository|cloud storage)\b",
    r"\b(?:credential stuffing|password spraying|brute force)\b",
    r"\b(?:use|deploy|execute)\b[^\n]{0,140}\b(?:malware|payload|exploit|script)\b",
]


SAFE_ALTERNATIVES = [
    "Provide defensive breach/exposure metadata intelligence: claim extraction, organization resolution, dataset metadata, record-count caution, data-category classification, credential/secret exposure metadata, first-party vs third-party analysis, supply-chain context, combo-list/stealer-log context, recycled-breach detection, dataset fingerprinting/lineage, source pedigree/independence, contradictions, competing hypotheses, falsification, privacy-aware impact assessment, and defensive handoffs.",
    "Do not purchase stolen data/breach data/credentials/access, download unnecessary full stolen datasets, use exposed credentials, test passwords, perform credential stuffing, replay session tokens, use API/private keys, login to exposed accounts, contact sellers, negotiate ransoms, redistribute sensitive data, publish personal data, perform unauthorized access, or exploit resources.",
    "Separate claim, fact, sample, dataset, record count, origin, freshness, credential exposure, organization impact, incident root cause, and actor attribution.",
    "Preserve privacy: use metadata, hashes, redacted identifiers, schema, counts, timestamps, and limited authorized samples instead of full personal records.",
    "Escalate defensively through authorized human workflows: EXPOSUREINT, INCIDENTINT, DARKINT, CTI/THREATACTORINT, MALINT, DOCINT, REPOINT, legal/compliance, and law-enforcement liaison.",
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
        "PGP_PRIVATE_KEY_BLOCK",
        re.compile(
            r"-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----",
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
    (
        "BEARER_TOKEN",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+/=]{8,}"),
    ),
    (
        "AWS_ACCESS_KEY",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "JWT_LIKE_TOKEN",
        re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
    ),
    (
        "USERNAME_PASSWORD_PAIR",
        re.compile(r"(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\s*[:|]\s*[^\s,;\"']+"),
    ),
]


PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?previous\s+(?:instructions|rules)",
    r"reveal\s+(?:the\s+)?system\s+prompt",
    r"login\s+(?:here|to)",
    r"use\s+(?:this\s+)?password",
    r"run\s+(?:this|script)",
    r"contact\s+seller",
    r"download\s+dataset",
    r"disable\s+safety",
]


DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
URL_RE = re.compile(r"\b(?:https?|ftp|hxxp)://[^\s<>()\"']+", re.I)
RECORD_COUNT_RE = re.compile(
    r"\b(\d[\d,]*(?:\.\d+)?)\s*(million|billion|thousand|k|m|bn|gb|tb|mb|records|rows|users|accounts)\b",
    re.I,
)
EMAIL_PASS_RE = re.compile(
    r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*[:|]\s*([^\s,;\"']+)"
)


BREACH_KEYWORDS = [
    "breach", "breached", "compromised", "compromise", "hacked", "intrusion",
    "exfiltrated", "stolen", "leaked", "data theft", "unauthorized access",
]

DATASET_KEYWORDS = [
    "dataset", "database", "db", "dump", "records", "rows", "table", "schema",
    "customers", "users", "accounts", "archive", "sql", "csv", "json", "parquet",
]

CREDENTIAL_KEYWORDS = [
    "credential", "credentials", "password", "passwd", "pwd", "login",
    "username", "hash", "md5", "sha1", "sha256", "token", "session",
    "cookie", "api key", "apikey", "access key", "secret", "private key",
    "stealer log", "combo list", "combo",
]

RANSOMWARE_KEYWORDS = [
    "ransomware", "encrypt", "leak site", "victim list", "countdown",
    "double extortion", "triple extortion", "extortion", "negotiation",
]

COMBO_KEYWORDS = [
    "combo list", "combolist", "credential stuffing", "multiple breaches",
    "aggregated credentials", "old passwords",
]

STEALER_KEYWORDS = [
    "stealer log", "infostealer", "redline", "racoon", "venom", "lumi",
    "cookies", "saved passwords", "browser data", "device metadata",
]

THIRD_PARTY_KEYWORDS = [
    "third party", "third-party", "vendor", "saas", "crm", "marketing platform",
    "payroll provider", "health provider", "processor", "service provider",
]

SUPPLY_CHAIN_KEYWORDS = [
    "supply chain", "supplier", "partner", "msp", "managed service",
    "contractor", "holds data for",
]

SOURCE_CODE_KEYWORDS = [
    "source code", "proprietary code", "repository", "repo", "git",
    "commit", "file tree",
]

REPOSITORY_KEYWORDS = [
    "github", "gitlab", "bitbucket", "repository", "repo", "public repo",
    "private repo",
]

CLOUD_KEYWORDS = [
    "cloud", "s3", "blob", "bucket", "azure", "gcp", "storage account",
    "misconfigured storage", "public storage",
]

DOCUMENT_KEYWORDS = [
    "document", "pdf", "docx", "xlsx", "contract", "invoice", "internal doc",
    "file metadata",
]

PUBLIC_DATA_KEYWORDS = [
    "public data", "publicly available", "public website", "business directory",
    "public filing", "open source",
]

SCRAPED_KEYWORDS = [
    "scraped", "scraping", "crawler", "harvested", "publicly scraped",
]

MISCONFIG_KEYWORDS = [
    "misconfiguration", "misconfigured", "open database", "public backup",
    "exposed api", "default credentials",
]

RECYCLED_KEYWORDS = [
    "recycled", "old breach", "previous breach", "historical", "reposted",
    "republished", "previously leaked", "old data",
]


DATA_CATEGORY_KEYWORDS = {
    "EMAIL": ["email", "e-mail", "mailbox"],
    "USERNAME": ["username", "user name", "login"],
    "PASSWORD_OR_HASH": ["password", "passwd", "pwd", "hash", "md5", "sha1", "sha256"],
    "NAME": ["name", "fullname", "first name", "last name"],
    "PHONE": ["phone", "mobile", "telephone"],
    "ADDRESS": ["address", "street", "city", "postal", "zip"],
    "EMPLOYEE_DATA": ["employee", "staff", "hr", "payroll"],
    "CUSTOMER_DATA": ["customer", "client", "user account"],
    "FINANCIAL_DATA": ["financial", "bank", "payment", "card", "invoice", "transaction"],
    "GOVERNMENT_IDENTIFIER": ["ssn", "national id", "passport", "driver license", "tax id"],
    "HEALTH_DATA": ["health", "medical", "patient", "clinical"],
    "AUTHENTICATION_SECRET": ["token", "session", "cookie", "api key", "private key", "secret"],
    "SOURCE_CODE": ["source code", "repository", "repo", "git", "commit"],
    "DOCUMENT": ["document", "pdf", "docx", "xlsx", "contract", "invoice"],
    "DATABASE_RECORD": ["database", "db", "table", "row", "record", "dump"],
}


SENSITIVE_FLAG_KEYWORDS = {
    "CREDENTIAL_DATA": ["password", "passwd", "pwd", "hash", "token", "session", "cookie", "api key", "private key"],
    "FINANCIAL_DATA": ["financial", "bank", "payment", "card", "transaction", "invoice"],
    "HEALTH_DATA": ["health", "medical", "patient", "clinical"],
    "IDENTITY_DOCUMENT": ["passport", "driver license", "national id", "ssn", "tax id"],
    "AUTHENTICATION_SECRET": ["token", "session", "cookie", "api key", "private key", "secret"],
    "PRIVATE_COMMUNICATION": ["private message", "dm", "chat log", "email content", "inbox"],
    "MINOR_RELATED_DATA": ["child", "minor", "pediatric", "student under 18"],
}


ORIGIN_CLAIM_TYPES = {
    "FIRST_PARTY_CANDIDATE",
    "THIRD_PARTY_CANDIDATE",
    "SUPPLY_CHAIN_CANDIDATE",
    "COMBO_LIST",
    "STEALER_LOG",
    "PUBLIC_DATA_CANDIDATE",
    "SCRAPED_DATA_CANDIDATE",
    "RECYCLED_CANDIDATE",
    "REPOSITORY_EXPOSURE_CANDIDATE",
    "CLOUD_EXPOSURE_CANDIDATE",
    "DOCUMENT_EXPOSURE_CANDIDATE",
    "SOURCE_CODE_EXPOSURE_CANDIDATE",
    "MISCONFIGURATION_CANDIDATE",
}


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


def normalize_domain(value: Any) -> str:
    original = str(value or "").strip().lower().rstrip(".")
    if not original:
        return ""

    if "://" in original:
        try:
            parsed = urlparse(original)
            original = (parsed.netloc or "").lower()
            if "@" in original:
                original = original.split("@", 1)[1]
            if ":" in original and not original.startswith("["):
                original = original.split(":", 1)[0]
        except Exception:
            pass

    if original.startswith("[") and original.endswith("]"):
        original = original[1:-1]

    try:
        original = original.encode("idna").decode("ascii")
    except Exception:
        pass

    return original


def redact_email_identifier(email: Any) -> str:
    raw = str(email or "").strip().lower()
    if "@" not in raw:
        return safe_str(raw, 120)
    local, domain = raw.split("@", 1)
    if len(local) <= 2:
        redacted_local = local[:1] + "***"
    else:
        redacted_local = local[:2] + "***"
    return f"{redacted_local}@{domain}"


def parse_datetime(value: Any) -> Optional[datetime]:
    if value in (None, ""):
        return None

    s = str(value).strip()
    if not s:
        return None

    s = s.replace("Z", "+00:00")

    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass

    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", s)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=timezone.utc)
        except Exception:
            pass

    return None


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


def extract_temporal(rec: Dict[str, Any]) -> Dict[str, str]:
    temporal: Dict[str, str] = {}
    mappings = {
        "first_seen": ["first_seen", "firstseen", "first_observed", "created", "start_time", "start"],
        "last_seen": ["last_seen", "lastseen", "last_observed", "updated", "end_time", "end", "modified"],
        "observed_at": ["observed_at", "observedat", "timestamp", "time", "observed"],
        "published_at": ["published_at", "publishedat", "publication_date", "published"],
        "retrieved_at": ["retrieved_at", "retrievedat", "collected_at", "snapshot_at"],
        "breach_date": ["breach_date", "compromise_date", "incident_date"],
    }

    for canonical, aliases in mappings.items():
        val = get_field(rec, aliases)
        if val not in (None, ""):
            temporal[canonical] = str(val)

    return temporal


def collect_tags(rec: Dict[str, Any]) -> List[str]:
    tags: List[str] = []

    for key in ["tags", "labels", "markings", "x_misp_tags", "tag", "label"]:
        val = rec.get(key)
        for item in listify(val):
            if isinstance(item, dict):
                name = item.get("name") or item.get("value") or item.get("label")
                if name:
                    tags.append(str(name))
            elif item not in (None, ""):
                tags.append(str(item))

    return unique_preserve_order(tags)[:200]


def content_tokens(text: str) -> List[str]:
    redacted, _ = redact_secrets(str(text or ""))
    low = normalize_text(redacted)
    return re.findall(r"[a-z0-9]+", low)


def content_fingerprint(text: str) -> str:
    tokens = content_tokens(text)
    if not tokens:
        return ""
    return sha256_text(" ".join(sorted(set(tokens))))[:32]


def extract_domains(text: str) -> List[str]:
    out = []
    for m in DOMAIN_RE.finditer(text or ""):
        d = normalize_domain(m.group(0))
        if d and d not in out and not d.endswith(".onion"):
            out.append(d)
    return out


def extract_emails(text: str) -> List[str]:
    out = []
    for m in EMAIL_RE.finditer(text or ""):
        e = m.group(0).lower()
        if e not in out:
            out.append(e)
    return out


def extract_ips(text: str) -> List[str]:
    out = []
    for m in IPV4_RE.finditer(text or ""):
        candidate = m.group(0).strip(".,;:")
        parts = candidate.split(".")
        try:
            if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                if candidate not in out:
                    out.append(candidate)
        except Exception:
            pass
    return out


def extract_hashes(text: str) -> List[str]:
    out = []
    for m in SHA256_RE.finditer(text or ""):
        h = m.group(0).lower()
        if h not in out:
            out.append(h)
    return out


def extract_record_count(text: str) -> List[Dict[str, Any]]:
    out = []
    for m in RECORD_COUNT_RE.finditer(text or ""):
        raw = m.group(0)
        num_str = m.group(1).replace(",", "")
        unit = m.group(2).lower()
        try:
            num = float(num_str)
        except Exception:
            continue

        if unit in {"million", "m"}:
            value = int(num * 1_000_000)
            kind = "claimed_count"
        elif unit == "billion" or unit == "bn":
            value = int(num * 1_000_000_000)
            kind = "claimed_count"
        elif unit in {"thousand", "k"}:
            value = int(num * 1_000)
            kind = "claimed_count"
        elif unit == "gb":
            value = int(num * 1_000_000_000)
            kind = "data_size_bytes"
        elif unit == "tb":
            value = int(num * 1_000_000_000_000)
            kind = "data_size_bytes"
        elif unit == "mb":
            value = int(num * 1_000_000)
            kind = "data_size_bytes"
        else:
            value = int(num)
            kind = "claimed_count"

        out.append({
            "raw": raw,
            "value": value,
            "unit": unit,
            "kind": kind,
        })

    return unique_preserve_order(out)


def classify_data_categories(text: str) -> List[str]:
    low = normalize_text(text)
    cats = []
    for cat, kws in DATA_CATEGORY_KEYWORDS.items():
        if any(k in low for k in kws):
            cats.append(cat)
    return unique_preserve_order(cats)


def classify_sensitive_flags(text: str, categories: List[str], secret_flags: List[str]) -> List[str]:
    low = normalize_text(text)
    flags = []

    if any(f in secret_flags for f in ["PASSWORD_OR_TOKEN_ASSIGNMENT", "USERNAME_PASSWORD_PAIR", "PRIVATE_KEY_BLOCK", "PGP_PRIVATE_KEY_BLOCK", "BEARER_TOKEN", "AWS_ACCESS_KEY", "JWT_LIKE_TOKEN"]):
        flags.append("CREDENTIAL_DATA")
        flags.append("AUTHENTICATION_SECRET")

    for flag, kws in SENSITIVE_FLAG_KEYWORDS.items():
        if any(k in low for k in kws):
            flags.append(flag)

    if "PASSWORD_OR_HASH" in categories or "AUTHENTICATION_SECRET" in categories:
        flags.append("CREDENTIAL_DATA")

    if any(f in flags for f in ["HEALTH_DATA", "FINANCIAL_DATA", "IDENTITY_DOCUMENT", "AUTHENTICATION_SECRET", "MINOR_RELATED_DATA", "PRIVATE_COMMUNICATION"]):
        flags.append("HIGHLY_SENSITIVE_PERSONAL_DATA")

    return unique_preserve_order(flags)


def infer_origin_candidates(text: str, categories: List[str], secret_flags: List[str]) -> List[str]:
    low = normalize_text(text)
    out = []

    if any(k in low for k in COMBO_KEYWORDS):
        out.append("COMBO_LIST")
    if any(k in low for k in STEALER_KEYWORDS):
        out.append("STEALER_LOG")
    if any(k in low for k in THIRD_PARTY_KEYWORDS):
        out.append("THIRD_PARTY_CANDIDATE")
    if any(k in low for k in SUPPLY_CHAIN_KEYWORDS):
        out.append("SUPPLY_CHAIN_CANDIDATE")
    if any(k in low for k in PUBLIC_DATA_KEYWORDS):
        out.append("PUBLIC_DATA_CANDIDATE")
    if any(k in low for k in SCRAPED_KEYWORDS):
        out.append("SCRAPED_DATA_CANDIDATE")
    if any(k in low for k in RECYCLED_KEYWORDS):
        out.append("RECYCLED_CANDIDATE")
    if any(k in low for k in SOURCE_CODE_KEYWORDS):
        out.append("SOURCE_CODE_EXPOSURE_CANDIDATE")
    if any(k in low for k in REPOSITORY_KEYWORDS):
        out.append("REPOSITORY_EXPOSURE_CANDIDATE")
    if any(k in low for k in CLOUD_KEYWORDS):
        out.append("CLOUD_EXPOSURE_CANDIDATE")
    if any(k in low for k in DOCUMENT_KEYWORDS):
        out.append("DOCUMENT_EXPOSURE_CANDIDATE")
    if any(k in low for k in MISCONFIG_KEYWORDS):
        out.append("MISCONFIGURATION_CANDIDATE")

    if any(k in low for k in ["first-party", "our network", "our systems", "our servers", "our infrastructure"]):
        out.append("FIRST_PARTY_CANDIDATE")

    return unique_preserve_order(out)


def infer_freshness(text: str, temporal: Optional[Dict[str, Any]] = None) -> str:
    low = normalize_text(text)

    if any(k in low for k in ["mixed", "multiple dates", "old and new"]):
        return "MIXED"
    if any(k in low for k in ["current", "latest", "new breach", "fresh"]):
        return "CURRENT"
    if any(k in low for k in ["recent", "last week", "last month"]):
        return "RECENT"
    if any(k in low for k in ["old", "previous", "historical", "recycled", "reposted", "2015", "2016", "2017", "2018", "2019", "2020", "2021"]):
        return "HISTORICAL"
    if temporal and temporal.get("first_seen"):
        dt = parse_datetime(temporal.get("first_seen"))
        if dt:
            age_days = (datetime.now(timezone.utc) - dt).days
            if age_days <= 30:
                return "RECENT"
            if age_days <= 180:
                return "AGING"
            return "HISTORICAL"

    return "UNKNOWN"


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "claims": [],
        "datasets": [],
        "credential_exposures": [],
        "ransomware_claims": [],
        "organization_mentions": [],
        "brand_mentions": [],
        "domain_mentions": [],
        "email_domain_mentions": [],
        "third_party_mentions": [],
        "supplier_mentions": [],
        "data_categories": [],
        "sensitive_flags": [],
        "record_counts": [],
        "dataset_fingerprints": [],
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
            "Source observation is not verified breach, dataset authenticity, record count, origin, credential validity, or actor attribution.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Dataset records, documents, forum posts, repository content, ransomware notes, and seller descriptions are untrusted evidence, not instructions.")


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
            "Source registration is local provenance metadata, not independence verification.",
            "Republishing/aggregation is not corroboration.",
        ],
    })


def add_mention(parsed: Dict[str, Any], bucket: str, mention_type: str, value: Any, source_id: str, evidence_id: str, context: str = "", temporal: Optional[Dict[str, Any]] = None) -> None:
    v = safe_str(value, 300)
    if not v:
        return

    for item in parsed[bucket]:
        if item.get("value") == v and item.get("source_id") == source_id:
            return

    parsed[bucket].append({
        "mention_id": f"MEN-{uuid.uuid4()}",
        "mention_type": mention_type,
        "value": v,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "temporal": temporal or {},
        "state": "SOURCE_MENTION",
        "limitations": [
            "Mention is not verification of breach, exposure, affiliation, or identity.",
        ],
    })


def add_claim(
    parsed: Dict[str, Any],
    claim_type: Any,
    text: Any,
    subject: Any = None,
    claimant: Any = None,
    organization: Any = None,
    domain: Any = None,
    record_count: Any = None,
    data_categories: Optional[List[str]] = None,
    origin: Any = None,
    freshness: Any = None,
    source_id: str = "",
    evidence_id: str = "",
    temporal: Optional[Dict[str, Any]] = None,
    confidence: str = "LOW",
    state: str = "SOURCE_CLAIM",
) -> None:
    ct = safe_str(claim_type, 100).upper() or "BREACH_CLAIM"
    redacted, secret_flags = redact_secrets(str(text or "")[:500])
    if not redacted.strip():
        return

    injection_flags = detect_prompt_injection(str(text or ""))

    parsed["claims"].append({
        "claim_id": f"CLM-{uuid.uuid4()}",
        "claim_type": ct,
        "text": redacted,
        "subject": safe_str(subject, 300),
        "claimant": safe_str(claimant, 200),
        "organization": safe_str(organization, 300),
        "domain": safe_str(domain, 300),
        "record_count": safe_str(record_count, 120),
        "data_categories": data_categories or [],
        "origin": safe_str(origin, 100),
        "freshness": safe_str(freshness, 50),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "temporal": temporal or {},
        "confidence": confidence,
        "state": state,
        "secret_flags": secret_flags,
        "prompt_injection_flags": injection_flags,
        "limitations": [
            "Breach/exposure claim is source-reported, not verified fact.",
            "Claimed record count, dataset size, origin, freshness, and actor remain unverified unless corroborated.",
        ],
    })


def add_dataset(
    parsed: Dict[str, Any],
    dataset_name: Any = None,
    claimed_origin: Any = None,
    suspected_origin: Any = None,
    record_count_claimed: Any = None,
    schema: Any = None,
    data_categories: Optional[List[str]] = None,
    sample_hashes: Optional[List[str]] = None,
    fingerprint: Any = None,
    freshness: Any = None,
    status: str = "DATASET_CLAIM",
    source_id: str = "",
    evidence_id: str = "",
    temporal: Optional[Dict[str, Any]] = None,
) -> None:
    name = safe_str(dataset_name, 300)
    if not any([name, claimed_origin, suspected_origin, record_count_claimed, schema, data_categories, sample_hashes, fingerprint]):
        return

    parsed["datasets"].append({
        "dataset_id": f"DAT-{uuid.uuid4()}",
        "dataset_name": name,
        "claimed_origin": safe_str(claimed_origin, 200),
        "suspected_origin": safe_str(suspected_origin, 200),
        "record_count_claimed": safe_str(record_count_claimed, 120),
        "schema": safe_str(schema, 500),
        "data_categories": data_categories or [],
        "sample_hashes": sample_hashes or [],
        "dataset_fingerprint": safe_str(fingerprint, 200),
        "freshness": safe_str(freshness, 50),
        "status": status,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "temporal": temporal or {},
        "limitations": [
            "Dataset metadata is claim/source-derived unless authorized verification exists.",
            "Sample does not prove full dataset existence or exact record count.",
        ],
    })


def add_credential_exposure(
    parsed: Dict[str, Any],
    exposure_type: Any,
    affected_domain: Any = None,
    redacted_identifier: Any = None,
    credential_category: Any = None,
    validity: str = "VALIDITY_UNKNOWN",
    freshness: str = "UNKNOWN",
    source_id: str = "",
    evidence_id: str = "",
    temporal: Optional[Dict[str, Any]] = None,
) -> None:
    et = safe_str(exposure_type, 100).upper() or "CREDENTIAL_EXPOSURE"
    dom = safe_str(affected_domain, 300)
    ident = safe_str(redacted_identifier, 200)
    if not any([et, dom, ident, credential_category]):
        return

    parsed["credential_exposures"].append({
        "credential_id": f"CRD-{uuid.uuid4()}",
        "exposure_type": et,
        "affected_domain": dom,
        "redacted_identifier": ident,
        "credential_category": safe_str(credential_category, 200),
        "validity": validity,
        "freshness": freshness,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "temporal": temporal or {},
        "state": "CREDENTIAL_EXPOSURE_METADATA",
        "limitations": [
            "Credential exposure metadata is not proof of current validity.",
            "Do not test, login, replay, redeem, or use credentials/tokens/keys.",
        ],
    })


def add_ransomware_claim(
    parsed: Dict[str, Any],
    group: Any = None,
    victim: Any = None,
    claim_date: Any = None,
    data_publication_claim: Any = None,
    sample_claim: Any = None,
    extortion_status: Any = None,
    source_id: str = "",
    evidence_id: str = "",
    temporal: Optional[Dict[str, Any]] = None,
) -> None:
    g = safe_str(group, 300)
    v = safe_str(victim, 300)
    if not any([g, v, claim_date, data_publication_claim, sample_claim, extortion_status]):
        return

    parsed["ransomware_claims"].append({
        "ransom_id": f"RNS-{uuid.uuid4()}",
        "group_label": g,
        "victim_claim": v,
        "claim_date": safe_str(claim_date, 100),
        "data_publication_claim": safe_str(data_publication_claim, 300),
        "sample_claim": safe_str(sample_claim, 300),
        "extortion_status": safe_str(extortion_status, 200),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "temporal": temporal or {},
        "state": "RANSOMWARE_SOURCE_CLAIM",
        "limitations": [
            "Ransomware leak-site/actor claim is not verified breach or verified exfiltration.",
            "Do not contact, negotiate, pay, or operationalize coercion techniques.",
        ],
    })


def add_data_category(parsed: Dict[str, Any], category: Any, source_id: str, evidence_id: str, context: str = "", temporal: Optional[Dict[str, Any]] = None) -> None:
    c = safe_str(category, 100).upper()
    if not c:
        return

    for item in parsed["data_categories"]:
        if item.get("category") == c and item.get("source_id") == source_id:
            return

    parsed["data_categories"].append({
        "category_id": f"CAT-{uuid.uuid4()}",
        "category": c,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "temporal": temporal or {},
        "state": "SOURCE_OBSERVED_DATA_CATEGORY_METADATA",
        "limitations": [
            "Data-category classification is high-level metadata, not reproduction of sensitive content.",
        ],
    })


def add_sensitive_flag(parsed: Dict[str, Any], flag: Any, source_id: str, evidence_id: str, context: str = "", temporal: Optional[Dict[str, Any]] = None) -> None:
    f = safe_str(flag, 100).upper()
    if not f:
        return

    for item in parsed["sensitive_flags"]:
        if item.get("flag") == f and item.get("source_id") == source_id:
            return

    parsed["sensitive_flags"].append({
        "flag_id": f"FLG-{uuid.uuid4()}",
        "flag": f,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "temporal": temporal or {},
        "state": "SENSITIVE_DATA_FLAG",
        "limitations": [
            "Sensitive-data flag triggers stricter privacy/legal handling and human review.",
        ],
    })


def add_record_count(parsed: Dict[str, Any], rc: Dict[str, Any], subject: Any, source_id: str, evidence_id: str, temporal: Optional[Dict[str, Any]] = None) -> None:
    parsed["record_counts"].append({
        "record_count_id": f"RCN-{uuid.uuid4()}",
        "subject": safe_str(subject, 300),
        "raw": safe_str(rc.get("raw"), 120),
        "value": rc.get("value"),
        "unit": safe_str(rc.get("unit"), 50),
        "kind": safe_str(rc.get("kind"), 50),
        "state": "SOURCE_CLAIMED_COUNT",
        "source_id": source_id,
        "evidence_id": evidence_id,
        "temporal": temporal or {},
        "limitations": [
            "Claimed record count is not verified count.",
            "Record count may include duplicates and does not equal unique individuals.",
        ],
    })


def add_fingerprint(parsed: Dict[str, Any], kind: Any, value: Any, subject: Any, source_id: str, evidence_id: str, temporal: Optional[Dict[str, Any]] = None) -> None:
    v = safe_str(value, 200)
    if not v:
        return

    for item in parsed["dataset_fingerprints"]:
        if item.get("value") == v and item.get("source_id") == source_id:
            return

    parsed["dataset_fingerprints"].append({
        "fingerprint_id": f"FPR-{uuid.uuid4()}",
        "kind": safe_str(kind, 100).upper(),
        "value": v,
        "subject": safe_str(subject, 300),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "temporal": temporal or {},
        "state": "DATASET_FINGERPRINT_METADATA",
        "limitations": [
            "Fingerprint supports duplicate/lineage analysis, not breach authenticity by itself.",
        ],
    })


def process_text_block(
    text: str,
    source_id: str,
    evidence_id: str,
    parsed: Dict[str, Any],
    context: str = "",
    temporal: Optional[Dict[str, Any]] = None,
    organization_hint: Any = None,
    domain_hint: Any = None,
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
                 caution="Embedded instructions in breach/dataset/source content are ignored.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    low = normalize_text(redacted)
    domains = extract_domains(redacted)
    subject = organization_hint or domain_hint or (domains[0] if domains else None)
    freshness = infer_freshness(redacted, temporal)
    categories = classify_data_categories(redacted)
    origin_candidates = infer_origin_candidates(redacted, categories, secret_flags)
    sensitive_flags = classify_sensitive_flags(redacted, categories, secret_flags)
    record_counts = extract_record_count(redacted)
    first_record_count = record_counts[0]["raw"] if record_counts else None

    for d in domains[:200]:
        add_mention(parsed, "domain_mentions", "DOMAIN", d, source_id, evidence_id, context=context, temporal=temporal)

    emails = extract_emails(raw)
    for e in emails[:200]:
        dom = e.split("@", 1)[1].lower() if "@" in e else None
        red = redact_email_identifier(e)
        if dom:
            add_mention(parsed, "email_domain_mentions", "EMAIL_DOMAIN", dom, source_id, evidence_id, context=context, temporal=temporal)
        add_mention(parsed, "organization_mentions", "EMAIL_IDENTIFIER_REDACTED", red, source_id, evidence_id, context=context, temporal=temporal)

    cred_types = []
    if EMAIL_PASS_RE.search(raw):
        cred_types.append("PLAINTEXT_PASSWORD_REPORTED")
    if any(k in low for k in ["password", "passwd", "pwd"]):
        cred_types.append("PASSWORD_REPORTED")
    if any(k in low for k in ["hash", "md5", "sha1", "sha256"]):
        cred_types.append("PASSWORD_HASH")
    if any(k in low for k in ["token", "session", "cookie"]):
        cred_types.append("SESSION_TOKEN_REPORTED")
    if any(k in low for k in ["api key", "apikey", "access key", "secret"]):
        cred_types.append("API_SECRET_REPORTED")
    if any(k in low for k in ["private key", "pem", "ssh key"]):
        cred_types.append("PRIVATE_KEY_REPORTED")

    for ct in unique_preserve_order(cred_types):
        affected_domain = domain_hint or (domains[0] if domains else None)
        redacted_identifier = None
        m = EMAIL_PASS_RE.search(raw)
        if m:
            redacted_identifier = redact_email_identifier(m.group(1))
        add_credential_exposure(
            parsed,
            exposure_type=ct,
            affected_domain=affected_domain,
            redacted_identifier=redacted_identifier,
            credential_category=ct,
            validity="VALIDITY_UNKNOWN",
            freshness=freshness,
            source_id=source_id,
            evidence_id=evidence_id,
            temporal=temporal,
        )

    for rc in record_counts[:100]:
        add_record_count(parsed, rc, subject, source_id, evidence_id, temporal=temporal)

    if any(k in low for k in BREACH_KEYWORDS):
        add_claim(
            parsed,
            "BREACH_CLAIM",
            redacted[:500],
            subject=subject,
            organization=organization_hint,
            domain=domain_hint or (domains[0] if domains else None),
            record_count=first_record_count,
            data_categories=categories,
            origin=origin_candidates[0] if origin_candidates else None,
            freshness=freshness,
            source_id=source_id,
            evidence_id=evidence_id,
            temporal=temporal,
            confidence="LOW",
            state="SOURCE_CLAIM",
        )

    if any(k in low for k in DATASET_KEYWORDS):
        add_dataset(
            parsed,
            dataset_name=subject,
            claimed_origin=origin_candidates[0] if origin_candidates else None,
            suspected_origin=origin_candidates[0] if origin_candidates else "UNKNOWN",
            record_count_claimed=first_record_count,
            data_categories=categories,
            freshness=freshness,
            status="DATASET_CLAIM",
            source_id=source_id,
            evidence_id=evidence_id,
            temporal=temporal,
        )

    if any(k in low for k in RANSOMWARE_KEYWORDS):
        add_ransomware_claim(
            parsed,
            victim=subject,
            data_publication_claim="claimed" if "publish" in low or "leak" in low else None,
            sample_claim="claimed" if "sample" in low else None,
            extortion_status="source_claimed_extortion" if "extort" in low or "ransom" in low else None,
            source_id=source_id,
            evidence_id=evidence_id,
            temporal=temporal,
        )

    for oc in origin_candidates[:50]:
        add_claim(
            parsed,
            oc,
            redacted[:500],
            subject=subject,
            organization=organization_hint,
            domain=domain_hint,
            record_count=first_record_count,
            data_categories=categories,
            origin=oc,
            freshness=freshness,
            source_id=source_id,
            evidence_id=evidence_id,
            temporal=temporal,
            confidence="LOW",
            state="SOURCE_CLAIM",
        )

    for cat in categories[:100]:
        add_data_category(parsed, cat, source_id, evidence_id, context=context, temporal=temporal)

    for flag in sensitive_flags[:100]:
        add_sensitive_flag(parsed, flag, source_id, evidence_id, context=context, temporal=temporal)

    for h in extract_hashes(redacted)[:200]:
        add_fingerprint(parsed, "SHA256", h, subject, source_id, evidence_id, temporal=temporal)


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:20000].lower()
    fname = normalize_text(filename)

    if data.get("type") == "bundle" or "objects" in keys:
        return "STIX_PACKAGE"
    if "Event" in data or "Attribute" in data or "Object" in data or "misp" in fname:
        return "MISP_EVENT"
    if "breach" in fname or "breach" in keys or "compromis" in low:
        return "BREACH_CLAIM"
    if "dataset" in fname or "schema" in keys or "record_count" in keys:
        return "DATASET_METADATA"
    if "credential" in fname or "password" in low or "combo" in low:
        return "CREDENTIAL_EXPOSURE_METADATA"
    if "ransom" in fname or "leak" in fname or "victim" in keys:
        return "RANSOMWARE_LEAK_METADATA"
    if "incident" in fname or "telemetry" in fname:
        return "AUTHORIZED_INCIDENT_DATA"
    if "historical" in fname or "old" in fname:
        return "HISTORICAL_BREACH_METADATA"
    if "stealer" in fname or "infostealer" in low:
        return "STEALER_LOG_METADATA"
    if "supply" in fname or "vendor" in low or "third_party" in keys:
        return "SUPPLY_CHAIN_EXPOSURE"
    if "repo" in fname or "source_code" in fname or "git" in low:
        return "REPOSITORY_OR_SOURCE_CODE_EXPOSURE"
    if "cloud" in fname or "bucket" in low or "storage" in low:
        return "CLOUD_EXPOSURE"
    if "document" in fname or "pdf" in low:
        return "DOCUMENT_EXPOSURE"

    return "GENERIC_JSON"


def process_json_record(
    rec: Dict[str, Any],
    source_id: str,
    evidence_id: str,
    parsed: Dict[str, Any],
    context: str = "",
    organization_hint: Any = None,
    domain_hint: Any = None,
) -> None:
    rec = json.loads(_support.redact_text(json.dumps(rec, ensure_ascii=False, default=str)))
    if not isinstance(rec, dict):
        return

    temporal = extract_temporal(rec)
    tags = collect_tags(rec)
    rec_context = context or "json_record"

    organization = get_field(rec, ["organization", "company", "victim_org", "target_org", "org"]) or organization_hint
    brand = get_field(rec, ["brand", "product"])
    domain = get_field(rec, ["domain", "target_domain"]) or domain_hint
    email_domain = get_field(rec, ["email_domain", "affected_email_domain"])
    subsidiary = get_field(rec, ["subsidiary", "parent_company"])
    third_party = get_field(rec, ["third_party", "vendor", "saas", "processor"])
    supplier = get_field(rec, ["supplier", "partner", "msp"])
    claim_type = get_field(rec, ["claim_type", "type"])
    claim_text = get_field(rec, ["claim_text", "text", "description", "summary", "evidence"])
    claimant = get_field(rec, ["claimant", "seller", "persona", "source_actor"])
    dataset_name = get_field(rec, ["dataset_name", "dataset", "dump_name"])
    record_count = get_field(rec, ["record_count", "claimed_records", "rows", "count"])
    data_size = get_field(rec, ["data_size", "size"])
    data_categories = get_field(rec, ["data_categories", "claimed_data", "categories"], as_list=True)
    credential_type = get_field(rec, ["credential_type", "exposure_type", "secret_type"])
    affected_domain = get_field(rec, ["affected_domain", "domain"]) or domain
    identifier = get_field(rec, ["identifier", "username", "email", "redacted_identifier"])
    ransomware_group = get_field(rec, ["ransomware_group", "group", "actor_label", "leak_site"])
    victim = get_field(rec, ["victim", "victim_name", "target"])
    origin = get_field(rec, ["origin", "suspected_origin", "claimed_origin"])
    freshness = get_field(rec, ["freshness", "data_freshness"])
    schema = get_field(rec, ["schema", "fields", "columns"])
    sample_hash = get_field(rec, ["sample_hash", "sample_hashes"], as_list=True)
    dataset_hash = get_field(rec, ["dataset_hash", "fingerprint", "content_hash"])

    subject = organization or domain or victim or dataset_name

    if organization:
        add_mention(parsed, "organization_mentions", "ORGANIZATION", organization, source_id, evidence_id, context=rec_context, temporal=temporal)
    if brand:
        add_mention(parsed, "brand_mentions", "BRAND", brand, source_id, evidence_id, context=rec_context, temporal=temporal)
    if domain:
        add_mention(parsed, "domain_mentions", "DOMAIN", domain, source_id, evidence_id, context=rec_context, temporal=temporal)
    if email_domain:
        add_mention(parsed, "email_domain_mentions", "EMAIL_DOMAIN", email_domain, source_id, evidence_id, context=rec_context, temporal=temporal)
    if subsidiary:
        add_mention(parsed, "organization_mentions", "SUBSIDIARY_OR_PARENT", subsidiary, source_id, evidence_id, context=rec_context, temporal=temporal)
    if third_party:
        add_mention(parsed, "third_party_mentions", "THIRD_PARTY", third_party, source_id, evidence_id, context=rec_context, temporal=temporal)
    if supplier:
        add_mention(parsed, "supplier_mentions", "SUPPLIER", supplier, source_id, evidence_id, context=rec_context, temporal=temporal)

    if identifier and "@" in str(identifier):
        add_mention(parsed, "organization_mentions", "EMAIL_IDENTIFIER_REDACTED", redact_email_identifier(identifier), source_id, evidence_id, context=rec_context, temporal=temporal)

    if claim_text or claim_type:
        add_claim(
            parsed,
            claim_type=claim_type or "BREACH_CLAIM",
            text=claim_text or json.dumps(rec, ensure_ascii=False, default=str)[:500],
            subject=subject,
            claimant=claimant,
            organization=organization,
            domain=domain,
            record_count=record_count or data_size,
            data_categories=[str(x) for x in data_categories if x],
            origin=origin,
            freshness=freshness,
            source_id=source_id,
            evidence_id=evidence_id,
            temporal=temporal,
            confidence="LOW",
            state="SOURCE_CLAIM",
        )

    if any([dataset_name, record_count, data_size, schema, dataset_hash, sample_hash]):
        add_dataset(
            parsed,
            dataset_name=dataset_name or subject,
            claimed_origin=origin,
            suspected_origin=origin or "UNKNOWN",
            record_count_claimed=record_count or data_size,
            schema=schema,
            data_categories=[str(x) for x in data_categories if x],
            sample_hashes=[str(x) for x in sample_hash if x],
            fingerprint=dataset_hash,
            freshness=freshness,
            status="DATASET_METADATA_PARSED",
            source_id=source_id,
            evidence_id=evidence_id,
            temporal=temporal,
        )

    if any([credential_type, identifier, affected_domain]):
        add_credential_exposure(
            parsed,
            exposure_type=credential_type or "CREDENTIAL_EXPOSURE",
            affected_domain=affected_domain,
            redacted_identifier=redact_email_identifier(identifier) if identifier and "@" in str(identifier) else safe_str(identifier, 200),
            credential_category=credential_type,
            validity="VALIDITY_UNKNOWN",
            freshness=freshness or "UNKNOWN",
            source_id=source_id,
            evidence_id=evidence_id,
            temporal=temporal,
        )

    if any([ransomware_group, victim, claim_type and "RANSOM" in str(claim_type).upper()]):
        add_ransomware_claim(
            parsed,
            group=ransomware_group,
            victim=victim or subject,
            claim_date=temporal.get("published_at") or temporal.get("first_seen"),
            data_publication_claim="claimed" if "publish" in normalize_text(json.dumps(rec, default=str)) else None,
            sample_claim="claimed" if "sample" in normalize_text(json.dumps(rec, default=str)) else None,
            extortion_status="source_claimed_extortion" if "extort" in normalize_text(json.dumps(rec, default=str)) else None,
            source_id=source_id,
            evidence_id=evidence_id,
            temporal=temporal,
        )

    if dataset_hash:
        add_fingerprint(parsed, "DATASET_HASH", dataset_hash, subject, source_id, evidence_id, temporal=temporal)
    for sh in sample_hash[:50]:
        add_fingerprint(parsed, "SAMPLE_HASH", sh, subject, source_id, evidence_id, temporal=temporal)

    rec_text = json.dumps(rec, ensure_ascii=False, default=str)[:5000]
    process_text_block(
        rec_text,
        source_id,
        evidence_id,
        parsed,
        context=f"json:{rec_context}",
        temporal=temporal,
        organization_hint=organization,
        domain_hint=domain,
    )


def walk_json(
    data: Any,
    source_id: str,
    evidence_id: str,
    parsed: Dict[str, Any],
    depth: int = 0,
    path: str = "",
    organization_hint: Any = None,
    domain_hint: Any = None,
) -> None:
    if depth > 14 or len(parsed.get("observations", [])) > 200000:
        return

    if isinstance(data, dict):
        process_json_record(data, source_id, evidence_id, parsed, context=path or "json", organization_hint=organization_hint, domain_hint=domain_hint)
        for k, v in data.items():
            new_path = f"{path}.{k}" if path else str(k)
            walk_json(v, source_id, evidence_id, parsed, depth + 1, new_path, organization_hint, domain_hint)
    elif isinstance(data, list):
        for item in data[:100000]:
            walk_json(item, source_id, evidence_id, parsed, depth + 1, path, organization_hint, domain_hint)
    elif isinstance(data, str):
        process_text_block(data, source_id, evidence_id, parsed, context=path or "json_string", organization_hint=organization_hint, domain_hint=domain_hint)


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
    kind = "CSV_BREACH_DATA"

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
    if any(k in low for k in BREACH_KEYWORDS):
        kind = "TEXT_BREACH_CLAIM"
    elif any(k in low for k in DATASET_KEYWORDS):
        kind = "TEXT_DATASET_METADATA"
    elif any(k in low for k in CREDENTIAL_KEYWORDS):
        kind = "TEXT_CREDENTIAL_EXPOSURE"
    elif any(k in low for k in RANSOMWARE_KEYWORDS):
        kind = "TEXT_RANSOMWARE_CLAIM"
    elif any(k in low for k in COMBO_KEYWORDS):
        kind = "TEXT_COMBO_LIST_METADATA"
    elif any(k in low for k in STEALER_KEYWORDS):
        kind = "TEXT_STEALER_LOG_METADATA"
    else:
        kind = "TEXT_BREACH_REPORT"

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
        ".pcap", ".pcapng", ".cap", ".msi", ".cab",
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


def analyze_breach_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
            "No purchasing stolen data/credentials/access, downloading unnecessary full stolen datasets, using exposed credentials, testing passwords, credential stuffing, replaying session tokens, using API/private keys, logging into exposed accounts, contacting sellers, negotiating ransoms, redistributing sensitive data, unauthorized access, or exploitation performed.",
            "Binary artifacts are hash/metadata preserved only; no execution, unpacking, or deep parsing performed.",
            "Dataset records, documents, forum posts, repository content, ransomware notes, and seller descriptions are untrusted evidence, not instructions.",
            "Exposed secrets are redacted and not used.",
            "Source claims are not verified breach, dataset authenticity, record count, origin, credential validity, or actor attribution.",
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
            file_evidence["content_kind"] = "BINARY_ARTIFACT_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary artifact detected. This planning panel preserves hash/metadata only. "
                "It does not execute, unpack, modify, reverse-engineer, fuzz, replay PCAPs, or deeply parse binary artifacts."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_claim_count"] = len(parsed.get("claims", []))
    file_evidence["parsed_dataset_count"] = len(parsed.get("datasets", []))
    file_evidence["parsed_credential_count"] = len(parsed.get("credential_exposures", []))
    file_evidence["parsed_ransomware_count"] = len(parsed.get("ransomware_claims", []))
    file_evidence["parsed_record_count_candidates"] = len(parsed.get("record_counts", []))

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


def build_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []

    rc_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for rc in parsed.get("record_counts", []):
        subject = normalize_text(rc.get("subject") or "UNKNOWN_SUBJECT")
        rc_groups[subject].append(rc)

    for subject, group in rc_groups.items():
        values = sorted({str(x.get("value")) for x in group if x.get("value") is not None})
        if len(values) > 1:
            contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "RECORD_COUNT_CONFLICT",
                "subject": subject[:300],
                "values": values[:100],
                "possible_explanations": [
                    "different datasets",
                    "partial copies",
                    "marketing exaggeration",
                    "old vs new breach",
                    "third-party breach",
                    "reseller/recycled data",
                    "duplicate records",
                    "analyst/source error",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Claimed record counts are source claims, not verified counts.",
            })

    claim_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for c in parsed.get("claims", []):
        subject = normalize_text(c.get("subject") or c.get("organization") or c.get("domain") or "UNKNOWN_SUBJECT")
        claim_groups[subject].append(c)

    for subject, group in claim_groups.items():
        origins = sorted({c.get("origin") for c in group if c.get("origin") and c.get("origin") != "UNKNOWN"})
        if len(origins) > 1:
            contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "ORIGIN_CONFLICT",
                "subject": subject[:300],
                "values": origins[:100],
                "possible_explanations": [
                    "first-party vs third-party uncertainty",
                    "supplier breach",
                    "combo list/stealer log aggregation",
                    "public/scraped data repackaging",
                    "recycled dataset",
                    "source simplification",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Do not force single origin without evidence.",
            })

        freshness_values = sorted({c.get("freshness") for c in group if c.get("freshness") and c.get("freshness") != "UNKNOWN"})
        if len(freshness_values) > 1:
            contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "FRESHNESS_CONFLICT",
                "subject": subject[:300],
                "values": freshness_values[:100],
                "possible_explanations": [
                    "mixed dataset",
                    "old + new records",
                    "recycled data",
                    "source lag",
                    "different publication times",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Data authenticity and data freshness are separate dimensions.",
            })

    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    claims = parsed.get("claims", [])
    datasets = parsed.get("datasets", [])
    creds = parsed.get("credential_exposures", [])
    ransom = parsed.get("ransomware_claims", [])
    sources = parsed.get("sources", [])
    claim_types = {c.get("claim_type") for c in claims}

    if not claims and not datasets and not creds and not ransom:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Current local deterministic evidence is insufficient to assess breach authenticity, dataset origin, record count, credential exposure, or defensive impact.",
            "supporting_facts": ["No breach/dataset/credential/ransomware claims parsed."],
            "opposing_facts": [],
            "assumptions": ["Evidence may be missing, unsupported, binary-only, or unavailable."],
            "unknowns": ["breach authenticity", "dataset origin", "record count", "data freshness", "credential validity", "source independence"],
            "falsification_conditions": ["New authorized/public/licensed breach, dataset, credential, incident, or exposure evidence changes assessment."],
            "next_test": "Attach breach claim exports, dataset metadata, credential exposure metadata, ransomware leak metadata, historical breach records, or authorized incident data.",
            "status": "OPEN",
        })
        return hyps[:1000]

    if "BREACH_CLAIM" in claim_types or any(c.get("claim_type") == "BREACH_CLAIM" for c in claims):
        hyps.extend([
            {
                "hypothesis_id": f"HYP-{uuid.uuid4()}",
                "statement": "Claim may represent a new first-party breach of the named organization/domain.",
                "supporting_facts": ["Breach claim parsed."],
                "opposing_facts": ["Email-domain presence alone does not establish first-party breach."],
                "unknowns": ["dataset origin", "breach authenticity", "current relevance", "incident evidence"],
                "falsification_conditions": ["Data is third-party, supplier, recycled, combo list, stealer log, public/scraped, or fraudulent."],
                "next_test": "Correlate authorized incident/identity/cloud/DLP telemetry; compare historical breaches; do not acquire full stolen dataset.",
                "status": "OPEN",
            },
            {
                "hypothesis_id": f"HYP-{uuid.uuid4()}",
                "statement": "Exposure may originate from third party, supplier, SaaS, CRM, payroll, marketing, or processor rather than customer infrastructure.",
                "supporting_facts": ["Third-party/supplier keywords or ambiguous origin parsed." if any(k in claim_types for k in ["THIRD_PARTY_CANDIDATE", "SUPPLY_CHAIN_CANDIDATE"]) else "Origin remains unresolved."],
                "opposing_facts": ["Some records may be directly associated with organization domain."],
                "unknowns": ["supplier relationship", "data holder", "breach origin"],
                "falsification_conditions": ["Independent incident evidence shows first-party system compromise."],
                "next_test": "Review vendor/supplier relationships and third-party breach context.",
                "status": "OPEN",
            },
            {
                "hypothesis_id": f"HYP-{uuid.uuid4()}",
                "statement": "Dataset may be recycled, repackaged, combo list, stealer log, or aggregated historical data rather than a new breach.",
                "supporting_facts": ["Recycled/combo/stealer/public keywords parsed." if any(k in claim_types for k in ["RECYCLED_CANDIDATE", "COMBO_LIST", "STEALER_LOG", "PUBLIC_DATA_CANDIDATE", "SCRAPED_DATA_CANDIDATE"]) else "No explicit recycling signal parsed, but origin remains uncertain."],
                "opposing_facts": ["Some timestamps or source metadata may suggest recent activity."],
                "unknowns": ["dataset lineage", "record overlap", "freshness"],
                "falsification_conditions": ["Fingerprint/lineage analysis shows unique new records and independent incident corroboration."],
                "next_test": "Compare historical breach corpus and dataset fingerprints.",
                "status": "OPEN",
            },
            {
                "hypothesis_id": f"HYP-{uuid.uuid4()}",
                "statement": "Claim may be fraudulent, exaggerated, or marketing-driven.",
                "supporting_facts": ["Seller/extortion incentives exist."],
                "opposing_facts": ["Claim may be genuine."],
                "unknowns": ["sample authenticity", "source reliability", "record count accuracy"],
                "falsification_conditions": ["Independent authorized evidence verifies dataset/access/exposure."],
                "next_test": "Adversarial review; do not contact seller, purchase data, or test credentials.",
                "status": "OPEN",
            },
        ])

    if creds:
        hyps.extend([
            {
                "hypothesis_id": f"HYP-{uuid.uuid4()}",
                "statement": "Credential/secret exposure metadata may reflect current authentication risk.",
                "supporting_facts": [f"{len(creds)} credential exposure record(s) parsed."],
                "opposing_facts": ["Validity is unknown and must not be tested."],
                "unknowns": ["credential freshness", "account status", "MFA/session context"],
                "falsification_conditions": ["Authorized identity/IAM evidence shows secrets already revoked/expired/invalid."],
                "next_test": "Handoff to EXPOSUREINT/identity workflow for rotation/revocation without testing.",
                "status": "OPEN",
            },
            {
                "hypothesis_id": f"HYP-{uuid.uuid4()}",
                "statement": "Credential exposure may reflect historical breach, password reuse, combo list, stealer log, or third-party service rather than current organizational compromise.",
                "supporting_facts": ["Combo/stealer/third-party/public context possible."],
                "opposing_facts": ["Some credentials may be active."],
                "unknowns": ["origin", "reuse", "current validity"],
                "falsification_conditions": ["Authorized telemetry shows no current use and identity provider confirms remediation."],
                "next_test": "Privacy-aware exposure triage; do not login/test/replay.",
                "status": "OPEN",
            },
        ])

    if ransom:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Ransomware victim/data-publication claim may be true but unverified, or may reflect bluff, misidentification, supplier breach, or recycled data.",
            "supporting_facts": [f"{len(ransom)} ransomware claim record(s) parsed."],
            "opposing_facts": ["Leak-site appearance alone is CLAIM_ONLY unless corroborated."],
            "unknowns": ["victim confirmation", "data exfiltration", "group attribution"],
            "falsification_conditions": ["Independent victim/incident/CTI evidence confirms or refutes claim."],
            "next_test": "Handoff to INCIDENTINT/CTI/DARKINT; do not negotiate/contact/pay.",
            "status": "OPEN",
        })

    dependent_sources = [s for s in sources if s.get("source_independence_state") in {"DEPENDENT_COPIES", "DEPENDENT_CONTENT_FAMILY", "PARTIALLY_DEPENDENT_PENDING_REVIEW"}]
    if dependent_sources:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Apparent multiple sources may be dependent copies, aggregators, mirrors, or reposts rather than independent corroboration.",
            "supporting_facts": [f"{len(dependent_sources)} dependent/partially dependent source record(s)."],
            "opposing_facts": ["Some sources may still be independent."],
            "unknowns": ["upstream pedigree", "original reporter"],
            "falsification_conditions": ["Source pedigree analysis shows truly independent observation families."],
            "next_test": "Resolve original claim, first mirror, aggregators, and media/vendor republication.",
            "status": "OPEN",
        })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    claims = parsed.get("claims", [])
    datasets = parsed.get("datasets", [])
    creds = parsed.get("credential_exposures", [])
    sources = parsed.get("sources", [])

    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What authorized/public/licensed breach/exposure evidence exists?",
            "missing_evidence": "No local BREACHINT evidence file supplied.",
            "likely_source": "Official disclosure, regulator notification, CERT advisory, licensed breach-monitoring export, authorized credential-monitoring export, ransomware leak metadata, incident data, STIX/MISP.",
            "specialist_owner": "BREACHINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables breach claim/dataset/credential metadata planning.",
            "safety_boundary": "No purchase, credential testing, login, token replay, seller contact, ransomware negotiation, full dataset acquisition, or exploitation.",
        })

    if not claims:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What breach/exposure claims are being asserted?",
            "missing_evidence": "No claim records parsed.",
            "likely_source": "Breach claim export, ransomware leak metadata, official disclosure, incident report, licensed monitoring feed.",
            "specialist_owner": "BREACHINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Establishes claim inventory.",
            "safety_boundary": "Do not invent breaches, victims, datasets, or record counts.",
        })

    if claims and not datasets:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What dataset metadata supports the claim?",
            "missing_evidence": "Claims parsed but no dataset metadata.",
            "likely_source": "Dataset schema, sample hashes, record counts, field names, timestamps, fingerprints.",
            "specialist_owner": "BREACHINT / EXPOSUREINT",
            "priority": "HIGH",
            "expected_information_value": "Supports dataset authenticity/lineage analysis.",
            "safety_boundary": "Use minimized metadata, not full stolen datasets.",
        })

    if datasets and not parsed.get("dataset_fingerprints"):
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Can dataset be deduplicated/lineage-analyzed against historical breaches?",
            "missing_evidence": "No dataset fingerprints parsed.",
            "likely_source": "File hashes, schema fingerprints, sample hashes, MinHash/SimHash, record overlap sketches.",
            "specialist_owner": "BREACHINT",
            "priority": "HIGH_IF_RECYCLING_CONSEQUENTIAL",
            "expected_information_value": "Reduces false new-breach rate.",
            "safety_boundary": "Do not acquire full illicit datasets merely to fingerprint.",
        })

    if creds:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Are exposed credentials/secrets current, historical, reused, third-party, or stealer-log noise?",
            "missing_evidence": "Credential exposure metadata parsed but validity/currentness unresolved.",
            "likely_source": "Authorized identity/IAM logs, credential-monitoring provider, EXPOSUREINT, incident telemetry.",
            "specialist_owner": "EXPOSUREINT / INCIDENTINT",
            "priority": "HIGH_PRIVACY_SENSITIVE",
            "expected_information_value": "Supports credential reset/token revocation/MFA review.",
            "safety_boundary": "Do not test, login, replay, redeem, or use credentials/tokens.",
        })

    if any(s.get("source_independence_state") in {"UNKNOWN", "UNKNOWN_POTENTIALLY_INDEPENDENT"} for s in sources) and len(sources) > 1:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Are multiple reports actually independent?",
            "missing_evidence": "Source independence unresolved.",
            "likely_source": "Original claim, first mirror, aggregator pedigree, media/vendor republication chain.",
            "specialist_owner": "BREACHINT / CTI",
            "priority": "HIGH",
            "expected_information_value": "Prevents false corroboration from reposts.",
            "safety_boundary": "Do not count republishing as corroboration.",
        })

    if parsed.get("sensitive_flags"):
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What privacy/legal handling is required for sensitive data categories?",
            "missing_evidence": "Sensitive flags detected but legal/privacy review not executed.",
            "likely_source": "Legal/compliance workflow, regulator guidance, organization policy.",
            "specialist_owner": "Legal / Compliance / Privacy Officer",
            "priority": "HIGH_PRIVACY_LEGAL",
            "expected_information_value": "Ensures lawful, minimized, privacy-aware handling.",
            "safety_boundary": "BREACHINT does not make final legal determinations or autonomously notify.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    claims = parsed.get("claims", [])
    creds = parsed.get("credential_exposures", [])
    ransom = parsed.get("ransomware_claims", [])
    datasets = parsed.get("datasets", [])
    flags = parsed.get("sensitive_flags", [])

    if creds:
        handoffs.append({
            "specialist": "EXPOSUREINT",
            "reason": "Credential/secret exposure metadata detected.",
            "expected_output": "Current exposure triage, rotation/revocation recommendation, without testing credentials.",
            "question": "Which exposed credentials/secrets are current, organizational, and require defensive remediation?",
        })

    if claims or datasets:
        handoffs.append({
            "specialist": "INCIDENTINT / LOGINT",
            "reason": "Breach/dataset claim detected.",
            "expected_output": "Authorized telemetry correlation, root-cause investigation, and incident timeline.",
            "question": "Do internal logs/EDR/identity/cloud/DLP evidence corroborate or refute the external claim?",
        })

    if ransom:
        handoffs.append({
            "specialist": "CTI / THREATACTORINT / DARKINT",
            "reason": "Ransomware/extortion claim detected.",
            "expected_output": "Leak-site/source authenticity, group lineage, campaign context, and victim validation support.",
            "question": "Is ransomware victim/data-publication claim independently corroborated, and what actor/campaign context applies?",
        })

    if any(c.get("claim_type") in {"THIRD_PARTY_CANDIDATE", "SUPPLY_CHAIN_CANDIDATE"} for c in claims) or parsed.get("third_party_mentions") or parsed.get("supplier_mentions"):
        handoffs.append({
            "specialist": "Third-party risk / vendor management / EXPOSUREINT",
            "reason": "Third-party/supply-chain exposure context detected.",
            "expected_output": "Supplier data relationship, affected customer scope, and vendor incident validation.",
            "question": "Does exposure originate from supplier/vendor/SaaS rather than customer infrastructure?",
        })

    if any(c.get("claim_type") in {"SOURCE_CODE_EXPOSURE_CANDIDATE", "REPOSITORY_EXPOSURE_CANDIDATE"} for c in claims):
        handoffs.append({
            "specialist": "REPOINT / EXPOSUREINT",
            "reason": "Source-code/repository exposure context detected.",
            "expected_output": "Repository identity, secret exposure, commit/history review, and code exposure impact.",
            "question": "Which repository/source-code metadata indicates exposure, and are secrets present?",
        })

    if any(c.get("claim_type") == "CLOUD_EXPOSURE_CANDIDATE" for c in claims):
        handoffs.append({
            "specialist": "CLOUDSEC / EXPOSUREINT",
            "reason": "Cloud exposure context detected.",
            "expected_output": "Misconfigured storage/bucket/API exposure validation without exploitation.",
            "question": "Is cloud storage/API exposure public, misconfigured, or tied to a breach event?",
        })

    if any(c.get("claim_type") == "DOCUMENT_EXPOSURE_CANDIDATE" for c in claims):
        handoffs.append({
            "specialist": "DOCINT",
            "reason": "Document exposure context detected.",
            "expected_output": "Safe document metadata/category analysis with privacy minimization.",
            "question": "Which document categories/metadata support exposure assessment?",
        })

    if flags:
        handoffs.append({
            "specialist": "Legal / Compliance / Privacy Officer",
            "reason": "Sensitive data flags detected.",
            "expected_output": "Privacy/legal review, regulated-data handling, notification consideration.",
            "question": "What legal/privacy obligations may apply, and what minimum evidence package is required?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "BREACHINT Manager",
            "reason": "No specialized handoff triggered from current local deterministic evidence alone.",
            "expected_output": "Review scope, approve authorized connectors, assign breach/exposure collection tasks.",
            "question": "What breach intelligence gap should be filled next?",
        })

    return handoffs


def build_breach_summary(parsed: Dict[str, Any]) -> Dict[str, Any]:
    claims = parsed.get("claims", [])
    datasets = parsed.get("datasets", [])
    creds = parsed.get("credential_exposures", [])
    ransom = parsed.get("ransomware_claims", [])
    sources = parsed.get("sources", [])

    claim_type_counter = Counter(str(c.get("claim_type", "UNKNOWN")) for c in claims)
    origin_counter = Counter(str(c.get("origin", "UNKNOWN")) for c in claims if c.get("origin"))
    freshness_counter = Counter(str(c.get("freshness", "UNKNOWN")) for c in claims if c.get("freshness"))
    category_counter = Counter()
    for c in claims:
        for cat in c.get("data_categories", []):
            category_counter[str(cat)] += 1
    for d in datasets:
        for cat in d.get("data_categories", []):
            category_counter[str(cat)] += 1

    sensitive_counter = Counter(str(f.get("flag", "UNKNOWN")) for f in parsed.get("sensitive_flags", []))
    independence_counter = Counter(str(s.get("source_independence_state", "UNKNOWN")) for s in sources)

    return {
        "source_count": len(sources),
        "claim_count": len(claims),
        "dataset_count": len(datasets),
        "credential_exposure_count": len(creds),
        "ransomware_claim_count": len(ransom),
        "record_count_candidate_count": len(parsed.get("record_counts", [])),
        "fingerprint_count": len(parsed.get("dataset_fingerprints", [])),
        "by_claim_type": dict(claim_type_counter.most_common(500)),
        "by_origin": dict(origin_counter.most_common(500)),
        "by_freshness": dict(freshness_counter.most_common(500)),
        "by_data_category": dict(category_counter.most_common(500)),
        "by_sensitive_flag": dict(sensitive_counter.most_common(500)),
        "by_source_independence": dict(independence_counter.most_common(500)),
        "top_claims": claims[:300],
        "top_datasets": datasets[:300],
        "top_credential_exposures": creds[:300],
        "top_ransomware_claims": ransom[:300],
        "limitations": [
            "Summary is deterministic/local and source-dependent.",
            "Claims are not verified breach, dataset authenticity, record count, origin, credential validity, or actor attribution.",
        ],
    }


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    build_source_independence(parsed)
    parsed["contradictions"] = build_contradictions(parsed)
    parsed["hypotheses"] = build_hypotheses(parsed)
    parsed["knowledge_gaps"] = build_knowledge_gaps(payload or {}, files or [], parsed)
    parsed["specialist_handoffs"] = build_specialist_handoffs(parsed)
    parsed["breach_summary"] = build_breach_summary(parsed)
    return parsed


def build_next_best_action(
    payload: Dict[str, Any],
    policy: Dict[str, Any],
    files: List[Dict[str, Any]],
    parsed: Dict[str, Any],
) -> Dict[str, str]:
    claims = parsed.get("claims", [])
    creds = parsed.get("credential_exposures", [])
    ransom = parsed.get("ransomware_claims", [])
    sources = parsed.get("sources", [])
    claim_types = {c.get("claim_type") for c in claims}

    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited purchase, credential testing, login, token replay, seller contact, ransomware negotiation, full stolen-dataset acquisition, redistribution, unauthorized access, or exploitation behavior.",
            "reason": "BREACHINT is defensive breach/exposure metadata intelligence, not stolen-data acquisition or credential use.",
            "owner": "BREACHINT Manager",
            "expected_output": "Policy-compliant defensive BREACHINT scope and question set.",
        }

    if policy.get("status") == "HUMAN_REVIEW_REQUIRED":
        return {
            "action": "Route to human BREACHINT/legal/privacy reviewer before breach confirmation, user notification, regulatory action, law-enforcement referral, credential remediation, or public disclosure.",
            "reason": "Breach/exposure findings can be consequential, privacy-sensitive, and legally sensitive.",
            "owner": "BREACHINT Manager",
            "expected_output": "Approved defensive verification plan, evidence gaps, and handoffs.",
        }

    if not files:
        return {
            "action": "Attach authorized/public/licensed breach claim, dataset metadata, credential exposure metadata, ransomware leak metadata, historical breach records, incident data, or STIX/MISP artifacts before analysis.",
            "reason": "No BREACHINT evidence artifact is available for local deterministic analysis.",
            "owner": "BREACHINT AI Employee",
            "expected_output": "Breach evidence inventory with hashes and provenance.",
        }

    if not claims:
        return {
            "action": "Obtain claim inventory from official disclosure, licensed breach-monitoring export, ransomware leak metadata, incident report, or authorized exposure report.",
            "reason": "No breach/exposure claims parsed.",
            "owner": "BREACHINT AI Employee",
            "expected_output": "Claim objects with claimant, subject, time, source, and limitations.",
        }

    if any(s.get("source_independence_state") in {"UNKNOWN", "UNKNOWN_POTENTIALLY_INDEPENDENT"} for s in sources) and len(sources) > 1:
        return {
            "action": "Resolve source pedigree/independence before treating reposts/aggregators/media coverage as corroboration.",
            "reason": "Multiple republishing events can reflect one original claim.",
            "owner": "BREACHINT / CTI",
            "expected_output": "INDEPENDENT / PARTIALLY_DEPENDENT / DEPENDENT source states.",
        }

    if creds:
        return {
            "action": "Handoff credential/secret exposure metadata to EXPOSUREINT/identity workflow for rotation/revocation; do not test credentials.",
            "reason": "Credential exposure validity is unknown and testing is prohibited.",
            "owner": "EXPOSUREINT / identity/security operations",
            "expected_output": "Privacy-aware credential remediation recommendation.",
        }

    if ransom:
        return {
            "action": "Seek independent victim/incident/CTI confirmation for ransomware claim; do not contact/negotiate/pay.",
            "reason": "Ransomware leak-site claim is CLAIM_ONLY until corroborated.",
            "owner": "INCIDENTINT / CTI / DARKINT",
            "expected_output": "Corroborated or inconclusive ransomware victim assessment.",
        }

    if {"THIRD_PARTY_CANDIDATE", "SUPPLY_CHAIN_CANDIDATE"} & claim_types or parsed.get("third_party_mentions") or parsed.get("supplier_mentions"):
        return {
            "action": "Review supplier/vendor/third-party data relationships before labeling customer infrastructure breached.",
            "reason": "Third-party exposure should not be converted into first-party breach without evidence.",
            "owner": "Third-party risk / EXPOSUREINT / INCIDENTINT",
            "expected_output": "First-party vs third-party origin assessment.",
        }

    if {"RECYCLED_CANDIDATE", "COMBO_LIST", "STEALER_LOG", "PUBLIC_DATA_CANDIDATE", "SCRAPED_DATA_CANDIDATE"} & claim_types:
        return {
            "action": "Compare dataset fingerprints/schema/record overlap against historical breach corpus before calling it new.",
            "reason": "Recycled/combo/stealer/public data can masquerade as new breach.",
            "owner": "BREACHINT",
            "expected_output": "NEW_DATASET_SUPPORTED / PARTIALLY_NEW / RECYCLED / REPACKAGED / UNKNOWN.",
        }

    if parsed.get("record_counts"):
        return {
            "action": "Separate claimed, observed sample, estimated unique, and verified record counts before reporting impact.",
            "reason": "Claimed record counts are often exaggerated and duplicates inflate counts.",
            "owner": "BREACHINT / data steward",
            "expected_output": "Record-count confidence dimensions.",
        }

    return {
        "action": "Proceed with dataset metadata review, organization resolution, source independence, privacy-aware impact assessment, incident correlation planning, and specialist handoffs.",
        "reason": "Local evidence exists, but breach truth remains source-dependent until corroboration.",
        "owner": "BREACHINT / EXPOSUREINT / INCIDENTINT / CTI",
        "expected_output": "Evidence-linked breach intelligence report with limitations and next actions.",
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
    has_claims = bool(parsed.get("claims"))
    has_datasets = bool(parsed.get("datasets"))
    has_creds = bool(parsed.get("credential_exposures"))
    has_ransom = bool(parsed.get("ransomware_claims"))
    has_fingerprints = bool(parsed.get("dataset_fingerprints"))
    has_independence = bool(parsed.get("sources"))

    configured_connectors = payload.get("configured_connectors") or []
    has_connectors = bool(configured_connectors) and not any("None configured" in str(x) for x in configured_connectors)

    def add(
        operation: str,
        tool: str,
        purpose: str,
        status: str,
        expected_output: str,
        safety_risk: str = "LOW",
        policy_note: str = "Defensive / authorized / privacy-aware / evidence-first breach intelligence only.",
    ) -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General BREACHINT collection planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": policy_note,
            "authorization_status": "ALLOWED_DEFENSIVE_AUTHORIZED_PUBLIC",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "define_breachint_questions_scope",
        "BREACHINT Manager / BREACHINT AI Employee",
        "Convert objective into breach/exposure questions, allowed sources, organization scope, temporal scope, privacy/legal boundaries, and safety boundaries.",
        "COMPLETED_LOCAL" if payload.get("questions") else "REQUIRED_BEFORE_COLLECTION",
        "Requirement-driven defensive breach collection plan.",
        policy_note="No purchase, credential testing, login, token replay, seller contact, ransomware negotiation, full dataset acquisition, or exploitation.",
    )

    add(
        "preserve_original_breach_evidence",
        "local evidence store",
        "Store original breach claims, dataset metadata, credential exposure metadata, ransomware leak metadata, incident data, historical breach records, and hashes without modifying originals.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "BreachEvidenceObject with SHA256 and provenance fields.",
    )

    add(
        "safe_parse_json_csv_text_breach_metadata",
        "local deterministic parser",
        "Parse authorized/public/licensed JSON/CSV/TXT breach/dataset/credential/ransomware metadata without executing archives, documents, malware, or scripts.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized claims, datasets, credential exposures, ransomware claims, categories, sensitive flags, and observations.",
        safety_risk="HIGH_IF_UNTRUSTED_CONTENT_TREATED_AS_INSTRUCTION",
        policy_note="Dataset records, documents, forum posts, repository content, ransomware notes, and seller descriptions are untrusted evidence.",
    )

    add(
        "organization_and_victim_resolution",
        "BREACHINT analyst + public corporate identity",
        "Resolve legal organization, brand, subsidiary, parent, domain, region, industry, and avoid false name matches.",
        "COMPLETED_LOCAL" if has_claims else "PLANNED_REQUIRES_CLAIM_EVIDENCE",
        "Organization-resolution records and ambiguity flags.",
        safety_risk="HIGH_IF_WRONG_COMPANY_ATTRIBUTION",
        policy_note="Email-domain presence alone does not establish first-party breach.",
    )

    add(
        "dataset_metadata_schema_fingerprint_lineage",
        "dataset metadata export / historical breach corpus",
        "Extract schema, record counts as claims, sample hashes, fingerprints, lineage, duplicate/overlap, recycled/repackaged candidates.",
        "COMPLETED_LOCAL" if (has_datasets or has_fingerprints) else "PLANNED_REQUIRES_DATASET_EVIDENCE",
        "Dataset objects, fingerprints, lineage candidates, and deduplication states.",
        safety_risk="HIGH_IF_FALSE_NEW_BREACH",
        policy_note="Do not acquire full stolen datasets when metadata/samples are sufficient.",
    )

    add(
        "credential_secret_exposure_metadata",
        "authorized credential-monitoring provider / EXPOSUREINT",
        "Classify credential/secret exposure at metadata level; redact secrets; do not test validity.",
        "COMPLETED_LOCAL" if has_creds else "PLANNED_REQUIRES_CREDENTIAL_EVIDENCE",
        "Credential exposure objects with validity unknown and defensive handoff.",
        safety_risk="HIGH_PRIVACY_SENSITIVE",
        policy_note="Do not use, test, login, replay, redeem, or expose plaintext secrets.",
    )

    add(
        "first_party_third_party_supply_chain_analysis",
        "BREACHINT analyst + vendor/supplier context",
        "Distinguish first-party breach, third-party exposure, supply-chain breach, combo list, stealer log, public/scraped data, and unknown origin.",
        "PLANNED_ANALYTIC",
        "Origin candidates and confidence dimensions.",
        safety_risk="HIGH_IF_FALSE_FIRST_PARTY",
        policy_note="Do not create hundreds of first-party breaches from one supplier breach.",
    )

    add(
        "ransomware_extortion_context",
        "DARKINT / CTI / INCIDENTINT",
        "Track ransomware victim/data-publication/extortion claims without contact/negotiation/payment.",
        "COMPLETED_LOCAL" if has_ransom else "PLANNED_REQUIRES_RANSOMWARE_EVIDENCE",
        "Ransomware claim objects and independent corroboration gaps.",
        safety_risk="HIGH_IF_RANSOMWARE_CLAIM_TREATED_AS_FACT",
        policy_note="Do not negotiate, pay, contact actor, or operationalize coercion techniques.",
    )

    add(
        "source_reliability_bias_independence",
        "BREACHINT analyst + report provenance",
        "Assess official disclosure, regulator, CERT, incident responder, licensed provider, seller, ransomware site, media, and copied reports.",
        "COMPLETED_LOCAL" if has_independence else "PLANNED_ANALYTIC",
        "INDEPENDENT / PARTIALLY_DEPENDENT / DEPENDENT / UNKNOWN source states.",
        safety_risk="HIGH_IF_SOURCE_DEPENDENCY_ERROR",
        policy_note="Republishing/aggregation is not corroboration.",
    )

    add(
        "privacy_legal_impact_assessment",
        "Legal / Compliance / Privacy Officer / data steward",
        "Flag personal/financial/health/identity/auth-secret/minor/regulated data and prepare defensive impact assessment without final legal determination.",
        "PLANNED_ANALYTIC",
        "Privacy/legal flags, impact severity, and human-review requirements.",
        safety_risk="HIGH_PRIVACY_LEGAL",
        policy_note="BREACHINT recommends; authorized humans govern notification and legal action.",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_text = " ".join(
        [
            str(payload.get("objective", "")),
            " ".join(str(q) for q in payload.get("questions", [])),
            str(payload.get("target", "")),
            " ".join(str(s) for s in payload.get("organizations", [])),
            " ".join(str(s) for s in payload.get("brands", [])),
            " ".join(str(s) for s in payload.get("domains", [])),
            " ".join(str(s) for s in payload.get("email_domains", [])),
            " ".join(str(s) for s in payload.get("breach_claims", [])),
            " ".join(str(s) for s in payload.get("dataset_claims", [])),
            " ".join(str(s) for s in payload.get("credential_claims", [])),
            " ".join(str(s) for s in payload.get("ransomware_claims", [])),
            " ".join(str(s) for s in payload.get("exposure_sources", [])),
            str(payload.get("incident_context", "")),
        ]
    ).lower()

    blocked_reasons = [p for p in POLICY_BLOCK_PATTERNS if re.search(p, scanned_text, re.IGNORECASE)]

    human_review_required = False
    safety_notes: List[str] = []

    if payload.get("target_type") in SENSITIVE_TARGET_TYPES:
        human_review_required = True
        safety_notes.append(
            "Sensitive breach/dataset/credential/ransomware/incident/supply-chain/repository/cloud/document context detected. "
            "Analysis must remain defensive, authorized, privacy-aware, and evidence-first. "
            "No purchase, credential testing, login, token replay, seller contact, ransomware negotiation, full stolen-dataset acquisition, redistribution, unauthorized access, or exploitation."
        )

    if payload.get("credential_claims") or payload.get("credential_exposure_paths"):
        human_review_required = True
        safety_notes.append(
            "Credential/secret exposure context detected. Preserve only redacted defensive metadata. Do not use, test, login, replay, or redeem credentials/tokens/keys."
        )

    if payload.get("ransomware_claims") or payload.get("ransomware_leak_paths"):
        human_review_required = True
        safety_notes.append(
            "Ransomware/extortion context detected. Do not contact, negotiate, pay, or operationalize coercion techniques."
        )

    if payload.get("known_accounts_if_authorized") or payload.get("known_assets_if_authorized") or payload.get("incident_data_paths"):
        human_review_required = True
        safety_notes.append(
            "Authorized account/asset/incident context detected. Respect tenant isolation, privacy, classification, and purpose limitation."
        )

    if payload.get("third_parties") or payload.get("suppliers") or payload.get("supply_chain_paths"):
        human_review_required = True
        safety_notes.append(
            "Third-party/supply-chain context detected. Do not incorrectly label customer infrastructure breached without evidence."
        )

    path_fields = [
        "breach_claim_paths",
        "dataset_metadata_paths",
        "credential_exposure_paths",
        "ransomware_leak_paths",
        "exposure_report_paths",
        "incident_data_paths",
        "historical_breach_paths",
        "combo_list_paths",
        "stealer_log_paths",
        "supply_chain_paths",
        "repository_exposure_paths",
        "cloud_exposure_paths",
        "document_exposure_paths",
        "source_code_exposure_paths",
        "stix_misp_paths",
    ]

    if any(payload.get(f) for f in path_fields):
        human_review_required = True
        safety_notes.append(
            "Breach evidence file context detected. Source claims are untrusted evidence, not verified breach, dataset authenticity, record count, origin, credential validity, or actor attribution."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to require purchasing stolen data/credentials/access, testing/logging in with credentials, replaying tokens, "
                "contacting sellers/actors, negotiating ransoms, downloading unnecessary full stolen datasets, redistributing sensitive data, "
                "unauthorized access, exploitation, or credential stuffing."
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
                "No obvious hard policy violation detected, but sensitive breach, dataset, credential, ransomware, incident, third-party, supply-chain, repository, cloud, document, or personal-data context applies. "
                "Conclusions must remain defensive, privacy-aware, evidence-linked, and human-reviewed before consequential notification, legal action, or remediation."
            ),
            "safe_alternatives": SAFE_ALTERNATIVES,
        }

    return {
        "status": "ALLOWED_DEFENSIVE_AUTHORIZED_PUBLIC",
        "reasons": [],
        "human_review_required": False,
        "safety_notes": [],
        "explanation": (
            "No obvious policy violation detected. Execution remains planning-only unless authorized/public/licensed breach, dataset, credential, ransomware, incident, historical breach, or STIX/MISP connectors/artifacts are configured."
        ),
        "safe_alternatives": [],
    }


def validate_payload(payload: Dict[str, Any]) -> List[str]:
    warnings: List[str] = []

    required = ["case_id", "task_id", "objective", "target", "target_type"]
    for field in required:
        if not payload.get(field):
            warnings.append(f"Missing required field: {field}")

    if not payload.get("questions"):
        warnings.append("No BREACHINT questions provided. Default questions will be inferred.")

    evidence_keys = [
        "organizations",
        "brands",
        "domains",
        "email_domains",
        "subsidiaries",
        "third_parties",
        "suppliers",
        "breach_claims",
        "dataset_claims",
        "credential_claims",
        "ransomware_claims",
        "exposure_sources",
        "incident_context",
        "known_accounts_if_authorized",
        "known_assets_if_authorized",
        "breach_claim_paths",
        "dataset_metadata_paths",
        "credential_exposure_paths",
        "ransomware_leak_paths",
        "exposure_report_paths",
        "incident_data_paths",
        "historical_breach_paths",
        "combo_list_paths",
        "stealer_log_paths",
        "supply_chain_paths",
        "repository_exposure_paths",
        "cloud_exposure_paths",
        "document_exposure_paths",
        "source_code_exposure_paths",
        "stix_misp_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No breach/dataset/credential/ransomware/incident/historical/supply-chain/repository/cloud/document evidence provided. Output remains planning-only.")

    if not payload.get("time_range"):
        warnings.append("No time range provided. Breach freshness, dataset lineage, credential currency, and publication timeline are temporal.")

    if not payload.get("configured_connectors"):
        warnings.append("No breach-monitoring/credential-monitoring/STIX/MISP/incident connectors configured. External correlation remains planning-only.")

    if payload.get("target_type") in SENSITIVE_TARGET_TYPES:
        warnings.append(
            "Sensitive breach/exposure context triggers defensive/privacy/legal controls. "
            "No purchase, credential testing, login, token replay, seller contact, ransomware negotiation, full stolen-dataset acquisition, redistribution, unauthorized access, or exploitation is permitted."
        )

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "What breach/exposure is being claimed, by whom, and when?",
        "Which organization/entity is allegedly affected, and is organization identity correctly resolved?",
        "Does evidence support a real breach, or only a claim/sample/listing?",
        "Is the exposure likely first-party, third-party, supply-chain, combo list, stealer log, public/scraped, recycled, or unknown?",
        "What data categories are claimed versus actually observed/verified at metadata level?",
        "What record count is claimed, observed in sample, estimated unique, and verified if authorized?",
        "Are credentials/secrets exposed, and are they current, historical, reused, or validity unknown?",
        "Are samples authentic, fabricated, public, recycled, or inconclusive?",
        "Are multiple sources independent, or reposts/aggregators/mirrors of one claim?",
        "What incident telemetry/identity/cloud/DLP evidence is needed for corroboration?",
        "What privacy/legal flags apply, and what human review is required?",
        "What defensive actions should be prioritized without testing or using exposed secrets?",
        "What remains unknown, and what next authorized action provides the most defensive value?",
    ]


class TraceAtlasBREACHINTPanel(tk.Tk):
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
            foreground="#fb7185",
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

        ttk.Label(header, text="TraceAtlas BREACHINT AI Employee", style="Header.TLabel").pack(anchor="w")

        ttk.Label(
            header,
            text=(
                "Defensive / authorized / privacy-aware / evidence-first breach intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT breach/dataset/credential/ransomware metadata parsing only • "
                "No purchase / credential testing / login / token replay / seller contact / ransomware negotiation / full stolen-dataset acquisition / redistribution / unauthorized access / exploitation • "
                "Claim != verified breach • sample != full dataset • email domain != first-party breach • stealer log != website breach"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="BREACHINT Task Input")
        self.notebook.add(self.output_tab, text="Output / BREACHINT Plan / Evidence")

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

        ttk.Button(buttons1, text="Add Breach Claims", command=self.add_breach_claims).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Dataset Metadata", command=self.add_dataset_metadata).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Credential Exposure", command=self.add_credential_exposure).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Ransomware Leak", command=self.add_ransomware_leak).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Exposure Reports", command=self.add_exposure_reports).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Incident Data", command=self.add_incident_data).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Historical Breaches", command=self.add_historical_breaches).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Add Combo / Stealer Metadata", command=self.add_combo_stealer).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Add Supply Chain / Repo / Cloud / Docs", command=self.add_supply_repo_cloud_docs).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Add STIX / MISP", command=self.add_stix_misp).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Analyze Local BREACHINT Evidence", command=self.analyze_local_breachint).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate BREACHINT Plan", command=self.generate_plan).pack(side="left", padx=4)
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
            fg="#fecdd3",
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
        self.set_widget_value("case_id", "BREACHINT-CASE-001")
        self.set_widget_value("task_id", "BREACHINT-TASK-001")
        self.set_widget_value(
            "objective",
            "Analyze authorized or publicly documented breach/exposure intelligence using defensive, privacy-aware, evidence-first BREACHINT methods. "
            "Preserve originals, parse safe breach/dataset/credential/ransomware/incident metadata deterministically, resolve organizations cautiously, separate claim from fact, "
            "analyze dataset fingerprints/lineage/deduplication, distinguish first-party vs third-party/supply-chain/combo/stealer/public/recycled origin, classify data categories and sensitive flags, "
            "preserve record-count uncertainty, assess credential/secret exposure without testing, assess source reliability/independence, preserve contradictions and competing hypotheses, "
            "and produce defensive escalation recommendations without purchasing stolen data, testing credentials, logging in, replaying tokens, contacting sellers, negotiating ransoms, "
            "downloading unnecessary full stolen datasets, redistributing sensitive data, unauthorized access, or exploitation.",
        )
        self.set_widget_value("target", "Illustrative example.com / authorized breach context")
        self.set_widget_value("target_type", "breach_claim")
        self.set_widget_value(
            "questions",
            "\n".join(default_questions({"target": "Illustrative example.com / authorized breach context"})),
        )

        for field in [
            "organizations",
            "brands",
            "domains",
            "email_domains",
            "subsidiaries",
            "third_parties",
            "suppliers",
            "breach_claims",
            "dataset_claims",
            "credential_claims",
            "ransomware_claims",
            "exposure_sources",
            "incident_context",
            "known_accounts_if_authorized",
            "known_assets_if_authorized",
            "breach_claim_paths",
            "dataset_metadata_paths",
            "credential_exposure_paths",
            "ransomware_leak_paths",
            "exposure_report_paths",
            "incident_data_paths",
            "historical_breach_paths",
            "combo_list_paths",
            "stealer_log_paths",
            "supply_chain_paths",
            "repository_exposure_paths",
            "cloud_exposure_paths",
            "document_exposure_paths",
            "source_code_exposure_paths",
            "stix_misp_paths",
        ]:
            self.set_widget_value(field, "")

        self.set_widget_value(
            "time_range",
            json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2),
        )
        self.set_widget_value("jurisdiction", "")
        self.set_widget_value(
            "scope",
            json.dumps(
                {
                    "allowed_source_types": [
                        "official organization disclosures",
                        "regulatory notifications",
                        "government advisories",
                        "CERT reports",
                        "public incident reports",
                        "public breach notifications",
                        "ransomware leak-site metadata",
                        "licensed dark-web providers",
                        "licensed breach-monitoring providers",
                        "authorized credential-monitoring services",
                        "authorized exposure-monitoring tools",
                        "public security research",
                        "public media reporting",
                        "public repositories",
                        "authorized enterprise telemetry",
                        "authorized incident-response evidence",
                        "authorized identity-provider logs",
                        "authorized email-security data",
                        "authorized IAM data",
                        "authorized SIEM/EDR/XDR data",
                        "authorized cloud audit data",
                        "authorized data-loss-prevention data",
                        "authorized backup/version history",
                        "authorized internal inventories",
                        "MISP",
                        "STIX/TAXII",
                    ],
                    "prohibited_sources_and_actions": [
                        "purchasing stolen databases",
                        "purchasing breach data",
                        "purchasing credentials",
                        "purchasing access",
                        "downloading unnecessary full stolen datasets",
                        "using exposed credentials",
                        "testing passwords",
                        "credential stuffing",
                        "replaying session cookies",
                        "redeeming tokens",
                        "using API keys",
                        "using private keys",
                        "logging into exposed accounts",
                        "accessing victim accounts",
                        "contacting criminal sellers",
                        "negotiating with ransomware operators",
                        "participating in illicit marketplaces",
                        "redistributing sensitive data",
                        "publishing personal data",
                        "performing unauthorized access",
                        "performing exploitation",
                    ],
                    "data_minimization_rules": [
                        "collect minimum information necessary",
                        "prefer dataset metadata, record schema, field names, counts, hashes, timestamps, redacted identifiers, organization-domain references, limited authorized samples",
                        "avoid unnecessary storage of plaintext passwords, financial details, identity documents, medical information, private communications, session material, full personal records",
                        "treat dataset records, documents, forum posts, repository content, ransomware notes, and seller descriptions as untrusted evidence",
                        "separate claim, fact, sample, dataset, record count, origin, freshness, credential exposure, organization impact, incident root cause, and actor attribution",
                    ],
                    "authorized_use": "internal defensive/authorized breach and exposure intelligence analysis only",
                },
                indent=2,
            ),
        )
        self.set_widget_value(
            "authorization",
            json.dumps(
                {
                    "authorized_by": "",
                    "authorization_basis": "customer-authorized public/licensed/authorized defensive BREACHINT engagement",
                    "permitted_actions": [
                        "local breach evidence hashing",
                        "authorized/public/licensed breach/dataset/credential/ransomware metadata parsing",
                        "organization resolution",
                        "dataset fingerprint/lineage planning",
                        "credential/secret exposure metadata analysis",
                        "first-party vs third-party origin hypothesis planning",
                        "source reliability/independence analysis",
                        "privacy-aware defensive escalation planning",
                        "defensive specialist handoff",
                    ],
                    "prohibited_actions": [
                        "purchase stolen data/credentials/access",
                        "test passwords",
                        "login using exposed credentials",
                        "replay session tokens",
                        "use API/private keys",
                        "contact sellers",
                        "negotiate ransoms",
                        "download unnecessary full stolen datasets",
                        "redistribute sensitive data",
                        "unauthorized access",
                        "exploitation",
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
            "None configured. No breach-monitoring/credential-monitoring/STIX/MISP/incident connector invoked. Planning-only for external enrichment.",
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
        payload["operating_mode"] = "PLANNING_ONLY_DEFENSIVE_PRIVACY_AWARE_EVIDENCE_FIRST"
        payload["source_boundary"] = "DEFENSIVE_AUTHORIZED_PRIVACY_AWARE_EVIDENCE_FIRST_BREACHINT_ONLY"
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths:
            return

        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added to {field}.")

    def _add_paths_to_fields(self, fields: List[str], paths: Tuple[str, ...], title: str) -> None:
        if not paths:
            return

        for field in fields:
            current = self.get_widget_value(field)
            added = "\n".join(paths)
            new_value = current + ("\n" if current else "") + added
            self.set_widget_value(field, new_value)

        messagebox.showinfo(title, f"{len(paths)} path(s) added to: {', '.join(fields)}.")

    def add_breach_claims(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select breach claim export files",
            filetypes=[
                ("Breach claims", "*.json *.csv *.tsv *.txt *.log *.md"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("breach_claim_paths", paths, "Breach Claim Files Added")

    def add_dataset_metadata(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select dataset metadata export files",
            filetypes=[
                ("Dataset metadata", "*.json *.csv *.tsv *.txt *.log *.md"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("dataset_metadata_paths", paths, "Dataset Metadata Files Added")

    def add_credential_exposure(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select credential exposure metadata files",
            filetypes=[
                ("Credential exposure", "*.json *.csv *.tsv *.txt *.log"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("credential_exposure_paths", paths, "Credential Exposure Files Added")

    def add_ransomware_leak(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select ransomware leak-site metadata files",
            filetypes=[
                ("Ransomware leak metadata", "*.json *.csv *.tsv *.txt *.log *.md"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("ransomware_leak_paths", paths, "Ransomware Leak Files Added")

    def add_exposure_reports(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select exposure report files",
            filetypes=[
                ("Exposure reports", "*.json *.csv *.tsv *.txt *.log *.md"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("exposure_report_paths", paths, "Exposure Report Files Added")

    def add_incident_data(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select authorized incident data files",
            filetypes=[
                ("Incident data", "*.json *.csv *.tsv *.txt *.log"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("incident_data_paths", paths, "Incident Data Files Added")

    def add_historical_breaches(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select historical breach / known leak files",
            filetypes=[
                ("Historical breaches", "*.json *.csv *.tsv *.txt *.log *.md"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("historical_breach_paths", paths, "Historical Breach Files Added")

    def add_combo_stealer(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select combo list / stealer log metadata files",
            filetypes=[
                ("Combo/stealer metadata", "*.json *.csv *.tsv *.txt *.log"),
                ("All files", "*.*"),
            ],
        )
        self._add_paths_to_fields(["combo_list_paths", "stealer_log_paths"], paths, "Combo / Stealer Metadata Files Added")

    def add_supply_repo_cloud_docs(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select supply-chain / repository / cloud / document / source-code exposure files",
            filetypes=[
                ("Exposure metadata", "*.json *.csv *.tsv *.txt *.log *.md"),
                ("All files", "*.*"),
            ],
        )
        self._add_paths_to_fields(
            [
                "supply_chain_paths",
                "repository_exposure_paths",
                "cloud_exposure_paths",
                "document_exposure_paths",
                "source_code_exposure_paths",
            ],
            paths,
            "Supply Chain / Repository / Cloud / Document / Source Code Files Added",
        )

    def add_stix_misp(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select STIX / MISP export files",
            filetypes=[
                ("STIX / MISP", "*.json *.xml *.csv *.tsv *.txt *.stix *.taxii *.misp"),
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
                "has_organizations": bool(payload.get("organizations")),
                "has_domains": bool(payload.get("domains")),
                "has_email_domains": bool(payload.get("email_domains")),
                "has_breach_claims": bool(payload.get("breach_claims")),
                "has_dataset_claims": bool(payload.get("dataset_claims")),
                "has_credential_claims": bool(payload.get("credential_claims")),
                "has_ransomware_claims": bool(payload.get("ransomware_claims")),
                "has_incident_context": bool(payload.get("incident_context")),
                "has_breach_claim_paths": bool(payload.get("breach_claim_paths")),
                "has_dataset_metadata_paths": bool(payload.get("dataset_metadata_paths")),
                "has_credential_exposure_paths": bool(payload.get("credential_exposure_paths")),
                "has_ransomware_leak_paths": bool(payload.get("ransomware_leak_paths")),
                "has_exposure_report_paths": bool(payload.get("exposure_report_paths")),
                "has_incident_data_paths": bool(payload.get("incident_data_paths")),
                "has_historical_breach_paths": bool(payload.get("historical_breach_paths")),
                "has_combo_list_paths": bool(payload.get("combo_list_paths")),
                "has_stealer_log_paths": bool(payload.get("stealer_log_paths")),
                "has_supply_chain_paths": bool(payload.get("supply_chain_paths")),
                "has_repository_exposure_paths": bool(payload.get("repository_exposure_paths")),
                "has_cloud_exposure_paths": bool(payload.get("cloud_exposure_paths")),
                "has_document_exposure_paths": bool(payload.get("document_exposure_paths")),
                "has_source_code_exposure_paths": bool(payload.get("source_code_exposure_paths")),
                "has_stix_misp_paths": bool(payload.get("stix_misp_paths")),
            },
        }

        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning(
                "Policy Blocked",
                "This BREACHINT request is policy-blocked.\n\n"
                + "\n".join(policy["reasons"])
                + "\n\nUse only defensive/authorized alternatives.",
            )
        elif policy["status"] == "HUMAN_REVIEW_REQUIRED":
            messagebox.showwarning(
                "Human Review Required",
                "No hard policy block detected, but sensitive breach/dataset/credential/ransomware/incident/third-party context applies.",
            )
        else:
            messagebox.showinfo(
                "Policy Screen",
                "No obvious policy violation detected. Planning-only mode remains active.",
            )

    def analyze_local_breachint(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)

        if policy["status"] == "POLICY_BLOCKED":
            result = {
                "mode": "POLICY_BLOCKED",
                "panel_version": APP_VERSION,
                "policy_screen": policy,
                "evidence_inventory": [],
                "breach_summary": {},
                "claims_preview": [],
                "datasets_preview": [],
                "credential_exposures_preview": [],
                "ransomware_claims_preview": [],
                "observations": [],
                "candidate_facts": [],
            }
            self.last_result = result
            self._write_output(result)
            messagebox.showwarning("Policy Blocked", "Local BREACHINT evidence analysis blocked by policy screen.")
            return

        path_fields = [
            "breach_claim_paths",
            "dataset_metadata_paths",
            "credential_exposure_paths",
            "ransomware_leak_paths",
            "exposure_report_paths",
            "incident_data_paths",
            "historical_breach_paths",
            "combo_list_paths",
            "stealer_log_paths",
            "supply_chain_paths",
            "repository_exposure_paths",
            "cloud_exposure_paths",
            "document_exposure_paths",
            "source_code_exposure_paths",
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
            messagebox.showwarning("No BREACHINT Evidence", "Add local authorized/public/licensed breach evidence files first.")
            return

        self.output.delete("1.0", "end")
        self.output.insert("1.0", "Analyzing local authorized/public/licensed BREACHINT evidence. Hashing and parsing may take time...\n")
        self.notebook.select(self.output_tab)

        files: List[Dict[str, Any]] = []
        parsed_list: List[Dict[str, Any]] = []

        for p in all_paths[:30]:
            f, parsed = analyze_breach_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
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
        summary = aggregated.get("breach_summary", {})
        messagebox.showinfo(
            "Local BREACHINT Evidence Analysis Complete",
            f"Processed {len(files)} evidence file(s).\n"
            f"Succeeded/partial: {succeeded}\n"
            f"Claims: {summary.get('claim_count', 0)}\n"
            f"Datasets: {summary.get('dataset_count', 0)}\n"
            f"Credential exposures: {summary.get('credential_exposure_count', 0)}\n"
            f"Ransomware claims: {summary.get('ransomware_claim_count', 0)}\n"
            f"Record-count candidates: {summary.get('record_count_candidate_count', 0)}\n"
            f"Fingerprints: {summary.get('fingerprint_count', 0)}\n"
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
                "breachint_collection_plan": [],
                "next_best_action": {
                    "action": "Revise task to remove prohibited purchase, credential testing, login, token replay, seller contact, ransomware negotiation, full stolen-dataset acquisition, redistribution, unauthorized access, or exploitation behavior.",
                    "owner": "BREACHINT Manager",
                    "expected_output": "Policy-compliant defensive BREACHINT scope and question set.",
                },
            }
            self.last_result = result
            self._write_output(result)
            messagebox.showwarning(
                "Policy Blocked",
                "BREACHINT plan not generated because the request is policy-blocked.",
            )
            return

        questions = payload.get("questions") or default_questions(payload)

        if not self.parsed.get("claims") and not self.parsed.get("datasets"):
            self.parsed = finalize_parsed(empty_parsed(), payload, self.analyzed_files)

        files = self.analyzed_files
        parsed = self.parsed

        next_action = build_next_best_action(payload, policy, files, parsed)
        collection_plan = build_collection_plan(payload, questions, files, parsed)

        overall_status = "PLANNING_ONLY"
        if policy["status"] == "HUMAN_REVIEW_REQUIRED":
            overall_status = "HUMAN_REVIEW_REQUIRED"
        if files or parsed.get("claims") or parsed.get("datasets"):
            overall_status = "PLANNING_PLUS_LOCAL_DETERMINISTIC_EVIDENCE"

        result = {
            "mode": overall_status,
            "panel_version": APP_VERSION,
            "policy": (
                "This output does not purchase stolen data/breach data/credentials/access, download unnecessary full stolen datasets, use exposed credentials, test passwords, "
                "perform credential stuffing, replay session tokens, use API/private keys, login to exposed accounts, contact sellers/criminal actors, negotiate ransoms, "
                "redistribute sensitive data, publish personal data, perform unauthorized access, or exploit resources. "
                "Local deterministic analysis is limited to hashing, safe JSON/CSV/TXT breach/dataset/credential/ransomware/incident metadata parsing, organization resolution, "
                "dataset fingerprint/lineage planning, record-count caution, data-category classification, sensitive-data flagging, credential/secret exposure metadata, "
                "first-party vs third-party/supply-chain/combo/stealer/public/recycled origin hypotheses, source reliability/independence, contradiction detection, "
                "competing hypotheses, falsification, secret redaction, prompt-injection flagging, privacy-aware impact assessment, and defensive specialist handoff planning. "
                "Live breach-monitoring/credential-monitoring/STIX/MISP/incident enrichment, notification, legal action, and consequential remediation remain planning-only unless configured/authorized/human-reviewed."
            ),
            "policy_screen": policy,
            "warnings": warnings,
            "payload": payload,
            "intelligence_questions": questions,
            "evidence_inventory": files,
            "breach_summary": parsed.get("breach_summary", {}),
            "claims_preview": parsed.get("claims", [])[:300],
            "datasets_preview": parsed.get("datasets", [])[:300],
            "credential_exposures_preview": parsed.get("credential_exposures", [])[:300],
            "ransomware_claims_preview": parsed.get("ransomware_claims", [])[:300],
            "organization_mentions_preview": parsed.get("organization_mentions", [])[:300],
            "domain_mentions_preview": parsed.get("domain_mentions", [])[:300],
            "email_domain_mentions_preview": parsed.get("email_domain_mentions", [])[:300],
            "third_party_mentions_preview": parsed.get("third_party_mentions", [])[:300],
            "supplier_mentions_preview": parsed.get("supplier_mentions", [])[:300],
            "data_categories_preview": parsed.get("data_categories", [])[:300],
            "sensitive_flags_preview": parsed.get("sensitive_flags", [])[:300],
            "record_counts_preview": parsed.get("record_counts", [])[:300],
            "dataset_fingerprints_preview": parsed.get("dataset_fingerprints", [])[:300],
            "contradictions": parsed.get("contradictions", [])[:1000],
            "hypotheses": parsed.get("hypotheses", [])[:1000],
            "knowledge_gaps": parsed.get("knowledge_gaps", [])[:500],
            "specialist_handoffs": parsed.get("specialist_handoffs", [])[:500],
            "next_best_action": next_action,
            "breachint_collection_plan": collection_plan,
            **self._policy_sections(),
            **self._schemas(),
        }

        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

        if warnings:
            messagebox.showwarning(
                "Validation Warnings",
                "BREACHINT plan generated with warnings:\n\n" + "\n".join(warnings),
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
        summary = parsed.get("breach_summary", {})

        observations: List[Dict[str, Any]] = []

        for f in files:
            observations.append({
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": f"A local authorized/public/licensed BREACHINT evidence file was accessed and hashed: {f.get('filename')}.",
                "evidence_id": f.get("evidence_id"),
                "source_id": f.get("source_id"),
                "observed_at": now_utc(),
                "extraction_method": "local_deterministic_file_hash",
                "limitations": "File hash does not prove breach, dataset authenticity, record count, origin, credential validity, or actor attribution.",
            })

        observations.extend([
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": f"{len(files)} BREACHINT evidence file(s) were parsed locally.",
                "evidence_id": "AGGREGATE",
                "source_id": "LOCAL_PARSER",
                "observed_at": now_utc(),
                "extraction_method": "safe_json_csv_text_breach_parser",
                "limitations": "Parser output is normalized evidence, not verified external reality.",
            },
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": f"{summary.get('claim_count', 0)} claim record(s), {summary.get('dataset_count', 0)} dataset record(s), {summary.get('credential_exposure_count', 0)} credential exposure record(s), and {summary.get('ransomware_claim_count', 0)} ransomware claim record(s) were extracted.",
                "evidence_id": "AGGREGATE",
                "source_id": "LOCAL_CLAIM_PARSER",
                "observed_at": now_utc(),
                "extraction_method": "breach_dataset_credential_ransomware_metadata_extraction",
                "limitations": "Claims/datasets/credential exposures/ransomware claims are source-reported, not verified facts.",
            },
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": f"{summary.get('record_count_candidate_count', 0)} record-count candidate(s) were preserved as claimed counts.",
                "evidence_id": "AGGREGATE",
                "source_id": "LOCAL_RECORD_PARSER",
                "observed_at": now_utc(),
                "extraction_method": "record_count_extraction",
                "limitations": "Claimed record count is not verified count and may include duplicates.",
            },
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": f"{summary.get('fingerprint_count', 0)} dataset/sample fingerprint candidate(s) were preserved for lineage/deduplication planning.",
                "evidence_id": "AGGREGATE",
                "source_id": "LOCAL_FINGERPRINT_PARSER",
                "observed_at": now_utc(),
                "extraction_method": "hash_fingerprint_extraction",
                "limitations": "Fingerprints support duplicate/lineage analysis, not breach authenticity by themselves.",
            },
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": "No purchasing stolen data/credentials/access, testing passwords, logging in, replaying tokens, contacting sellers, negotiating ransoms, downloading unnecessary full stolen datasets, redistributing sensitive data, unauthorized access, or exploitation was performed.",
                "evidence_id": "LOCAL_PANEL_POLICY",
                "source_id": "LOCAL_POLICY_GUARD",
                "observed_at": now_utc(),
                "extraction_method": "defensive_privacy_aware_policy",
                "limitations": "Planning/local deterministic panel only.",
            },
        ])

        observations, _ = truncate_list(observations, 500)

        candidate_facts: List[Dict[str, Any]] = []

        for f in files:
            if f.get("sha256"):
                candidate_facts.append({
                    "candidate_fact": f"The preserved local BREACHINT evidence artifact {f.get('filename')} has SHA256 {f.get('sha256')}.",
                    "status": "SUPPORTED",
                    "evidence_ids": [f.get("evidence_id")],
                    "notes": "Supported by deterministic local hashing. Does not prove breach, dataset authenticity, record count, origin, credential validity, or actor attribution.",
                })

        candidate_facts.extend([
            {
                "candidate_fact": f"{summary.get('claim_count', 0)} breach/exposure claim candidate(s) were extracted.",
                "status": "SUPPORTED_AS_CANDIDATE_ONLY",
                "evidence_ids": ["AGGREGATE"],
                "not_supported": [
                    "verified breach",
                    "verified dataset authenticity",
                    "verified record count",
                    "verified origin",
                    "verified credential validity",
                    "verified actor attribution",
                ],
            },
            {
                "candidate_fact": f"{summary.get('dataset_count', 0)} dataset metadata candidate(s) were extracted.",
                "status": "SUPPORTED_AS_DATASET_CANDIDATE_ONLY",
                "evidence_ids": ["AGGREGATE"],
                "notes": "Dataset metadata may be claimed, sampled, recycled, third-party, combo list, stealer log, public/scraped, or unknown origin.",
            },
            {
                "candidate_fact": f"{summary.get('credential_exposure_count', 0)} credential/secret exposure metadata candidate(s) were extracted with validity unknown.",
                "status": "SUPPORTED_AS_CREDENTIAL_METADATA_ONLY",
                "evidence_ids": ["AGGREGATE"],
                "notes": "Do not test, login, replay, redeem, or use credentials/tokens/keys.",
            },
            {
                "candidate_fact": "No purchasing stolen data/credentials/access, testing passwords, logging in, replaying tokens, contacting sellers, negotiating ransoms, downloading unnecessary full stolen datasets, redistributing sensitive data, unauthorized access, or exploitation was performed.",
                "status": "SUPPORTED",
                "evidence_ids": ["LOCAL_PANEL_POLICY"],
                "notes": "Defensive/privacy-aware planning boundary.",
            },
        ])

        candidate_facts, _ = truncate_list(candidate_facts, 200)

        fact_gate = {
            "status": "LOCAL_DETERMINISTIC_ONLY" if files or parsed.get("claims") or parsed.get("datasets") else "NO_LOCAL_BREACHINT_EVIDENCE",
            "supported": [
                "file/source existence and SHA256 hash where local artifact accessible",
                "parsed claim candidates",
                "parsed dataset metadata candidates",
                "parsed credential/secret exposure metadata candidates",
                "parsed ransomware claim candidates",
                "parsed organization/domain/email-domain/third-party/supplier mentions",
                "parsed data-category metadata",
                "parsed sensitive-data flags",
                "parsed record-count candidates as claims",
                "parsed dataset/sample fingerprints",
                "source independence preliminary states",
                "contradiction candidates",
                "competing hypotheses",
                "secret redaction flags",
                "prompt-injection flags",
            ],
            "not_supported": [
                "verified breach",
                "verified dataset authenticity",
                "verified record count",
                "verified origin",
                "verified first-party breach",
                "verified third-party breach",
                "verified credential validity",
                "verified current exposure",
                "verified actor attribution",
                "verified root cause",
                               "verified initial access vector",
                "verified compromised host",
                "verified data exfiltration",
                "verified publication of full dataset",
                "verified credential current validity",
                "verified third-party origin",
                "verified supply-chain origin",
                "verified combo-list origin",
                "verified stealer-log origin",
                "verified public/scraped origin",
                "verified recycled/repackaged status",
                "final legal determination",
                "autonomous user/customer/employee notification",
                "autonomous law-enforcement referral",
                "purchase of stolen data/credentials/access",
                "credential testing",
                "login using exposed credentials",
                "session-token replay",
                "API/private-key use",
                "seller contact",
                "ransomware negotiation/payment",
                "unnecessary full stolen-dataset acquisition",
                "redistribution of sensitive data",
                "unauthorized access",
                "exploitation",
            ],
            "safety_status": (
                "No purchasing stolen data/credentials/access, testing passwords, logging in, replaying tokens, "
                "contacting sellers, negotiating ransoms, downloading unnecessary full stolen datasets, "
                "redistributing sensitive data, unauthorized access, or exploitation performed."
            ),
        }

        return {
            "mode": "LOCAL_DETERMINISTIC_BREACHINT_ANALYSIS",
            "panel_version": APP_VERSION,
            "policy_screen": policy,
            "purchase_stolen_data_performed": False,
            "purchase_credentials_performed": False,
            "purchase_access_performed": False,
            "credential_testing_performed": False,
            "login_using_exposed_credentials_performed": False,
            "session_token_replay_performed": False,
            "api_private_key_use_performed": False,
            "seller_contact_performed": False,
            "ransomware_negotiation_performed": False,
            "ransomware_payment_recommendation_performed": False,
            "full_stolen_dataset_acquisition_performed": False,
            "sensitive_data_redistribution_performed": False,
            "personal_data_publication_performed": False,
            "unauthorized_access_performed": False,
            "exploitation_performed": False,
            "evidence_inventory": files,
            "breach_summary": summary,
            "claims_preview": parsed.get("claims", [])[:300],
            "datasets_preview": parsed.get("datasets", [])[:300],
            "credential_exposures_preview": parsed.get("credential_exposures", [])[:300],
            "ransomware_claims_preview": parsed.get("ransomware_claims", [])[:300],
            "organization_mentions_preview": parsed.get("organization_mentions", [])[:300],
            "brand_mentions_preview": parsed.get("brand_mentions", [])[:300],
            "domain_mentions_preview": parsed.get("domain_mentions", [])[:300],
            "email_domain_mentions_preview": parsed.get("email_domain_mentions", [])[:300],
            "third_party_mentions_preview": parsed.get("third_party_mentions", [])[:300],
            "supplier_mentions_preview": parsed.get("supplier_mentions", [])[:300],
            "data_categories_preview": parsed.get("data_categories", [])[:300],
            "sensitive_flags_preview": parsed.get("sensitive_flags", [])[:300],
            "record_counts_preview": parsed.get("record_counts", [])[:300],
            "dataset_fingerprints_preview": parsed.get("dataset_fingerprints", [])[:300],
            "contradictions": parsed.get("contradictions", [])[:1000],
            "hypotheses": parsed.get("hypotheses", [])[:1000],
            "knowledge_gaps": parsed.get("knowledge_gaps", [])[:500],
            "specialist_handoffs": parsed.get("specialist_handoffs", [])[:500],
            "observations": observations,
            "candidate_facts": candidate_facts,
            "fact_gate": fact_gate,
            "recommended_next_actions": next_action,
            "breachint_collection_plan_preview": collection_plan[:20],
            "limitations": [
                "Only local deterministic checks were performed.",
                "No network access was performed.",
                "No purchasing stolen data/credentials/access, testing passwords, logging in, replaying tokens, contacting sellers, negotiating ransoms, downloading unnecessary full stolen datasets, redistributing sensitive data, unauthorized access, or exploitation was performed.",
                "Breach claim is not verified breach.",
                "Dark-web listing is not verified breach.",
                "Data sample is not full dataset.",
                "Claimed record count is not verified record count.",
                "Email-domain presence is not first-party breach.",
                "User credential exposure is not organization server breach.",
                "Stealer log is not website breach.",
                "Combo list is not a new breach.",
                "Publicly scraped data is not compromise.",
                "Exposure is not system compromise.",
                "Data publication is not known root cause.",
                "Ransomware claim is not verified data exfiltration.",
                "Third-party exposure is not customer infrastructure breach.",
                "Account credential exposure is not current validity.",
                "Multiple reposts are not independent corroboration.",
                "AI agreement is not breach corroboration.",
                "Exposed secrets were redacted heuristically and not used.",
                "Dataset records, documents, forum posts, repository content, ransomware notes, and seller descriptions were treated as untrusted evidence.",
            ],
        }

    def _write_output(self, result: Dict[str, Any]) -> None:
        self.output.delete("1.0", "end")
        self.output.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2, default=str))

    def _policy_sections(self) -> Dict[str, Any]:
        return {
            "role": {
                "employee": "BREACHINT AI Employee",
                "hierarchy": [
                    "Chief Intelligence Manager",
                    "Cyber / Exposure Intelligence Manager",
                    "BREACHINT Manager",
                    "BREACHINT AI Employee",
                    "Claim / Dataset / Exposure / Attribution / Impact / Verification Skills",
                ],
                "not": [
                    "stolen-data collector",
                    "credential validator",
                    "credential-stuffing system",
                    "password tester",
                    "data broker",
                    "illicit marketplace buyer",
                    "ransomware negotiator",
                    "private-data exploitation system",
                ],
            },
            "core_principle": [
                "CLAIM",
                "SOURCE",
                "PRESERVED EVIDENCE",
                "ORGANIZATION RESOLUTION",
                "DATASET / EXPOSURE METADATA",
                "TEMPORAL ANALYSIS",
                "DATA ORIGIN ANALYSIS",
                "SOURCE RELIABILITY",
                "SOURCE INDEPENDENCE",
                "EXTERNAL CORROBORATION",
                "FACT GATE",
                "IMPACT ASSESSMENT",
                "DEFENSIVE RESPONSE",
            ],
            "critical_separations": [
                "breach claim != verified breach",
                "dark-web listing != verified breach",
                "data sample != full dataset",
                "claimed record count != verified record count",
                "email-domain presence != first-party breach",
                "user credential exposure != organization server breach",
                "stealer log != website breach",
                "combo list != new breach",
                "publicly scraped data != compromise",
                "exposure != system compromise",
                "data publication != known root cause",
                "ransomware claim != verified data exfiltration",
                "third-party exposure != customer infrastructure breach",
                "account credential exposure != current validity",
                "multiple reposts != independent corroboration",
                "AI agreement != breach corroboration",
                "data authenticity != data freshness",
                "breach confidence != impact severity",
                "current relevance != historical exposure",
            ],
            "hard_restrictions": [
                "Do not purchase stolen databases.",
                "Do not purchase breach data.",
                "Do not purchase credentials.",
                "Do not purchase access.",
                "Do not download unnecessary full stolen datasets.",
                "Do not use exposed credentials.",
                "Do not test passwords.",
                "Do not perform credential stuffing.",
                "Do not replay session cookies.",
                "Do not redeem tokens.",
                "Do not use API keys.",
                "Do not use private keys.",
                "Do not login to exposed accounts.",
                "Do not access victim accounts.",
                "Do not contact criminal sellers.",
                "Do not negotiate with ransomware operators.",
                "Do not participate in illicit marketplaces.",
                "Do not redistribute sensitive data.",
                "Do not publish personal data.",
                "Do not perform unauthorized access.",
                "Do not perform exploitation.",
            ],
            "data_minimization_policy": [
                "Collect the minimum information necessary.",
                "Prefer dataset metadata, record schema, field names, counts, hashes, timestamps, redacted identifiers, organization-domain references, and limited authorized samples.",
                "Avoid unnecessary storage of plaintext passwords, financial details, identity documents, medical information, private communications, session material, and full personal records.",
            ],
            "credential_policy": [
                "Do not use exposed credentials.",
                "Do not test password validity.",
                "Do not login using exposed credentials.",
                "Do not replay session cookies or tokens.",
                "Represent defensively: credential_type, affected_domain, redacted_identifier, source, first_seen, last_seen, claim confidence.",
                "Handoff to EXPOSUREINT and authorized identity/security operations workflow.",
            ],
            "secret_policy": [
                "Do not display passwords, API keys, private keys, access tokens, session cookies, auth tokens, or recovery codes unnecessarily.",
                "Store redacted value, cryptographic hash where appropriate, secret_type, context, and source.",
                "No operational use.",
            ],
            "claim_states": [
                "UNVERIFIED_CLAIM",
                "PLAUSIBLE",
                "PARTIALLY_SUPPORTED",
                "SUPPORTED",
                "STRONGLY_SUPPORTED",
                "DISPUTED",
                "FALSE_CLAIM_CANDIDATE",
                "UNSUPPORTED",
                "INCONCLUSIVE",
            ],
            "origin_states": [
                "FIRST_PARTY_CANDIDATE",
                "THIRD_PARTY_CANDIDATE",
                "SUPPLY_CHAIN_CANDIDATE",
                "COMBO_LIST",
                "STEALER_LOG",
                "PUBLIC_DATA_CANDIDATE",
                "SCRAPED_DATA_CANDIDATE",
                "RECYCLED_CANDIDATE",
                "REPOSITORY_EXPOSURE_CANDIDATE",
                "CLOUD_EXPOSURE_CANDIDATE",
                "DOCUMENT_EXPOSURE_CANDIDATE",
                "SOURCE_CODE_EXPOSURE_CANDIDATE",
                "MISCONFIGURATION_CANDIDATE",
                "UNKNOWN",
            ],
            "freshness_states": [
                "CURRENT",
                "RECENT",
                "AGING",
                "HISTORICAL",
                "MIXED",
                "UNKNOWN",
            ],
            "impact_severity_states": [
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "INFORMATIONAL",
                "UNKNOWN",
            ],
            "breach_taxonomy": [
                "FIRST_PARTY_BREACH",
                "THIRD_PARTY_BREACH",
                "SUPPLY_CHAIN_BREACH",
                "CLOUD_EXPOSURE",
                "REPOSITORY_EXPOSURE",
                "CREDENTIAL_EXPOSURE",
                "STEALER_LOG_EXPOSURE",
                "RANSOMWARE_EXPOSURE",
                "PUBLIC_DATA_REPACKAGING",
                "COMBO_LIST",
                "UNKNOWN_ORIGIN",
            ],
            "dataset_deduplication_states": [
                "EXACT_DUPLICATE",
                "NEAR_DUPLICATE",
                "PARTIAL_OVERLAP",
                "DERIVED_DATASET",
                "DISTINCT",
                "UNKNOWN",
            ],
            "sample_authenticity_states": [
                "AUTHENTIC_CANDIDATE",
                "FABRICATED_CANDIDATE",
                "PUBLIC_DATA_CANDIDATE",
                "INCONCLUSIVE",
            ],
            "source_reliability_policy": [
                "Evaluate official disclosure, regulator, government/CERT, incident responder, victim organization, licensed provider, security researcher, ransomware site, forum seller, marketplace vendor, and anonymous source.",
                "Return HIGH, MEDIUM, LOW, or UNKNOWN with reasons.",
                "Source type and access to primary evidence matter.",
            ],
            "source_bias_policy": [
                "Consider extortion pressure, seller marketing, media incentives, vendor marketing, victim underreporting, legal caution, regulatory framing, and research selection bias.",
                "Bias does not automatically invalidate a claim.",
            ],
            "source_independence_policy": [
                "Determine whether reports rely on the same seller post, same ransomware claim, same sample, same provider feed, same victim statement, same screenshot, or same dataset.",
                "Use INDEPENDENT, PARTIALLY_DEPENDENT, DEPENDENT, UNKNOWN.",
                "Republishing, aggregation, mirrors, and crawlers are not corroboration.",
            ],
            "privacy_legal_policy": [
                "Flag personal data, financial data, health data, child data, authentication secrets, regulated data, cross-border data, and legal-hold candidates.",
                "Do not make final legal determinations.",
                "Handoff to authorized legal/compliance workflow.",
                "Do not autonomously notify employees, customers, victims, regulators, journalists, or law enforcement.",
            ],
            "human_review_policy": {
                "mandatory_when": [
                    "breach appears credible",
                    "customer/employee PII is involved",
                    "credentials/secrets are exposed",
                    "financial/health data appears",
                    "minors may be affected",
                    "ransomware/extortion is active",
                    "regulatory notification may be required",
                    "public disclosure is proposed",
                    "law-enforcement engagement may occur",
                    "high-impact defensive action is proposed",
                    "models materially disagree",
                ],
                "rule": "AI assists. Humans govern consequential actions.",
            },
            "falsification_questions": [
                "Could this be old data?",
                "Could it be from a supplier?",
                "Could it be public data?",
                "Could emails come from unrelated services?",
                "Could dataset be a combo list?",
                "Could seller have copied another breach?",
                "Could record count be inflated?",
                "Could sample be synthetic?",
                "Could sources share one upstream claim?",
            ],
            "dual_ai_review_policy": {
                "passes": [
                    "Primary Breach Analyst",
                    "Independent Breach Skeptic",
                ],
                "outcomes": [
                    "AGREE",
                    "PARTIAL_AGREEMENT",
                    "DISAGREE",
                    "INSUFFICIENT_EVIDENCE",
                ],
                "rule": "AI agreement is not independent evidence.",
            },
            "non_negotiable_rules": [
                "DO NOT BUY STOLEN DATA.",
                "DO NOT BUY CREDENTIALS.",
                "DO NOT BUY ACCESS.",
                "DO NOT CONTACT SELLERS AUTONOMOUSLY.",
                "DO NOT TEST PASSWORDS.",
                "DO NOT LOGIN USING EXPOSED CREDENTIALS.",
                "DO NOT REPLAY SESSION TOKENS.",
                "DO NOT USE LEAKED API KEYS.",
                "DO NOT USE PRIVATE KEYS.",
                "DO NOT ACQUIRE FULL STOLEN DATASETS WHEN METADATA/SAMPLES ARE SUFFICIENT.",
                "DO NOT REDISTRIBUTE BREACHED DATA.",
                "DO NOT EXPOSE PLAINTEXT SECRETS IN REPORTS.",
                "DO NOT EQUATE BREACH CLAIM WITH VERIFIED BREACH.",
                "DO NOT EQUATE DARK-WEB LISTING WITH VERIFIED BREACH.",
                "DO NOT EQUATE DATA SAMPLE WITH FULL DATASET.",
                "DO NOT EQUATE CLAIMED RECORD COUNT WITH VERIFIED COUNT.",
                "DO NOT EQUATE EMAIL DOMAIN PRESENCE WITH FIRST-PARTY BREACH.",
                "DO NOT EQUATE USER CREDENTIAL EXPOSURE WITH ORGANIZATION SERVER BREACH.",
                "DO NOT EQUATE STEALER LOG WITH WEBSITE BREACH.",
                "DO NOT EQUATE COMBO LIST WITH A NEW BREACH.",
                "DO NOT EQUATE PUBLICLY SCRAPED DATA WITH COMPROMISE.",
                "DO NOT EQUATE EXPOSURE WITH SYSTEM COMPROMISE.",
                "DO NOT EQUATE DATA PUBLICATION WITH KNOWN ROOT CAUSE.",
                "DO NOT EQUATE RANSOMWARE CLAIM WITH VERIFIED DATA EXFILTRATION.",
                "DO NOT EQUATE THIRD-PARTY EXPOSURE WITH CUSTOMER INFRASTRUCTURE BREACH.",
                "DO NOT EQUATE ACCOUNT CREDENTIAL EXPOSURE WITH CURRENT VALIDITY.",
                "DO NOT EQUATE MULTIPLE REPOSTS WITH INDEPENDENT CORROBORATION.",
                "DO NOT EQUATE AI AGREEMENT WITH BREACH CORROBORATION.",
                "DO NOT HIDE DATASET RECYCLING.",
                "DO NOT HIDE THIRD-PARTY ORIGIN.",
                "DO NOT HIDE RECORD-COUNT UNCERTAINTY.",
                "DO NOT HIDE PRIVACY RISK.",
                "DO NOT INVENT BREACHES.",
                "DO NOT INVENT AFFECTED USERS.",
                "DO NOT INVENT RECORD COUNTS.",
                "DO NOT INVENT DATASET CONTENT.",
                "DO NOT INVENT ROOT CAUSES.",
                "DO NOT INVENT ACTOR ATTRIBUTION.",
                "DO NOT LOSE HISTORICAL BREACH / DATASET LINEAGE.",
            ],
        }

    def _schemas(self) -> Dict[str, Any]:
        return {
            "breach_evidence_schema": {
                "evidence_id": "Unique BREACHINT evidence identifier",
                "case_id": "Case identifier",
                "source_id": "Source identifier",
                "source_type": "Breach claim / dataset metadata / credential exposure / ransomware leak / incident data / historical breach / supply chain / repository / cloud / document / STIX / MISP / etc.",
                "claim_id": "Associated claim identifier if available",
                "dataset_id": "Associated dataset identifier if available",
                "organization_id": "Associated organization identifier if available",
                "observed_at": "Observation timestamp",
                "published_at": "Publication timestamp",
                "retrieved_at": "Retrieval timestamp",
                "first_seen": "First source-seen timestamp",
                "last_seen": "Last source-seen timestamp",
                "content_hash": "SHA256 of original artifact/value",
                "snapshot_reference": "Snapshot/archive reference if available",
                "raw_artifact_reference": "Secure path/object storage reference",
                "parser_version": "Parser version",
                "normalizer_version": "Normalizer version",
                "authorization_context": "Authorization basis/reference",
            },
            "breach_claim_schema": {
                "claim_id": "Unique claim identifier",
                "claimant": "Seller/persona/source/organization making the claim",
                "source": "Source identifier",
                "claimed_victim": "Claimed victim organization/person/domain",
                "claimed_date": "Claimed breach/incident date",
                "claimed_record_count": "Claimed record count or dataset size",
                "claimed_data_size": "Claimed data size",
                "claimed_data_categories": "Claimed data categories",
                "claimed_access_type": "Claimed access type if relevant",
                "claimed_actor": "Claimed actor/group if relevant",
                "claimed_cause": "Claimed cause/root cause if relevant",
                "claimed_sample": "Claimed sample evidence",
                "first_seen": "First source-seen timestamp",
                "last_seen": "Last source-seen timestamp",
                "claim_status": "UNVERIFIED_CLAIM / PLAUSIBLE / PARTIALLY_SUPPORTED / SUPPORTED / STRONGLY_SUPPORTED / DISPUTED / FALSE_CLAIM_CANDIDATE / UNSUPPORTED / INCONCLUSIVE",
                "confidence": "LOW / MODERATE / HIGH",
                "limitations": [
                    "All claimed_* fields remain claims until verified.",
                    "Breach claim is not verified breach.",
                    "Claimed record count is not verified record count.",
                ],
            },
            "dataset_schema": {
                "dataset_id": "Unique dataset identifier",
                "dataset_name": "Dataset name/label",
                "source_ids": "Source identifiers",
                "claimed_origin": "Claimed origin",
                "suspected_origin": "Suspected origin candidate",
                "first_seen": "First source-seen timestamp",
                "last_seen": "Last source-seen timestamp",
                "record_count_claimed": "Claimed record count",
                "record_count_estimated": "Estimated unique record count if authorized",
                "record_count_verified_if_authorized": "Verified count only with authorized evidence",
                "schema": "Schema/field metadata",
                "data_categories": "High-level data categories",
                "sample_hashes": "Hashes of authorized samples",
                "dataset_fingerprints": "Dataset fingerprints",
                "lineage": "Lineage/derived-from/duplicate-of candidates",
                "freshness": "CURRENT / RECENT / AGING / HISTORICAL / MIXED / UNKNOWN",
                "status": "DATASET_CLAIM / DATASET_METADATA_PARSED / DUPLICATE_CANDIDATE / RECYCLED_CANDIDATE / UNKNOWN",
                "limitations": [
                    "Dataset metadata is claim/source-derived unless authorized verification exists.",
                    "Sample does not prove full dataset existence or exact record count.",
                ],
            },
            "credential_exposure_schema": {
                "credential_id": "Unique credential exposure identifier",
                "exposure_type": "EMAIL_ONLY / USERNAME_ONLY / PASSWORD_HASH / PLAINTEXT_PASSWORD_REPORTED / SESSION_TOKEN_REPORTED / API_SECRET_REPORTED / PRIVATE_KEY_REPORTED / OTHER_SECRET",
                "affected_domain": "Affected domain if known",
                "redacted_identifier": "Redacted username/email identifier",
                "credential_category": "High-level credential category",
                "validity": "VALIDITY_UNKNOWN / HISTORICAL / RECENT / CURRENT_RELEVANCE_UNKNOWN",
                "freshness": "CURRENT / RECENT / AGING / HISTORICAL / MIXED / UNKNOWN",
                "source_id": "Source identifier",
                "evidence_id": "Evidence identifier",
                "temporal": "Temporal metadata",
                "state": "CREDENTIAL_EXPOSURE_METADATA",
                "limitations": [
                    "Credential exposure metadata is not proof of current validity.",
                    "Do not test, login, replay, redeem, or use credentials/tokens/keys.",
                ],
            },
            "ransomware_claim_schema": {
                "ransom_id": "Unique ransomware claim identifier",
                "group_label": "Claimed ransomware group/leak-site label",
                "victim_claim": "Claimed victim",
                "claim_date": "Claim date if available",
                "data_publication_claim": "Claimed data publication status",
                "sample_claim": "Claimed sample status",
                "extortion_status": "Claimed extortion status",
                "source_id": "Source identifier",
                "evidence_id": "Evidence identifier",
                "temporal": "Temporal metadata",
                "state": "RANSOMWARE_SOURCE_CLAIM",
                "limitations": [
                    "Ransomware leak-site/actor claim is not verified breach or verified exfiltration.",
                    "Do not contact, negotiate, pay, or operationalize coercion techniques.",
                ],
            },
            "data_category_schema": {
                "category_id": "Unique data-category identifier",
                "category": "EMAIL / USERNAME / PASSWORD_OR_HASH / NAME / PHONE / ADDRESS / EMPLOYEE_DATA / CUSTOMER_DATA / FINANCIAL_DATA / GOVERNMENT_IDENTIFIER / HEALTH_DATA / AUTHENTICATION_SECRET / SOURCE_CODE / DOCUMENT / DATABASE_RECORD / OTHER",
                "source_id": "Source identifier",
                "evidence_id": "Evidence identifier",
                "context": "Where/how observed",
                "temporal": "Temporal metadata",
                "state": "SOURCE_OBSERVED_DATA_CATEGORY_METADATA",
                "limitations": [
                    "Data-category classification is high-level metadata, not reproduction of sensitive content.",
                ],
            },
            "sensitive_flag_schema": {
                "flag_id": "Unique sensitive-data flag identifier",
                "flag": "CREDENTIAL_DATA / FINANCIAL_DATA / HEALTH_DATA / IDENTITY_DOCUMENT / AUTHENTICATION_SECRET / PRIVATE_COMMUNICATION / MINOR_RELATED_DATA / HIGHLY_SENSITIVE_PERSONAL_DATA",
                "source_id": "Source identifier",
                "evidence_id": "Evidence identifier",
                "context": "Where/how flagged",
                "temporal": "Temporal metadata",
                "state": "SENSITIVE_DATA_FLAG",
                "limitations": [
                    "Sensitive-data flag triggers stricter privacy/legal handling and human review.",
                ],
            },
            "record_count_schema": {
                "record_count_id": "Unique record-count identifier",
                "subject": "Organization/dataset/claim subject",
                "raw": "Raw claimed count text",
                "value": "Parsed numeric value if available",
                "unit": "Parsed unit",
                "kind": "claimed_count / data_size_bytes / other",
                "state": "SOURCE_CLAIMED_COUNT",
                "source_id": "Source identifier",
                "evidence_id": "Evidence identifier",
                "temporal": "Temporal metadata",
                "limitations": [
                    "Claimed record count is not verified count.",
                    "Record count may include duplicates and does not equal unique individuals.",
                ],
            },
            "dataset_fingerprint_schema": {
                "fingerprint_id": "Unique fingerprint identifier",
                "kind": "SHA256 / DATASET_HASH / SAMPLE_HASH / SCHEMA_FINGERPRINT / CONTENT_FINGERPRINT / OTHER",
                "value": "Fingerprint value",
                "subject": "Dataset/claim/sample subject",
                "source_id": "Source identifier",
                "evidence_id": "Evidence identifier",
                "temporal": "Temporal metadata",
                "state": "DATASET_FINGERPRINT_METADATA",
                "limitations": [
                    "Fingerprint supports duplicate/lineage analysis, not breach authenticity by itself.",
                ],
            },
            "contradiction_schema": {
                "contradiction_id": "Unique contradiction identifier",
                "type": "RECORD_COUNT_CONFLICT / ORIGIN_CONFLICT / FRESHNESS_CONFLICT / VICTIM_IDENTITY_CONFLICT / SOURCE_CONFLICT / DATASET_OVERLAP_CONFLICT",
                "subject": "Conflicting claim/dataset/organization subject",
                "values": "Conflicting values",
                "possible_explanations": [
                    "different datasets",
                    "partial copies",
                    "marketing exaggeration",
                    "old vs new breach",
                    "third-party breach",
                    "supplier breach",
                    "reseller/recycled data",
                    "duplicate records",
                    "mixed dataset",
                    "source simplification",
                    "analyst/source error",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Do not average conflicting claims into fake precision.",
            },
            "hypothesis_schema": {
                "hypothesis_id": "Unique hypothesis identifier",
                "statement": "Testable BREACHINT hypothesis",
                "supporting_facts": "Evidence-linked supporting facts",
                "opposing_facts": "Evidence-linked opposing facts",
                "assumptions": "Assumptions required",
                "unknowns": "Unknowns",
                "falsification_conditions": "What would disprove it",
                "next_test": "Next defensive test/handoff",
                "status": "OPEN, SUPPORTED, DISPUTED, REJECTED, INCONCLUSIVE",
            },
            "knowledge_gap_schema": {
                "gap_id": "Unique gap identifier",
                "question": "BREACHINT question affected",
                "missing_evidence": "What evidence is missing",
                "likely_source": "Source type that could fill the gap",
                "specialist_owner": "Employee or specialist responsible",
                "priority": "HIGH, MEDIUM, LOW, HIGH_PRIVACY_SENSITIVE, HIGH_PRIVACY_LEGAL, HIGH_IF_RECYCLING_CONSEQUENTIAL, etc.",
                "expected_information_value": "Expected discriminating value if filled",
                "safety_boundary": "Any safety, privacy, legal, or authorization constraint",
            },
            "breachint_result_schema": [
                "case_id",
                "task_id",
                "objective",
                "questions",
                "source_ids",
                "evidence_ids",
                "breach_claims",
                "breach_events",
                "exposure_events",
                "organizations",
                "brands",
                "subsidiaries",
                "third_parties",
                "dataset_claims",
                "datasets",
                "dataset_samples",
                "dataset_fingerprints",
                "dataset_lineage",
                "dataset_overlap",
                "claimed_record_counts",
                "estimated_record_counts",
                "verified_record_counts",
                "data_categories",
                "sensitive_data_flags",
                "credential_exposure",
                "secret_exposure",
                "email_domain_context",
                "first_party_status",
                "third_party_status",
                "supply_chain_context",
                "combo_list_context",
                "stealer_log_context",
                "ransomware_context",
                "source_code_context",
                "document_context",
                "cloud_exposure_context",
                "repository_exposure_context",
                "sample_authenticity",
                "dataset_authenticity",
                "dataset_freshness",
                "breach_authenticity",
                "breach_origin_confidence",
                "impact_severity",
                "current_relevance",
                "timeline_updates",
                "observations",
                "candidate_facts",
                "supported_facts",
                "partial_facts",
                "disputed_facts",
                "source_reliability",
                "source_bias",
                "source_limitations",
                "source_pedigree",
                "source_independence",
                "contradictions",
                "hypotheses",
                "falsification_results",
                "privacy_flags",
                "legal_flags",
                "unknowns",
                "knowledge_gaps",
                "recommended_next_actions",
                "specialist_handoffs",
                "limitations",
                "status",
            ],
            "required_analyst_summary_format": [
                "BREACH / EXPOSURE STATUS",
                "AFFECTED ORGANIZATION",
                "CLAIM SOURCE",
                "CLAIM DATE",
                "BREACH AUTHENTICITY",
                "FIRST-PARTY / THIRD-PARTY",
                "DATASET AUTHENTICITY",
                "DATASET ORIGIN",
                "DATA FRESHNESS",
                "CLAIMED RECORD COUNT",
                "SUPPORTED RECORD COUNT",
                "DATA CATEGORIES",
                "CREDENTIAL / SECRET EXPOSURE",
                "RANSOMWARE CONTEXT",
                "SUPPLY-CHAIN CONTEXT",
                "SAMPLE AUTHENTICITY",
                "RECYCLED / COMBO-LIST POSSIBILITY",
                "INCIDENT CORRELATION",
                "SOURCE RELIABILITY",
                "SOURCE INDEPENDENCE",
                "CONTRADICTIONS",
                "IMPACT",
                "UNKNOWN",
                "NEXT ACTION",
            ],
            "breachint_report_sections": [
                "Objective",
                "Authorized Scope",
                "Collection / Privacy Boundaries",
                "Breach Claims",
                "Affected Organization Resolution",
                "First-Party / Third-Party Assessment",
                "Dataset Inventory",
                "Dataset Schema",
                "Dataset Fingerprints",
                "Dataset Lineage",
                "Duplicate / Overlap Analysis",
                "Record Counts",
                "Data Categories",
                "Sensitive Data",
                "Credential Exposure",
                "Secret Exposure",
                "Combo Lists",
                "Stealer Logs",
                "Ransomware Context",
                "Supply-Chain Exposure",
                "Source-Code Exposure",
                "Document Exposure",
                "Cloud / Repository Exposure",
                "Sample Authenticity",
                "Dataset Authenticity",
                "Data Freshness",
                "Breach Timeline",
                "Incident Correlation",
                "Current Relevance",
                "Impact Assessment",
                "Source Reliability",
                "Source Bias / Limitations",
                "Source Pedigree",
                "Source Independence",
                "Facts",
                "Observations",
                "Contradictions",
                "Competing Hypotheses",
                "Falsification",
                "Privacy / Legal Flags",
                "Unknowns",
                "Knowledge Gaps",
                "Defensive Next Actions",
                "Specialist Handoffs",
                "Limitations",
                "Evidence / Citations",
                "Replay Manifest",
            ],
            "replay_requirements_policy": {
                "preserve": [
                    "claim source",
                    "claim snapshot",
                    "claim timestamp",
                    "dataset metadata",
                    "sample hashes",
                    "dataset fingerprints",
                    "schema fingerprints",
                    "overlap calculations",
                    "organization-resolution decision",
                    "first-party/third-party decision",
                    "record-count calculation",
                    "source-pedigree graph",
                    "source-independence decision",
                    "fact-gate result",
                    "hypothesis comparison",
                    "privacy transformations",
                    "model versions",
                    "graph updates",
                ],
                "rule": (
                    "Replay must answer WHO CLAIMED THE BREACH? WHEN? WHAT DATA WAS ACTUALLY OBSERVED? "
                    "WHAT WAS ONLY CLAIMED? HOW WAS THE ORGANIZATION RESOLVED? WHY IS THIS FIRST-PARTY OR THIRD-PARTY? "
                    "IS THE DATA NEW OR RECYCLED? WHICH SOURCES ARE ACTUALLY INDEPENDENT?"
                ),
            },
            "collection_plan_schema": {
                "question": "BREACHINT question or general collection planning",
                "operation": "Planned defensive BREACHINT operation",
                "tool_or_provider": "Tool/source/connector",
                "purpose": "Why this operation matters",
                "status": "COMPLETED_LOCAL/PLANNED_REQUIRES_EVIDENCE/PLANNED_REQUIRES_CLAIM_EVIDENCE/PLANNED_REQUIRES_DATASET_EVIDENCE/PLANNED_REQUIRES_CREDENTIAL_EVIDENCE/PLANNED_REQUIRES_RANSOMWARE_EVIDENCE/PLANNED_ANALYTIC/BLOCKED_CONFIGURATION/PLANNED_REQUIRES_CONNECTOR/REQUIRED_BEFORE_COLLECTION",
                "expected_output": "Expected intelligence output",
                "priority": "Rank",
                "safety_risk": "LOW/MEDIUM/HIGH/HIGH_PRIVACY_SENSITIVE/HIGH_PRIVACY_LEGAL",
                "policy_note": "Defensive/authorized/privacy-aware/evidence-first boundary",
                "authorization_status": "ALLOWED_DEFENSIVE_AUTHORIZED_PUBLIC",
                "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
            },
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
            "Are you sure you want to clear all fields, analyzed BREACHINT evidence, and reset defaults?",
        )
        if not confirm:
            return

        self._set_defaults()
        self.output.delete("1.0", "end")
        self.last_result = {}
        self.analyzed_files = []
        self.parsed = empty_parsed()


if __name__ == "__main__":
    app = TraceAtlasBREACHINTPanel()
    app.mainloop()
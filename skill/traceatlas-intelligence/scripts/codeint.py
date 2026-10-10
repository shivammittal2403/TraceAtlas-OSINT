#!/usr/bin/env python3
"""
TRACEATLAS / CODEINT — Local defensive source-code intelligence pipeline.

IMPORTANT SAFETY / POLICY NOTES:
- This is a local demo implementation.
- It does NOT access live repositories, private repos, package registries, CI systems, or cloud deployments.
- It does NOT use/test/redeem discovered secrets, API keys, tokens, or private keys.
- It does NOT execute unknown code.
- It does NOT generate exploits, payloads, malware, persistence, EDR bypass, or attack chains.
- It supports authorized, defensive, static-first, evidence-first source-code intelligence only.
- Sample data is synthetic.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import unicodedata
from collections import defaultdict, deque
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


PIPELINE_VERSION = "0.1.0-codeint-static-safe-demo"


# =====================================================================
# ENUMS
# =====================================================================

class Status(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    LANGUAGE_UNSUPPORTED = "LANGUAGE_UNSUPPORTED"
    PARSER_FAILED = "PARSER_FAILED"
    DEPENDENCY_UNRESOLVED = "DEPENDENCY_UNRESOLVED"
    BUILD_UNRESOLVED = "BUILD_UNRESOLVED"
    RUNTIME_STATE_UNKNOWN = "RUNTIME_STATE_UNKNOWN"
    DEPLOYED_VERSION_UNKNOWN = "DEPLOYED_VERSION_UNKNOWN"
    SBOM_STALE = "SBOM_STALE"
    FINDING_UNVALIDATED = "FINDING_UNVALIDATED"
    BLOCKED_CONFIGURATION = "BLOCKED_CONFIGURATION"
    BLOCKED_POLICY = "BLOCKED_POLICY"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"


class SourceType(str, Enum):
    PUBLIC_REPO = "PUBLIC_REPO"
    AUTHORIZED_REPO = "AUTHORIZED_REPO"
    USER_SUPPLIED_SOURCE = "USER_SUPPLIED_SOURCE"
    PACKAGE_REGISTRY = "PACKAGE_REGISTRY"
    SBOM = "SBOM"
    LOCKFILE = "LOCKFILE"
    BUILD_FILE = "BUILD_FILE"
    CI_CD_CONFIG = "CI_CD_CONFIG"
    DOCUMENTATION = "DOCUMENTATION"
    SECURITY_REPORT = "SECURITY_REPORT"
    TEST_RESULT = "TEST_RESULT"
    PUBLIC_ADVISORY = "PUBLIC_ADVISORY"
    OTHER = "OTHER"


class Visibility(str, Enum):
    PUBLIC = "PUBLIC"
    PRIVATE_AUTHORIZED = "PRIVATE_AUTHORIZED"
    USER_SUPPLIED = "USER_SUPPLIED"
    UNKNOWN = "UNKNOWN"


class Language(str, Enum):
    PYTHON = "PYTHON"
    JAVASCRIPT = "JAVASCRIPT"
    TYPESCRIPT = "TYPESCRIPT"
    JAVA = "JAVA"
    GO = "GO"
    RUST = "RUST"
    YAML = "YAML"
    JSON = "JSON"
    TOML = "TOML"
    DOCKERFILE = "DOCKERFILE"
    MARKDOWN = "MARKDOWN"
    SQL = "SQL"
    SHELL = "SHELL"
    TEXT = "TEXT"
    UNKNOWN = "UNKNOWN"


class Framework(str, Enum):
    FASTAPI = "FASTAPI"
    DJANGO = "DJANGO"
    FLASK = "FLASK"
    EXPRESS = "EXPRESS"
    SPRING = "SPRING"
    PYTEST = "PYTEST"
    UNKNOWN = "UNKNOWN"


class BuildSystem(str, Enum):
    POETRY = "POETRY"
    PIP = "PIP"
    NPM = "NPM"
    MAVEN = "MAVEN"
    GRADLE = "GRADLE"
    CARGO = "CARGO"
    GO_MODULES = "GO_MODULES"
    DOCKER = "DOCKER"
    GITHUB_ACTIONS = "GITHUB_ACTIONS"
    UNKNOWN = "UNKNOWN"


class PackageManager(str, Enum):
    POETRY = "POETRY"
    PIP = "PIP"
    NPM = "NPM"
    MAVEN = "MAVEN"
    GRADLE = "GRADLE"
    CARGO = "CARGO"
    GO_MODULES = "GO_MODULES"
    UNKNOWN = "UNKNOWN"


class SymbolType(str, Enum):
    MODULE = "MODULE"
    CLASS = "CLASS"
    FUNCTION = "FUNCTION"
    METHOD = "METHOD"
    INTERFACE = "INTERFACE"
    TYPE = "TYPE"
    STRUCT = "STRUCT"
    ENUM = "ENUM"
    VARIABLE = "VARIABLE"
    CONSTANT = "CONSTANT"
    ROUTE = "ROUTE"
    ENDPOINT = "ENDPOINT"
    COMMAND = "COMMAND"
    HANDLER = "HANDLER"
    JOB = "JOB"
    WORKER = "WORKER"
    ENTRYPOINT = "ENTRYPOINT"
    CONFIG = "CONFIG"
    OTHER = "OTHER"


class ReachabilityState(str, Enum):
    REACHABLE_SUPPORTED = "REACHABLE_SUPPORTED"
    LIKELY_REACHABLE = "LIKELY_REACHABLE"
    POSSIBLY_REACHABLE = "POSSIBLY_REACHABLE"
    NOT_REACHABLE_SUPPORTED = "NOT_REACHABLE_SUPPORTED"
    UNKNOWN = "UNKNOWN"


class FindingType(str, Enum):
    OBSERVATION = "OBSERVATION"
    RISKY_PATTERN = "RISKY_PATTERN"
    VULNERABILITY_CANDIDATE = "VULNERABILITY_CANDIDATE"
    VULNERABILITY_SUPPORTED = "VULNERABILITY_SUPPORTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"
    ACCESS_CONTROL_GAP_CANDIDATE = "ACCESS_CONTROL_GAP_CANDIDATE"
    SECRET_CANDIDATE = "SECRET_CANDIDATE"
    SOURCE_TO_SINK_RISKY_PATTERN = "SOURCE_TO_SINK_RISKY_PATTERN"
    DOCUMENTATION_DRIFT = "DOCUMENTATION_DRIFT"
    DEPENDENCY_VERSION_CONFLICT = "DEPENDENCY_VERSION_CONFLICT"
    SBOM_STALE = "SBOM_STALE"
    TEST_COVERAGE_GAP = "TEST_COVERAGE_GAP"
    MALICIOUS_BEHAVIOR_CANDIDATE = "MALICIOUS_BEHAVIOR_CANDIDATE"
    PROVENANCE_CANDIDATE = "PROVENANCE_CANDIDATE"
    FORK_LINEAGE = "FORK_LINEAGE"
    CODE_SIMILARITY = "CODE_SIMILARITY"
    LICENSE_CONTEXT = "LICENSE_CONTEXT"
    CI_SUPPLY_CHAIN_CONTEXT = "CI_SUPPLY_CHAIN_CONTEXT"


class FindingState(str, Enum):
    OBSERVED = "OBSERVED"
    RISKY_PATTERN = "RISKY_PATTERN"
    VULNERABILITY_CANDIDATE = "VULNERABILITY_CANDIDATE"
    VULNERABILITY_SUPPORTED = "VULNERABILITY_SUPPORTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"


class SecretState(str, Enum):
    CANDIDATE = "CANDIDATE"
    REDACTED = "REDACTED"
    FINGERPRINTED = "FINGERPRINTED"
    NOT_TESTED = "NOT_TESTED"
    HISTORY_PRESENT = "HISTORY_PRESENT"
    REMOVED_IN_HEAD_NOT_REVOKED = "REMOVED_IN_HEAD_NOT_REVOKED"


class ProvenanceState(str, Enum):
    FIRST_PARTY = "FIRST_PARTY"
    VENDORED = "VENDORED"
    GENERATED = "GENERATED"
    FORK_DERIVED = "FORK_DERIVED"
    UPSTREAM_PACKAGE = "UPSTREAM_PACKAGE"
    LOCAL_MODIFICATION = "LOCAL_MODIFICATION"
    UNKNOWN = "UNKNOWN"


class ForkState(str, Enum):
    VERIFIED_FORK = "VERIFIED_FORK"
    SUPPORTED_FORK = "SUPPORTED_FORK"
    PROBABLE_FORK = "PROBABLE_FORK"
    POSSIBLE_FORK = "POSSIBLE_FORK"
    UNKNOWN = "UNKNOWN"


class SimilarityState(str, Enum):
    EXACT_DUPLICATE = "EXACT_DUPLICATE"
    NEAR_DUPLICATE = "NEAR_DUPLICATE"
    STRUCTURALLY_SIMILAR = "STRUCTURALLY_SIMILAR"
    COMMON_TEMPLATE = "COMMON_TEMPLATE"
    UNKNOWN = "UNKNOWN"


class HypothesisStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    UNRESOLVED = "UNRESOLVED"
    DISPUTED = "DISPUTED"
    REJECTED = "REJECTED"


class GapType(str, Enum):
    DEPLOYED_VERSION_UNKNOWN = "DEPLOYED_VERSION_UNKNOWN"
    REACHABILITY_UNKNOWN = "REACHABILITY_UNKNOWN"
    RUNTIME_CONFIG_UNKNOWN = "RUNTIME_CONFIG_UNKNOWN"
    SBOM_STALE = "SBOM_STALE"
    SECRET_VALIDITY_UNKNOWN = "SECRET_VALIDITY_UNKNOWN"
    TEST_COVERAGE_MISSING = "TEST_COVERAGE_MISSING"
    PROVENANCE_UNRESOLVED = "PROVENANCE_UNRESOLVED"
    LICENSE_REVIEW_REQUIRED = "LICENSE_REVIEW_REQUIRED"
    MALWARE_HANDOFF_REQUIRED = "MALWARE_HANDOFF_REQUIRED"
    VULN_APPLICABILITY_UNKNOWN = "VULN_APPLICABILITY_UNKNOWN"
    CI_SUPPLY_CHAIN_UNKNOWN = "CI_SUPPLY_CHAIN_UNKNOWN"
    SOURCE_INDEPENDENCE_GAP = "SOURCE_INDEPENDENCE_GAP"


class PrivacyFlag(str, Enum):
    CASE_SCOPED = "CASE_SCOPED"
    AUTHORIZED_SOURCE_ONLY = "AUTHORIZED_SOURCE_ONLY"
    NO_PRIVATE_REPO_ACCESS = "NO_PRIVATE_REPO_ACCESS"
    NO_SECRET_USE = "NO_SECRET_USE"
    NO_RAW_SECRET_EXPOSURE = "NO_RAW_SECRET_EXPOSURE"
    NO_UNKNOWN_CODE_EXECUTION = "NO_UNKNOWN_CODE_EXECUTION"
    LOCAL_ONLY_DEFAULT = "LOCAL_ONLY_DEFAULT"
    PROPRIETARY_CODE_CONFIDENTIAL = "PROPRIETARY_CODE_CONFIDENTIAL"


class PolicyFlag(str, Enum):
    NONE = "NONE"
    BLOCKED_REQUEST = "BLOCKED_REQUEST"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
    DEFENSIVE_ONLY = "DEFENSIVE_ONLY"
    STATIC_FIRST = "STATIC_FIRST"


class Approval(str, Enum):
    AUTONOMOUS_ANALYTIC = "AUTONOMOUS_ANALYTIC"
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
    SANDBOX_AUTHORIZATION_REQUIRED = "SANDBOX_AUTHORIZATION_REQUIRED"


# =====================================================================
# CONSTANTS
# =====================================================================

SOURCE_FACTOR: Dict[SourceType, float] = {
    SourceType.AUTHORIZED_REPO: 0.95,
    SourceType.PUBLIC_REPO: 0.90,
    SourceType.USER_SUPPLIED_SOURCE: 0.92,
    SourceType.PACKAGE_REGISTRY: 0.88,
    SourceType.SBOM: 0.75,
    SourceType.LOCKFILE: 0.90,
    SourceType.BUILD_FILE: 0.88,
    SourceType.CI_CD_CONFIG: 0.82,
    SourceType.DOCUMENTATION: 0.55,
    SourceType.SECURITY_REPORT: 0.75,
    SourceType.TEST_RESULT: 0.78,
    SourceType.PUBLIC_ADVISORY: 0.80,
    SourceType.OTHER: 0.65,
}

REACH_FACTOR: Dict[ReachabilityState, float] = {
    ReachabilityState.REACHABLE_SUPPORTED: 1.00,
    ReachabilityState.LIKELY_REACHABLE: 0.90,
    ReachabilityState.POSSIBLY_REACHABLE: 0.70,
    ReachabilityState.NOT_REACHABLE_SUPPORTED: 0.30,
    ReachabilityState.UNKNOWN: 0.50,
}

EXT_LANG: Dict[str, Language] = {
    ".py": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT,
    ".java": Language.JAVA,
    ".go": Language.GO,
    ".rs": Language.RUST,
    ".yaml": Language.YAML,
    ".yml": Language.YAML,
    ".json": Language.JSON,
    ".toml": Language.TOML,
    ".md": Language.MARKDOWN,
    ".sql": Language.SQL,
    ".sh": Language.SHELL,
    ".txt": Language.TEXT,
}

PROHIBITED_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    (
        "EXPLOIT_OR_MALWARE_GENERATION",
        re.compile(
            r"\b(write|generate|create|develop|improve)\s+"
            r"(an?\s+)?(exploit|payload|weaponized\s+code|malware|ransomware|keylogger|"
            r"rootkit|botnet|loader|dropper|credential\s+stealer|backdoor)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "SECRET_USE_OR_TESTING",
        re.compile(
            r"\b(use|test|validate|redeem|authenticate\s+with|login\s+with|query\s+with)\s+"
            r"(secret|api\s+key|token|private\s+key|credential|cloud\s+key|access\s+key)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "UNAUTHORIZED_REPO_ACCESS",
        re.compile(
            r"\b(access|scrape|bypass|steal|stolen)\s+"
            r"(private\s+repository|git\s+credential|access\s+token|repository\s+authentication|"
            r"branch\s+protection)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "UNAUTHORIZED_CODE_EXECUTION",
        re.compile(
            r"\b(execute|run|deploy|launch)\s+(unknown|malicious|untrusted|unauthorized)\s+"
            r"(code|payload|container|binary|script)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "EDR_AV_BYPASS",
        re.compile(
            r"\b(bypass|evade|disable|optimize\s+bypass)\s+"
            r"(edr|av|antivirus|security\s+control|logging|audit\s+trail)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "PERSISTENCE_OR_STEALTH",
        re.compile(
            r"\b(install|create|design|add)\s+"
            r"(persistence|stealth\s+mechanism|hidden\s+service|malicious\s+startup)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "TARGET_SPECIFIC_ATTACK",
        re.compile(
            r"\b(target[- ]specific\s+exploit|attack\s+chain|weaponize|compromise\s+production|"
            r"breach\s+live\s+system)\b",
            re.IGNORECASE,
        ),
    ),
]


# =====================================================================
# UTILITIES
# =====================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str, seed: str) -> str:
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:10]
    return f"{prefix}{h}" if prefix else h


def stable_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_short(text: str) -> str:
    return stable_hash(text)[:16]


def jsonable(obj: Any) -> Any:
    if isinstance(obj, Enum):
        return obj.value
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: jsonable(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, (list, tuple, set)):
        return [jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): jsonable(v) for k, v in obj.items()}
    return obj


def normalize_text(value: str) -> str:
    s = unicodedata.normalize("NFKC", value or "")
    s = s.lower().strip()
    s = re.sub(r"[^\w\s\-'.:/@]", " ", s)
    s = re.sub(r"\s+", " ", s)
    return s


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def dt_or_min(value: Optional[str]) -> datetime:
    dt = parse_dt(value)
    return dt if dt else datetime.min.replace(tzinfo=timezone.utc)


def infer_language(path: str, declared: Optional[Language] = None) -> Language:
    if declared and declared != Language.UNKNOWN:
        return declared
    lower = path.lower()
    if lower.endswith("dockerfile") or "/dockerfile" in lower:
        return Language.DOCKERFILE
    for ext, lang in EXT_LANG.items():
        if lower.endswith(ext):
            return lang
    return Language.UNKNOWN


def fingerprint_secret(value: str) -> str:
    # Never store raw secret. Only deterministic fingerprint of provided shape/value.
    return sha256_short("codeint-secret:" + value)


def redact_preview(value: str) -> str:
    if not value:
        return "****"
    if len(value) <= 4:
        return "****"
    return value[:2] + "****" + value[-2:]


def policy_guard(text: str) -> List[Dict[str, str]]:
    violations: List[Dict[str, str]] = []
    for rule, rx in PROHIBITED_PATTERNS:
        m = rx.search(text or "")
        if m:
            violations.append({"rule": rule, "matched": m.group(0)})
    return violations


# =====================================================================
# DATACLASSES
# =====================================================================

@dataclass
class Source:
    id: str
    title: str
    url: str
    source_type: SourceType
    independence_group: str = "UNKNOWN"
    reliability: float = 0.5
    derived_from: Optional[str] = None
    published_at: Optional[str] = None
    retrieved_at: Optional[str] = None
    notes: str = ""


@dataclass
class Evidence:
    id: str
    source_id: str
    repository_id: str
    commit_id: str
    file_path: Optional[str] = None
    symbol: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    artifact_hash: str = ""
    language: Language = Language.UNKNOWN
    parser_version: str = "synthetic-code-parser-0.1"
    analysis_version: str = PIPELINE_VERSION
    observed_at: Optional[str] = None
    excerpt: str = ""
    parsed_fields: Dict[str, Any] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Repository:
    id: str
    name: str
    remote_reference: str
    visibility: Visibility = Visibility.UNKNOWN
    default_branch: str = "main"
    current_commit: str = ""
    languages: List[Language] = field(default_factory=list)
    frameworks: List[Framework] = field(default_factory=list)
    build_systems: List[BuildSystem] = field(default_factory=list)
    package_managers: List[PackageManager] = field(default_factory=list)
    components: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    entrypoints: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    licenses: List[str] = field(default_factory=list)
    security_controls: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    confidence: float = 0.0
    limitations: List[str] = field(default_factory=list)


@dataclass
class Commit:
    id: str
    repository_id: str
    hash: str
    parents: List[str] = field(default_factory=list)
    author_metadata: Dict[str, str] = field(default_factory=dict)
    committer_metadata: Dict[str, str] = field(default_factory=dict)
    timestamp: Optional[str] = None
    message: str = ""
    changed_files: List[str] = field(default_factory=list)
    signature_status: str = "UNSIGNED"
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Branch:
    id: str
    repository_id: str
    name: str
    is_default: bool = False
    head_commit_id: Optional[str] = None
    protected: Optional[bool] = None
    source_ids: List[str] = field(default_factory=list)


@dataclass
class Tag:
    id: str
    repository_id: str
    name: str
    commit_id: Optional[str] = None
    annotated: bool = False
    signature_status: str = "UNSIGNED"
    date: Optional[str] = None
    source_ids: List[str] = field(default_factory=list)


@dataclass
class Release:
    id: str
    repository_id: str
    version: str
    tag_id: Optional[str] = None
    artifact_hashes: List[str] = field(default_factory=list)
    publication_date: Optional[str] = None
    release_notes: str = ""
    source_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class SourceFile:
    id: str
    repository_id: str
    commit_id: str
    path: str
    language: Language = Language.UNKNOWN
    size: Optional[int] = None
    hash: str = ""
    generated_status: str = "NOT_GENERATED"
    vendor_status: str = "FIRST_PARTY"
    test_status: str = "NOT_TEST"
    configuration_status: str = "NOT_CONFIG"
    security_relevance: str = "UNKNOWN"
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Symbol:
    id: str
    repository_id: str
    commit_id: str
    file_id: str
    name: str
    symbol_type: SymbolType = SymbolType.OTHER
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    decorators: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)
    entrypoint: bool = False
    route: Optional[str] = None
    method: Optional[str] = None
    handler: Optional[str] = None
    reachability_state: ReachabilityState = ReachabilityState.UNKNOWN
    confidence: float = 0.0
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Component:
    id: str
    repository_id: str
    name: str
    component_type: str
    files: List[str] = field(default_factory=list)
    symbols: List[str] = field(default_factory=list)
    description: str = ""
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    limitations: List[str] = field(default_factory=list)


@dataclass
class Service:
    id: str
    repository_id: str
    name: str
    deployment_unit: Optional[str] = None
    entrypoint_symbol_ids: List[str] = field(default_factory=list)
    route_symbols: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    limitations: List[str] = field(default_factory=list)


@dataclass
class Dependency:
    id: str
    consumer: str
    provider: str
    package: str
    ecosystem: str
    declared_version: Optional[str] = None
    resolved_version: Optional[str] = None
    scope: str = "RUNTIME"
    directness: str = "DIRECT"
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    hash: Optional[str] = None
    license: Optional[str] = None
    limitations: List[str] = field(default_factory=list)


@dataclass
class SBOMComponent:
    id: str
    repository_id: str
    commit_id: str
    purl: Optional[str] = None
    name: str = ""
    version: Optional[str] = None
    license: Optional[str] = None
    hashes: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class LicenseInfo:
    id: str
    repository_id: str
    declared_license: Optional[str] = None
    file_level_notices: List[str] = field(default_factory=list)
    dependency_licenses: Dict[str, str] = field(default_factory=dict)
    conflict_candidates: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    legal_review_required: bool = True
    limitations: List[str] = field(default_factory=list)


@dataclass
class SecretCandidate:
    id: str
    repository_id: str
    commit_id: str
    file_path: str
    line: Optional[int]
    secret_type: str
    redacted_preview: str
    fingerprint: str
    state: SecretState = SecretState.CANDIDATE
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    removed_in_head: bool = False
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class ConfigItem:
    id: str
    repository_id: str
    commit_id: str
    key: str
    value_type: str
    redacted_value: str
    fingerprint: str
    environment: str = "UNKNOWN"
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class SecurityFinding:
    id: str
    repository_id: str
    commit_id: str
    finding_type: FindingType
    state: FindingState
    title: str
    description: str
    file_path: Optional[str] = None
    symbol: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    severity: str = "MEDIUM"
    confidence: float = 0.0
    reachability: ReachabilityState = ReachabilityState.UNKNOWN
    deployment_context: str = "UNKNOWN"
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    introduced_in: Optional[str] = None
    fixed_in: Optional[str] = None
    limitations: List[str] = field(default_factory=list)
    specialist_handoff: Optional[str] = None
    remediation: List[str] = field(default_factory=list)


@dataclass
class Provenance:
    id: str
    repository_id: str
    commit_id: str
    subject: str
    origin: str
    state: ProvenanceState
    upstream_repository_id: Optional[str] = None
    upstream_commit_id: Optional[str] = None
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class CodeSimilarity:
    id: str
    left_repository_id: str
    right_repository_id: str
    left_commit_id: str
    right_commit_id: str
    scope: str
    state: SimilarityState
    similarity_score: float
    method: str
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Test:
    id: str
    repository_id: str
    commit_id: str
    name: str
    target_symbols: List[str] = field(default_factory=list)
    passed: Optional[bool] = None
    coverage: Optional[str] = None
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Coverage:
    id: str
    repository_id: str
    commit_id: str
    line_coverage: Optional[float] = None
    branch_coverage: Optional[float] = None
    function_coverage: Optional[float] = None
    scope: str = "UNKNOWN"
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Hypothesis:
    id: str
    statement: str
    kind: str
    supporting_finding_ids: List[str] = field(default_factory=list)
    supporting_evidence_ids: List[str] = field(default_factory=list)
    contradicting_evidence_ids: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    predictions: List[str] = field(default_factory=list)
    falsification_conditions: List[str] = field(default_factory=list)
    status: HypothesisStatus = HypothesisStatus.UNRESOLVED
    confidence: float = 0.0
    limitations: List[str] = field(default_factory=list)


@dataclass
class Contradiction:
    id: str
    contradiction_type: str
    description: str
    repository_id: Optional[str] = None
    finding_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    status: str = "OPEN"
    recommended_resolution: str = ""


@dataclass
class KnowledgeGap:
    id: str
    gap_type: GapType
    description: str
    about_repository_ids: List[str] = field(default_factory=list)
    about_finding_ids: List[str] = field(default_factory=list)
    importance: str = "MEDIUM"
    recommended_source: str = ""
    specialist: Optional[str] = None
    expected_information_value: float = 0.0


@dataclass
class NextAction:
    id: str
    description: str
    priority: int = 1
    privacy_impact: str = "LOW_IF_AUTHORIZED"
    expected_gain: float = 0.0
    specialist: Optional[str] = None
    requires_human_approval: bool = False


@dataclass
class Recommendation:
    id: str
    category: str
    action: str
    target: str
    rationale: str
    evidence_ids: List[str] = field(default_factory=list)
    finding_ids: List[str] = field(default_factory=list)
    approval: Approval = Approval.HUMAN_APPROVAL_REQUIRED
    business_impact: str = "REQUIRES_ENGINEERING_REVIEW"
    reversibility: str = "REQUIRES_VALIDATION"
    limitations: List[str] = field(default_factory=list)


@dataclass
class Case:
    case_id: str
    task_id: str
    objective: str
    questions: List[str] = field(default_factory=list)
    scope: List[str] = field(default_factory=lambda: ["authorized_source_only", "static_first", "case_scoped"])
    authorization: str = "demo_authorized_code_intelligence"
    repositories: List[str] = field(default_factory=list)
    commits: List[str] = field(default_factory=list)
    time_range: Optional[str] = None
    sample: bool = False
    budget: Optional[str] = None
    deadline: Optional[str] = None


# =====================================================================
# CODEINT ENGINE
# =====================================================================

class CodeInt:
    def __init__(self, case: Case) -> None:
        self.case = case
        self.sources: Dict[str, Source] = {}
        self.evidence: Dict[str, Evidence] = {}
        self.repositories: Dict[str, Repository] = {}
        self.commits: Dict[str, Commit] = {}
        self.branches: Dict[str, Branch] = {}
        self.tags: Dict[str, Tag] = {}
        self.releases: Dict[str, Release] = {}
        self.files: Dict[str, SourceFile] = {}
        self.symbols: Dict[str, Symbol] = {}
        self.components: Dict[str, Component] = {}
        self.services: Dict[str, Service] = {}
        self.dependencies: Dict[str, Dependency] = {}
        self.sbom_components: Dict[str, SBOMComponent] = {}
        self.licenses: Dict[str, LicenseInfo] = {}
        self.secret_candidates: Dict[str, SecretCandidate] = {}
        self.config_items: Dict[str, ConfigItem] = {}
        self.findings: Dict[str, SecurityFinding] = {}
        self.provenance: Dict[str, Provenance] = {}
        self.similarities: Dict[str, CodeSimilarity] = {}
        self.tests: Dict[str, Test] = {}
        self.coverages: Dict[str, Coverage] = {}
        self.hypotheses: List[Hypothesis] = []
        self.contradictions: List[Contradiction] = []
        self.gaps: List[KnowledgeGap] = []
        self.actions: List[NextAction] = []
        self.recommendations: List[Recommendation] = []
        self.handoffs: List[Dict[str, str]] = []
        self.documentation_claims: List[Dict[str, Any]] = []
        self.validation_errors: List[str] = []

        self.symbol_calls: Dict[str, Set[str]] = defaultdict(set)
        self.route_handler_map: Dict[str, str] = {}
        self.entrypoint_ids: Set[str] = set()
        self.reachable_symbols: Set[str] = set()
        self.deployment_context_known: bool = False

    # -----------------------------------------------------------------
    # Adders
    # -----------------------------------------------------------------

    def add_source(self, source: Source) -> Source:
        self.sources[source.id] = source
        return source

    def add_evidence(self, evidence: Evidence) -> Evidence:
        if not evidence.artifact_hash:
            seed = "|".join([
                evidence.repository_id,
                evidence.commit_id,
                evidence.file_path or "",
                evidence.symbol or "",
                evidence.excerpt,
            ])
            evidence.artifact_hash = stable_hash(seed)
        self.evidence[evidence.id] = evidence
        return evidence

    def add_repository(self, repo: Repository) -> Repository:
        self.repositories[repo.id] = repo
        return repo

    def add_commit(self, commit: Commit) -> Commit:
        self.commits[commit.id] = commit
        return commit

    def add_branch(self, branch: Branch) -> Branch:
        self.branches[branch.id] = branch
        return branch

    def add_tag(self, tag: Tag) -> Tag:
        self.tags[tag.id] = tag
        return tag

    def add_release(self, release: Release) -> Release:
        self.releases[release.id] = release
        return release

    def add_file(self, file: SourceFile) -> SourceFile:
        if not file.hash:
            file.hash = sha256_short(f"{file.repository_id}:{file.commit_id}:{file.path}")
        file.language = infer_language(file.path, file.language)
        self.files[file.id] = file
        return file

    def add_symbol(self, symbol: Symbol) -> Symbol:
        self.symbols[symbol.id] = symbol
        if symbol.entrypoint:
            self.entrypoint_ids.add(symbol.id)
        if symbol.route and symbol.handler:
            self.route_handler_map[symbol.id] = symbol.handler
        for callee in symbol.calls:
            self.symbol_calls[symbol.id].add(callee)
        return symbol

    def add_component(self, component: Component) -> Component:
        self.components[component.id] = component
        return component

    def add_service(self, service: Service) -> Service:
        self.services[service.id] = service
        return service

    def add_dependency(self, dep: Dependency) -> Dependency:
        self.dependencies[dep.id] = dep
        return dep

    def add_sbom_component(self, comp: SBOMComponent) -> SBOMComponent:
        self.sbom_components[comp.id] = comp
        return comp

    def add_license(self, lic: LicenseInfo) -> LicenseInfo:
        self.licenses[lic.id] = lic
        return lic

    def add_secret_candidate(self, secret: SecretCandidate) -> SecretCandidate:
        self.secret_candidates[secret.id] = secret
        return secret

    def add_config_item(self, item: ConfigItem) -> ConfigItem:
        self.config_items[item.id] = item
        return item

    def add_finding(self, finding: SecurityFinding) -> SecurityFinding:
        self.findings[finding.id] = finding
        return finding

    def add_provenance(self, prov: Provenance) -> Provenance:
        self.provenance[prov.id] = prov
        return prov

    def add_similarity(self, sim: CodeSimilarity) -> CodeSimilarity:
        self.similarities[sim.id] = sim
        return sim

    def add_test(self, test: Test) -> Test:
        self.tests[test.id] = test
        return test

    def add_coverage(self, cov: Coverage) -> Coverage:
        self.coverages[cov.id] = cov
        return cov

    def add_documentation_claim(self, claim: Dict[str, Any]) -> None:
        self.documentation_claims.append(claim)

    # -----------------------------------------------------------------
    # Source lineage / independence
    # -----------------------------------------------------------------

    def get_source_family(self, source_id: str) -> Optional[str]:
        src = self.sources.get(source_id)
        if not src:
            return None
        seen: Set[str] = set()
        cur = src
        while (
            cur
            and cur.derived_from
            and cur.derived_from in self.sources
            and cur.id not in seen
        ):
            seen.add(cur.id)
            cur = self.sources[cur.derived_from]
        return cur.id if cur else source_id

    def source_families(self, source_ids: List[str]) -> Set[str]:
        families: Set[str] = set()
        for sid in source_ids:
            fam = self.get_source_family(sid)
            families.add(fam or sid)
        return families

    def independence_state(self, source_ids: List[str]) -> str:
        if not source_ids:
            return "UNKNOWN"
        families = self.source_families(source_ids)
        if len(source_ids) == 1:
            return "SINGLE_SOURCE"
        if len(families) == 1:
            return "DEPENDENT"
        if len(families) == len(source_ids):
            return "INDEPENDENT"
        return "PARTIALLY_DEPENDENT"

    # -----------------------------------------------------------------
    # Detection / resolution
    # -----------------------------------------------------------------

    def detect_languages_and_frameworks(self) -> None:
        for repo in self.repositories.values():
            langs: Set[Language] = set()
            for file in self.files.values():
                if file.repository_id == repo.id:
                    langs.add(file.language)
            repo.languages = sorted(langs, key=lambda x: x.value)

            pkgs = {d.package.lower() for d in self.dependencies.values() if d.consumer == repo.id}
            frameworks: Set[Framework] = set()
            if "fastapi" in pkgs:
                frameworks.add(Framework.FASTAPI)
            if "pytest" in pkgs:
                frameworks.add(Framework.PYTEST)
            repo.frameworks = sorted(frameworks, key=lambda x: x.value) if frameworks else [Framework.UNKNOWN]

    def resolve_dependencies(self) -> None:
        # Dependencies are added from manifest/lock evidence in sample.
        # Here we ensure direct/transitive classification and repo dependency list.
        for repo in self.repositories.values():
            repo.dependencies = sorted(
                {
                    d.id for d in self.dependencies.values()
                    if d.consumer == repo.id
                }
            )

    def reconcile_sbom(self) -> None:
        dep_by_package: Dict[str, Dependency] = {}
        for dep in self.dependencies.values():
            if dep.directness == "DIRECT" and dep.resolved_version:
                dep_by_package[dep.package.lower()] = dep

        for sb in self.sbom_components.values():
            dep = dep_by_package.get(sb.name.lower())
            if not dep or not sb.version:
                continue
            if dep.resolved_version and dep.resolved_version != sb.version:
                self.contradictions.append(Contradiction(
                    id=new_id("CON-SBOM-", sb.id + dep.id),
                    contradiction_type="SBOM_VS_LOCKFILE",
                    description=(
                        f"SBOM component {sb.name} version {sb.version} conflicts with lockfile resolved "
                        f"version {dep.resolved_version} for dependency {dep.id}."
                    ),
                    repository_id=sb.repository_id,
                    evidence_ids=sorted(set(sb.evidence_ids + dep.evidence_ids)),
                    source_ids=sorted(set(sb.source_ids + dep.source_ids)),
                    severity="MEDIUM",
                    status="OPEN",
                    recommended_resolution=(
                        "Regenerate SBOM from authoritative lockfile/build artifact; do not treat SBOM as deployed truth."
                    ),
                ))

    def compute_reachability(self) -> None:
        adj: Dict[str, Set[str]] = defaultdict(set)
        for caller, callees in self.symbol_calls.items():
            adj[caller].update(callees)
        for route_id, handler_id in self.route_handler_map.items():
            adj[route_id].add(handler_id)

        visited: Set[str] = set()
        q = deque(self.entrypoint_ids)
        for eid in self.entrypoint_ids:
            visited.add(eid)

        while q:
            cur = q.popleft()
            for nxt in adj.get(cur, set()):
                if nxt not in visited:
                    visited.add(nxt)
                    q.append(nxt)

        self.reachable_symbols = visited

        for sym in self.symbols.values():
            if sym.id in visited:
                sym.reachability_state = ReachabilityState.REACHABLE_SUPPORTED
            elif sym.route:
                sym.reachability_state = ReachabilityState.POSSIBLY_REACHABLE
            else:
                sym.reachability_state = ReachabilityState.UNKNOWN

    def effective_reachability(self, symbol_id: Optional[str]) -> ReachabilityState:
        if not symbol_id:
            return ReachabilityState.UNKNOWN
        sym = self.symbols.get(symbol_id)
        if not sym:
            return ReachabilityState.UNKNOWN
        if sym.reachability_state == ReachabilityState.REACHABLE_SUPPORTED and not self.deployment_context_known:
            return ReachabilityState.LIKELY_REACHABLE
        return sym.reachability_state

    # -----------------------------------------------------------------
    # Contradictions
    # -----------------------------------------------------------------

    def detect_documentation_drift(self) -> None:
        existing = {c.description for c in self.contradictions}

        auth_gap_findings = [
            f for f in self.findings.values()
            if f.finding_type == FindingType.ACCESS_CONTROL_GAP_CANDIDATE
        ]
        if not auth_gap_findings:
            return

        for claim in self.documentation_claims:
            if claim.get("claim") != "all_api_routes_require_authorization":
                continue
            for f in auth_gap_findings:
                desc = (
                    f"Documentation claims all API routes require authorization, but finding {f.id} "
                    f"identifies an access-control gap candidate at {f.file_path or 'unknown file'} "
                    f"symbol {f.symbol or 'unknown symbol'}."
                )
                if desc in existing:
                    continue
                self.contradictions.append(Contradiction(
                    id=new_id("CON-DOC-", desc),
                    contradiction_type="DOCUMENTATION_VS_CODE",
                    description=desc,
                    repository_id=f.repository_id,
                    finding_ids=[f.id],
                    evidence_ids=sorted(set(claim.get("evidence_ids", []) + f.evidence_ids)),
                    source_ids=sorted(set(claim.get("source_ids", []) + f.source_ids)),
                    severity="MEDIUM",
                    status="OPEN",
                    recommended_resolution=(
                        "Compare README/architecture claims against actual route dependencies and middleware; "
                        "update either documentation or implementation through approved change process."
                    ),
                ))
                existing.add(desc)

    # -----------------------------------------------------------------
    # Fact gate
    # -----------------------------------------------------------------

    def fact_gate_findings(self) -> None:
        for f in self.findings.values():
            srcs = [self.sources[sid] for sid in f.source_ids if sid in self.sources]
            if not srcs:
                f.confidence = 0.0
                f.state = FindingState.INCONCLUSIVE
                f.limitations.append("No mapped source.")
                continue

            families = self.source_families(f.source_ids)
            max_rel = max((s.reliability for s in srcs), default=0.5)
            direct = max((SOURCE_FACTOR.get(s.source_type, 0.65) for s in srcs), default=0.65)
            base = max_rel * direct

            if len(families) >= 2:
                base = min(0.99, base * 1.05)
            elif len(families) == 1 and len(f.source_ids) > 1:
                base *= 0.90
                f.limitations.append("Multiple sources share one upstream source family.")

            # Reachability adjustment.
            if f.symbol:
                f.reachability = self.effective_reachability(f.symbol)
            reach_mult = REACH_FACTOR.get(f.reachability, 0.5)
            base *= reach_mult

            # Deployment context guard.
            if not self.deployment_context_known:
                f.deployment_context = "UNKNOWN"
                base = min(base, 0.78)
                f.limitations.append(
                    "Production/deployed commit is not established; source-code risk is not production vulnerability."
                )

            # Type-specific semantic guards.
            if f.finding_type == FindingType.ACCESS_CONTROL_GAP_CANDIDATE:
                if base >= 0.62 and f.reachability in {
                    ReachabilityState.REACHABLE_SUPPORTED,
                    ReachabilityState.LIKELY_REACHABLE,
                }:
                    f.state = FindingState.VULNERABILITY_CANDIDATE
                else:
                    f.state = FindingState.INCONCLUSIVE
                f.limitations.extend([
                    "Access-control gap candidate is not proven exploitable.",
                    "Middleware/global authorization may still cover route; runtime configuration unresolved.",
                    "No live probing or bypass testing performed.",
                ])
                f.specialist_handoff = f.specialist_handoff or "VULNINT"

            elif f.finding_type == FindingType.SECRET_CANDIDATE:
                f.state = FindingState.OBSERVED
                base = min(base, 0.85)
                f.limitations.extend([
                    "Secret candidate is not validated.",
                    "No secret was used, tested, redeemed, or authenticated with.",
                    "Removal from HEAD does not equal revocation.",
                ])
                f.specialist_handoff = f.specialist_handoff or "CREDINT"

            elif f.finding_type == FindingType.SOURCE_TO_SINK_RISKY_PATTERN:
                f.state = FindingState.RISKY_PATTERN
                f.limitations.extend([
                    "Source-to-sink pattern is security-relevant but not automatically exploitable.",
                    "Validation, sanitization, runtime config, and reachability may mitigate.",
                    "No exploit payload generation performed.",
                ])
                f.specialist_handoff = f.specialist_handoff or "VULNINT"

            elif f.finding_type == FindingType.DOCUMENTATION_DRIFT:
                f.state = FindingState.OBSERVED

            elif f.finding_type in {
                FindingType.DEPENDENCY_VERSION_CONFLICT,
                FindingType.SBOM_STALE,
            }:
                f.state = FindingState.INCONCLUSIVE
                base = min(base, 0.70)
                f.limitations.append("SBOM/lockfile/build artifact may differ from deployed runtime.")

            elif f.finding_type == FindingType.TEST_COVERAGE_GAP:
                f.state = FindingState.OBSERVED
                f.limitations.append("Missing tests do not prove vulnerability; they reduce assurance.")

            elif f.finding_type == FindingType.CI_SUPPLY_CHAIN_CONTEXT:
                f.state = FindingState.OBSERVED
                f.specialist_handoff = f.specialist_handoff or "SUPPLYCHAININT"
                f.limitations.append("CI configuration observation is not pipeline compromise evidence.")

            elif f.finding_type in {
                FindingType.FORK_LINEAGE,
                FindingType.CODE_SIMILARITY,
                FindingType.PROVENANCE_CANDIDATE,
            }:
                f.state = FindingState.OBSERVED
                f.limitations.append("Provenance/similarity does not establish authorship, ownership, or plagiarism.")

            elif f.finding_type == FindingType.LICENSE_CONTEXT:
                f.state = FindingState.OBSERVED
                f.specialist_handoff = f.specialist_handoff or "LEGALINT"
                f.limitations.append("License interpretation requires legal review.")

            elif f.finding_type == FindingType.MALICIOUS_BEHAVIOR_CANDIDATE:
                f.state = FindingState.RISKY_PATTERN
                f.specialist_handoff = f.specialist_handoff or "MALINT"
                f.limitations.extend([
                    "Malware-like capability is not automatically malware; context matters.",
                    "No sample execution or improvement performed.",
                ])

            else:
                if base >= 0.75:
                    f.state = FindingState.OBSERVED
                elif base >= 0.55:
                    f.state = FindingState.RISKY_PATTERN
                else:
                    f.state = FindingState.INCONCLUSIVE

            f.confidence = round(max(0.0, min(0.99, base)), 3)

    # -----------------------------------------------------------------
    # Gaps / actions / recommendations / handoffs
    # -----------------------------------------------------------------

    def build_knowledge_gaps(self) -> None:
        existing = {g.description for g in self.gaps}

        if not self.deployment_context_known:
            desc = "Deployed production commit/artifact is unknown; source findings cannot be mapped to production impact."
            if desc not in existing:
                self.gaps.append(KnowledgeGap(
                    id=new_id("GAP-DEPLOY-", desc),
                    gap_type=GapType.DEPLOYED_VERSION_UNKNOWN,
                    description=desc,
                    about_repository_ids=list(self.repositories.keys()),
                    importance="HIGH",
                    recommended_source="Authorized deployment metadata, release artifact signatures, container image digest, cloud/CI deployment logs",
                    specialist="CLOUDINT / DEPLOYMENTINT / CIINT",
                    expected_information_value=0.90,
                ))
                existing.add(desc)

        for f in self.findings.values():
            if f.state == FindingState.VULNERABILITY_CANDIDATE:
                desc = f"Vulnerability applicability/exploitability unresolved for finding {f.id}."
                if desc not in existing:
                    self.gaps.append(KnowledgeGap(
                        id=new_id("GAP-VULN-", desc),
                        gap_type=GapType.VULN_APPLICABILITY_UNKNOWN,
                        description=desc,
                        about_finding_ids=[f.id],
                        importance="HIGH",
                        recommended_source="Authorized VULNINT analysis, reachability validation, patch status, runtime configuration",
                        specialist="VULNINT",
                        expected_information_value=0.85,
                    ))
                    existing.add(desc)

            if f.finding_type == FindingType.SECRET_CANDIDATE:
                desc = f"Secret candidate {f.id} validity unknown; not tested by CODEINT."
                if desc not in existing:
                    self.gaps.append(KnowledgeGap(
                        id=new_id("GAP-SECRET-", desc),
                        gap_type=GapType.SECRET_VALIDITY_UNKNOWN,
                        description=desc,
                        about_finding_ids=[f.id],
                        importance="HIGH",
                        recommended_source="Authorized CREDINT exposure workflow; rotation if confirmed",
                        specialist="CREDINT",
                        expected_information_value=0.85,
                    ))
                    existing.add(desc)

        for c in self.contradictions:
            if c.contradiction_type == "SBOM_VS_LOCKFILE":
                desc = f"SBOM freshness/reconciliation unresolved: {c.description}"
                if desc not in existing:
                    self.gaps.append(KnowledgeGap(
                        id=new_id("GAP-SBOM-", desc),
                        gap_type=GapType.SBOM_STALE,
                        description=desc,
                        importance="MEDIUM",
                        recommended_source="Regenerate SBOM from lockfile/build artifact",
                        specialist="PACKAGEINT / SUPPLYCHAININT",
                        expected_information_value=0.70,
                    ))
                    existing.add(desc)

        if not self.coverages:
            desc = "No coverage report available; test assurance is limited."
            if desc not in existing:
                self.gaps.append(KnowledgeGap(
                    id=new_id("GAP-COV-", desc),
                    gap_type=GapType.TEST_COVERAGE_MISSING,
                    description=desc,
                    importance="MEDIUM",
                    recommended_source="Authorized test coverage report for analyzed commit",
                    specialist="QA / CODEINT",
                    expected_information_value=0.60,
                ))
                existing.add(desc)

        for prov in self.provenance.values():
            if prov.state == ProvenanceState.UNKNOWN:
                desc = f"Code provenance unresolved for {prov.subject}."
                if desc not in existing:
                    self.gaps.append(KnowledgeGap(
                        id=new_id("GAP-PROV-", desc),
                        gap_type=GapType.PROVENANCE_UNRESOLVED,
                        description=desc,
                        importance="MEDIUM",
                        recommended_source="Upstream repository metadata, license notices, vendoring records",
                        specialist="REPOINT / PACKAGEINT / LEGALINT",
                        expected_information_value=0.65,
                    ))
                    existing.add(desc)

    def build_next_actions(self) -> None:
        self.actions = []
        if not (self.repositories or self.files or self.evidence or self.findings):
            self.actions.append(NextAction(
                id="ACT-CONFIGURE-EVIDENCE",description="Supply an authorized local corpus before assigning specialist analysis.",
                priority=1,privacy_impact="LOW_IF_AUTHORIZED",expected_gain=0.95,specialist="CODEINT",requires_human_approval=False))
            return
        for index,gap in enumerate(self.gaps,1):
            self.actions.append(NextAction(
                id=new_id("ACT-GAP-",gap.id),description=f"Review {gap.recommended_source or 'authorized source records'} to resolve: {gap.description}",
                priority=index,privacy_impact="LOW_IF_AUTHORIZED",expected_gain=gap.expected_information_value,
                specialist=gap.specialist,requires_human_approval=False))

    def build_recommendations(self) -> None:
        recs: List[Recommendation] = []

        for f in self.findings.values():
            if f.finding_type == FindingType.ACCESS_CONTROL_GAP_CANDIDATE:
                recs.append(Recommendation(
                    id=new_id("REC-AUTH-", f.id),
                    category="SECURE_CODING",
                    action="Apply the shared authorization dependency/guard to the affected route handler and add regression tests.",
                    target=f"{f.file_path or 'unknown'}:{f.symbol or 'unknown'}",
                    rationale="Source analysis identifies an access-control gap candidate; production exploitability is not established.",
                    finding_ids=[f.id],
                    evidence_ids=f.evidence_ids,
                    approval=Approval.HUMAN_APPROVAL_REQUIRED,
                    business_impact="May affect API behavior; requires owner review.",
                    reversibility="Revertible with standard code review.",
                    limitations=[
                        "Do not provide bypass procedures.",
                        "Validate middleware/global authorization before assuming gap is exploitable.",
                    ],
                ))

            elif f.finding_type == FindingType.SECRET_CANDIDATE:
                recs.append(Recommendation(
                    id=new_id("REC-SECRET-", f.id),
                    category="SECRET_HANDLING",
                    action="Route secret candidate to CREDINT and rotate through authorized workflow if confirmed; do not use or test the secret.",
                    target=f"{f.file_path or 'unknown'}:{f.symbol or 'unknown'}",
                    rationale="A secret-shaped candidate was observed in history; validity is unknown and raw value is not exposed.",
                    finding_ids=[f.id],
                    evidence_ids=f.evidence_ids,
                    approval=Approval.HUMAN_APPROVAL_REQUIRED,
                    business_impact="Rotation may require service coordination.",
                    reversibility="Managed through secret rotation workflow.",
                    limitations=[
                        "CODEINT does not test secrets.",
                        "Removal from HEAD does not equal revocation.",
                    ],
                ))

            elif f.finding_type in {FindingType.SBOM_STALE, FindingType.DEPENDENCY_VERSION_CONFLICT}:
                recs.append(Recommendation(
                    id=new_id("REC-SBOM-", f.id),
                    category="SBOM_HYGIENE",
                    action="Regenerate SBOM from authoritative lockfile/build artifact and reconcile component versions.",
                    target=f.repository_id,
                    rationale="SBOM conflicts with lockfile/resolved dependency evidence.",
                    finding_ids=[f.id],
                    evidence_ids=f.evidence_ids,
                    approval=Approval.AUTONOMOUS_ANALYTIC,
                    business_impact="LOW",
                    reversibility="N/A",
                    limitations=["SBOM is not deployed runtime truth without build/deployment correlation."],
                ))

            elif f.finding_type == FindingType.DOCUMENTATION_DRIFT:
                recs.append(Recommendation(
                    id=new_id("REC-DOC-", f.id),
                    category="DOCUMENTATION",
                    action="Update README/architecture documentation or implementation to eliminate drift.",
                    target=f.repository_id,
                    rationale="Documentation claim conflicts with observed code behavior.",
                    finding_ids=[f.id],
                    evidence_ids=f.evidence_ids,
                    approval=Approval.HUMAN_APPROVAL_REQUIRED,
                    business_impact="LOW",
                    reversibility="Standard documentation change.",
                    limitations=["Docs are not implementation truth."],
                ))

            elif f.finding_type == FindingType.TEST_COVERAGE_GAP:
                recs.append(Recommendation(
                    id=new_id("REC-TEST-", f.id),
                    category="TESTING",
                    action="Add authorized regression/unit tests for the affected security-relevant behavior.",
                    target=f"{f.file_path or 'unknown'}:{f.symbol or 'unknown'}",
                    rationale="Current test corpus does not cover the security-relevant route/handler.",
                    finding_ids=[f.id],
                    evidence_ids=f.evidence_ids,
                    approval=Approval.HUMAN_APPROVAL_REQUIRED,
                    business_impact="LOW",
                    reversibility="Test addition is reversible.",
                    limitations=["Tests passing does not prove absence of vulnerabilities."],
                ))

            elif f.finding_type == FindingType.CI_SUPPLY_CHAIN_CONTEXT:
                recs.append(Recommendation(
                    id=new_id("REC-CI-", f.id),
                    category="SUPPLY_CHAIN",
                    action="Pin third-party CI actions to immutable commit SHAs and review permissions/secrets exposure.",
                    target=f.repository_id,
                    rationale="CI configuration references mutable third-party action ref.",
                    finding_ids=[f.id],
                    evidence_ids=f.evidence_ids,
                    approval=Approval.HUMAN_APPROVAL_REQUIRED,
                    business_impact="May require pipeline maintenance.",
                    reversibility="Pipeline config change reversible.",
                    limitations=["No pipeline tampering or exploitation instructions."],
                ))

        self.recommendations = recs

    def build_handoffs(self) -> None:
        self.handoffs = []
        if not (self.repositories or self.files or self.evidence or self.findings):
            return
        seen = set()
        for item in list(self.findings.values()) + self.gaps:
            specialist = getattr(item,"specialist_handoff",None) or getattr(item,"specialist",None)
            if not specialist:
                continue
            reason = getattr(item,"description",None) or getattr(item,"statement",None) or getattr(item,"title",None)
            key = (specialist,reason)
            if key in seen:
                continue
            seen.add(key)
            self.handoffs.append({"specialist":specialist,"reason":reason,"basis_id":item.id,"status":"PROPOSED_FROM_LOCAL_ANALYSIS"})

    # -----------------------------------------------------------------
    # Hypotheses / dual AI / summary
    # -----------------------------------------------------------------

    def build_hypotheses(self) -> None:
        hyps: List[Hypothesis] = []

        auth_findings = [f for f in self.findings.values() if f.finding_type == FindingType.ACCESS_CONTROL_GAP_CANDIDATE]
        if auth_findings:
            f = auth_findings[0]
            hyps.append(Hypothesis(
                id="H-ROUTE-PRODUCTION-REACHABLE",
                statement=(
                    f"The access-control gap candidate {f.id} is reachable in the deployed production environment."
                ),
                kind="PRODUCTION_REACHABILITY",
                supporting_finding_ids=[f.id],
                supporting_evidence_ids=f.evidence_ids,
                assumptions=["Deployed artifact corresponds to analyzed commit.", "No global middleware mitigates the route."],
                predictions=["Deployment metadata would show analyzed commit/tag in production.", "Runtime auth tests/logs would show missing enforcement."],
                falsification_conditions=[
                    "Production runs a different commit/branch.",
                    "Global middleware enforces authorization despite missing route dependency.",
                    "Feature flag disables the route in production.",
                    "Network/access controls prevent external reachability.",
                ],
                status=HypothesisStatus.UNRESOLVED,
                confidence=0.45,
                limitations=["Deployment context unknown.", "No live probing performed."],
            ))

            hyps.append(Hypothesis(
                id="H-GLOBAL-MIDDLEWARE-MITIGATES",
                statement="A global authentication/authorization middleware may mitigate the missing route-level dependency.",
                kind="MITIGATION",
                supporting_finding_ids=[],
                supporting_evidence_ids=[],
                assumptions=["Framework middleware may apply beyond explicit dependencies."],
                predictions=["Main application startup or middleware configuration would show global guard."],
                falsification_conditions=[
                    "No global guard exists.",
                    "Global guard excludes this route.",
                    "Guard only authenticates but does not authorize resource access.",
                ],
                status=HypothesisStatus.POSSIBLE,
                confidence=0.35,
                limitations=["Runtime configuration and middleware order unresolved."],
            ))

        secret_findings = [f for f in self.findings.values() if f.finding_type == FindingType.SECRET_CANDIDATE]
        if secret_findings:
            f = secret_findings[0]
            hyps.append(Hypothesis(
                id="H-SECRET-STILL-VALID",
                statement=f"Secret candidate {f.id} may still be valid in an external service.",
                kind="SECRET_VALIDITY",
                supporting_finding_ids=[f.id],
                supporting_evidence_ids=f.evidence_ids,
                assumptions=["Secret-shaped string was real at some point."],
                predictions=["CREDINT authorized workflow would determine validity without CODEINT testing it."],
                falsification_conditions=[
                    "String was example/test/fake.",
                    "Secret was rotated before exposure.",
                    "Service scope never allowed access.",
                ],
                status=HypothesisStatus.UNRESOLVED,
                confidence=0.30,
                limitations=["CODEINT does not test or use secrets."],
            ))

        if self.contradictions:
            hyps.append(Hypothesis(
                id="H-SBOM-STALE",
                statement="SBOM is stale or generated from a different build variant than the analyzed lockfile/source.",
                kind="SBOM_FRESHNESS",
                supporting_evidence_ids=sorted({eid for c in self.contradictions for eid in c.evidence_ids}),
                assumptions=["Lockfile is closer to source resolution than SBOM export."],
                predictions=["Regenerated SBOM from lockfile/build would align versions."],
                falsification_conditions=[
                    "SBOM corresponds to a different deployed artifact.",
                    "Lockfile is stale relative to build.",
                ],
                status=HypothesisStatus.PROBABLE,
                confidence=0.65,
                limitations=["SBOM may be build-specific; deployment artifact correlation unavailable."],
            ))

        self.hypotheses = hyps

    def dual_ai_review(self) -> Dict[str, Any]:
        issues: List[str] = []

        if not self.deployment_context_known:
            issues.append("Deployed production commit/artifact unknown; production impact cannot be asserted.")

        if any(f.state == FindingState.VULNERABILITY_CANDIDATE for f in self.findings.values()):
            issues.append("Security findings remain candidates, not verified exploitable vulnerabilities.")

        if any(f.finding_type == FindingType.SECRET_CANDIDATE for f in self.findings.values()):
            issues.append("Secret candidates are not validated; CREDINT handoff required.")

        if self.contradictions:
            issues.append(f"{len(self.contradictions)} documentation/SBOM/code contradiction(s) remain open.")

        if any(g.gap_type == GapType.TEST_COVERAGE_MISSING for g in self.gaps):
            issues.append("Test coverage evidence is incomplete.")

        if any(f.finding_type == FindingType.CI_SUPPLY_CHAIN_CONTEXT for f in self.findings.values()):
            issues.append("CI/third-party action supply-chain context requires SUPPLYCHAININT review.")

        if not self.evidence:
            verdict = "INSUFFICIENT_EVIDENCE"
        elif not issues:
            verdict = "DETERMINISTIC_CHECKLIST_COMPLETE"
        elif len(issues) <= 5:
            verdict = "CHECKLIST_ISSUES_IDENTIFIED"
        else:
            verdict = "INSUFFICIENT_EVIDENCE"

        return {
            "primary_code_analyst": (
                f"Supplied corpus contains {len(self.repositories)} repositories, {len(self.files)} files "
                f"and {len(self.findings)} findings. This is a deterministic checklist of local analysis."
            ),
            "independent_code_skeptic_issues": issues,
            "verdict": verdict,
            "review_mode": "DETERMINISTIC_CHECKLIST",
            "independent_review_performed": False,
            "adversarial_checks": [
                "Is repository HEAD assumed to be production? No; deployment unknown.",
                "Is package presence assumed runtime reachable? No; reachability graph used.",
                "Is route existence assumed publicly reachable? No; deployment/network unknown.",
                "Is secret candidate treated as valid? No; not tested.",
                "Is README treated as implementation truth? No; drift preserved.",
                "Is SBOM treated as deployed artifact? No; conflict flagged.",
                "Were unknown code or secrets executed/used? No.",
            ],
            "note": "Deterministic checklist only; no independent AI review or source corroboration was performed.",
        }

    def analyst_summary(self, dual: Dict[str, Any]) -> str:
        lines = [f"CASE: {self.case.case_id}",
                 f"SUPPLIED CORPUS: {len(self.repositories)} repositories, {len(self.files)} files, {len(self.evidence)} evidence records."]
        for repository in self.repositories.values():
            lines.append(f"REPOSITORY: {repository.id}; name={repository.name}; declared commit={repository.current_commit or 'unknown'}.")
            lines.append("LANGUAGES: " + (", ".join(language.value for language in repository.languages) or "unknown"))
            lines.append("FRAMEWORKS: " + (", ".join(framework.value for framework in repository.frameworks) or "unknown"))
        for finding in self.findings.values():
            lines.append(f"FINDING: {finding.id}; {finding.title}; local state={finding.state.value}; production impact unresolved.")
        lines.extend([f"OPEN CONTRADICTIONS: {len(self.contradictions)}.",
                      f"DETERMINISTIC CHECKLIST: {dual['verdict']}.",
                      "No model-based independent review, live repository access, code execution or secret testing was performed.",
                      "Repository metadata and local findings do not establish deployed architecture or production vulnerabilities."])
        return "\n".join(lines)

    # -----------------------------------------------------------------
    # Prepare
    # -----------------------------------------------------------------

    def prepare(self) -> None:
        self.detect_languages_and_frameworks()
        self.resolve_dependencies()
        self.reconcile_sbom()
        self.compute_reachability()
        self.detect_documentation_drift()
        self.fact_gate_findings()
        self.build_knowledge_gaps()
        self.build_next_actions()
        self.build_recommendations()
        self.build_handoffs()
        self.build_hypotheses()


# =====================================================================
# SAMPLE DATA
# =====================================================================

def sample_case() -> Case:
    return Case(
        case_id="SAMPLE-CODEINT-001",
        task_id="TASK-CODEINT-001",
        objective=(
            "Authorized static-first analysis of synthetic payments API repository to identify architecture, "
            "dependencies, secret candidates, access-control gap candidates, provenance, SBOM conflicts, "
            "documentation drift, and defensive remediation priorities without executing code or using secrets."
        ),
        questions=[
            "What is this codebase?",
            "Which languages/frameworks/components/services exist?",
            "Which dependencies are direct/transitive and what versions are resolved?",
            "Is the SBOM consistent with lockfile/source?",
            "Which API routes exist and are they reachable from entrypoints?",
            "Are there access-control gap candidates?",
            "Are there secret candidates, and how are they handled safely?",
            "What provenance/fork/similarity evidence exists?",
            "What remains unknown about production impact?",
            "What defensive next actions are justified?",
        ],
        scope=["authorized_source_only", "static_first", "case_scoped", "no_secret_use", "no_code_execution"],
        authorization="demo_authorized_code_intelligence",
        repositories=["REPO-PAYMENTS-API"],
        commits=["C-HEAD"],
        time_range="2026-09-01/2026-10-09",
        sample=True,
    )


def build_sample_codeint() -> CodeInt:
    c = CodeInt(sample_case())
    retrieved = now_iso()

    # Sources
    c.add_source(Source(
        id="SRC-REPO",
        title="Authorized repository snapshot: payments-api",
        url="https://repo.example/payments-api",
        source_type=SourceType.AUTHORIZED_REPO,
        independence_group="REPO_ROOT",
        reliability=0.95,
        published_at="2026-10-08T00:00:00Z",
        retrieved_at=retrieved,
        notes="Authorized source snapshot. Not live repository access.",
    ))
    c.add_source(Source(
        id="SRC-LOCK",
        title="Lockfile artifact from repository snapshot",
        url="https://repo.example/payments-api/poetry.lock",
        source_type=SourceType.LOCKFILE,
        independence_group="LOCK_DERIVED_REPO",
        reliability=0.90,
        derived_from="SRC-REPO",
        published_at="2026-10-08T00:00:00Z",
        retrieved_at=retrieved,
        notes="Lockfile provides resolved versions stronger than manifest ranges.",
    ))
    c.add_source(Source(
        id="SRC-SBOM",
        title="SBOM export associated with build pipeline",
        url="https://build.example/payments-api/sbom.cdx.json",
        source_type=SourceType.SBOM,
        independence_group="SBOM_DERIVED_BUILD",
        reliability=0.75,
        derived_from="SRC-REPO",
        published_at="2026-10-07T00:00:00Z",
        retrieved_at=retrieved,
        notes="SBOM may be build-specific and stale.",
    ))
    c.add_source(Source(
        id="SRC-README",
        title="README documentation from repository snapshot",
        url="https://repo.example/payments-api/README.md",
        source_type=SourceType.DOCUMENTATION,
        independence_group="DOC_DERIVED_REPO",
        reliability=0.55,
        derived_from="SRC-REPO",
        published_at="2026-10-08T00:00:00Z",
        retrieved_at=retrieved,
        notes="Documentation is a claim source, not implementation truth.",
    ))
    c.add_source(Source(
        id="SRC-CI",
        title="CI configuration from repository snapshot",
        url="https://repo.example/payments-api/.github/workflows/ci.yml",
        source_type=SourceType.CI_CD_CONFIG,
        independence_group="CI_DERIVED_REPO",
        reliability=0.82,
        derived_from="SRC-REPO",
        published_at="2026-10-08T00:00:00Z",
        retrieved_at=retrieved,
        notes="CI config is not actual pipeline execution evidence.",
    ))
    c.add_source(Source(
        id="SRC-TEST",
        title="Authorized test result for analyzed commit",
        url="https://ci.example/payments-api/test-results",
        source_type=SourceType.TEST_RESULT,
        independence_group="TEST_ROOT",
        reliability=0.78,
        published_at="2026-10-08T01:00:00Z",
        retrieved_at=retrieved,
        notes="Test pass does not prove security.",
    ))
    c.add_source(Source(
        id="SRC-UPSTREAM",
        title="Upstream template repository metadata",
        url="https://repo.example/fastapi-template",
        source_type=SourceType.PUBLIC_REPO,
        independence_group="UPSTREAM_REPO_ROOT",
        reliability=0.85,
        published_at="2026-01-01T00:00:00Z",
        retrieved_at=retrieved,
        notes="Used for fork/lineage context only.",
    ))

    # Repository
    c.add_repository(Repository(
        id="REPO-PAYMENTS-API",
        name="payments-api",
        remote_reference="https://repo.example/payments-api",
        visibility=Visibility.PRIVATE_AUTHORIZED,
        default_branch="main",
        current_commit="C-HEAD",
        languages=[Language.PYTHON, Language.YAML, Language.TOML, Language.MARKDOWN, Language.DOCKERFILE],
        frameworks=[Framework.FASTAPI, Framework.PYTEST],
        build_systems=[BuildSystem.POETRY, BuildSystem.DOCKER, BuildSystem.GITHUB_ACTIONS],
        package_managers=[PackageManager.POETRY],
        components=["COMPONENT-API", "COMPONENT-AUTH", "COMPONENT-DB"],
        services=["SERVICE-PAYMENTS-API"],
        entrypoints=["SYM-APP"],
        security_controls=["AUTHENTICATION_DEPENDENCY_PRESENT", "AUTHORIZATION_DEPENDENCY_PARTIAL", "TESTS_PRESENT"],
        sources=["SRC-REPO", "SRC-LOCK", "SRC-SBOM", "SRC-README", "SRC-CI", "SRC-TEST"],
        confidence=0.93,
        limitations=[
            "Repository snapshot is not deployed production artifact.",
            "Private authorized source treated as confidential.",
        ],
    ))

    # Commits
    c.add_commit(Commit(
        id="C-HEAD",
        repository_id="REPO-PAYMENTS-API",
        hash="abc123def456",
        parents=["C-FIX-SECRET"],
        author_metadata={"name": "CI Bot or configured author", "email": "bot@example.invalid"},
        committer_metadata={"name": "CI Bot or configured committer", "email": "bot@example.invalid"},
        timestamp="2026-10-08T00:00:00Z",
        message="Update dependencies and remove historical secret-shaped placeholder.",
        changed_files=["poetry.lock", "config/settings.py", "app/api/routes.py"],
        signature_status="UNSIGNED",
        source_ids=["SRC-REPO"],
        evidence_ids=["EV-REPO-META"],
        limitations=["Git author/committer metadata is not verified real-person identity."],
    ))
    c.add_commit(Commit(
        id="C-SECRET",
        repository_id="REPO-PAYMENTS-API",
        hash="111122223333",
        parents=["C-ANCIENT"],
        author_metadata={"name": "developer-configured", "email": "dev@example.invalid"},
        committer_metadata={"name": "developer-configured", "email": "dev@example.invalid"},
        timestamp="2026-03-01T00:00:00Z",
        message="Add local configuration.",
        changed_files=["config/settings.py"],
        signature_status="UNSIGNED",
        source_ids=["SRC-REPO"],
        evidence_ids=["EV-HIST-SECRET"],
        limitations=["Historical commit may contain secret-shaped candidate."],
    ))
    c.add_commit(Commit(
        id="C-FIX-SECRET",
        repository_id="REPO-PAYMENTS-API",
        hash="444455556666",
        parents=["C-SECRET"],
        author_metadata={"name": "maintainer-configured", "email": "maint@example.invalid"},
        committer_metadata={"name": "maintainer-configured", "email": "maint@example.invalid"},
        timestamp="2026-09-15T00:00:00Z",
        message="Remove secret-shaped value from settings.",
        changed_files=["config/settings.py"],
        signature_status="UNSIGNED",
        source_ids=["SRC-REPO"],
        evidence_ids=["EV-HIST-SECRET"],
        limitations=["Removal from HEAD does not equal revocation."],
    ))
    c.add_commit(Commit(
        id="C-ROUTE-ADDED",
        repository_id="REPO-PAYMENTS-API",
        hash="777788889999",
        parents=["C-ANCIENT"],
        author_metadata={"name": "developer-configured", "email": "dev@example.invalid"},
        committer_metadata={"name": "developer-configured", "email": "dev@example.invalid"},
        timestamp="2026-08-01T00:00:00Z",
        message="Add user lookup route.",
        changed_files=["app/api/routes.py"],
        signature_status="UNSIGNED",
        source_ids=["SRC-REPO"],
        evidence_ids=["EV-ROUTES"],
    ))
    c.add_commit(Commit(
        id="C-ANCIENT",
        repository_id="REPO-PAYMENTS-API",
        hash="000011112222",
        parents=[],
        author_metadata={"name": "upstream-template", "email": "template@example.invalid"},
        committer_metadata={"name": "upstream-template", "email": "template@example.invalid"},
        timestamp="2025-01-01T00:00:00Z",
        message="Initial template import.",
        changed_files=["app/main.py", "app/utils.py"],
        signature_status="UNSIGNED",
        source_ids=["SRC-REPO", "SRC-UPSTREAM"],
        evidence_ids=["EV-UPSTREAM"],
    ))

    # Branch / Tag / Release
    c.add_branch(Branch(
        id="BRANCH-MAIN",
        repository_id="REPO-PAYMENTS-API",
        name="main",
        is_default=True,
        head_commit_id="C-HEAD",
        protected=True,
        source_ids=["SRC-REPO"],
    ))
    c.add_tag(Tag(
        id="TAG-V120",
        repository_id="REPO-PAYMENTS-API",
        name="v1.2.0",
        commit_id="C-HEAD",
        annotated=True,
        signature_status="UNSIGNED",
        date="2026-10-08T00:00:00Z",
        source_ids=["SRC-REPO"],
    ))
    c.add_release(Release(
        id="REL-V120",
        repository_id="REPO-PAYMENTS-API",
        version="1.2.0",
        tag_id="TAG-V120",
        artifact_hashes=["sha256:release-artifact-placeholder"],
        publication_date="2026-10-08T01:00:00Z",
        release_notes="Synthetic release notes.",
        source_ids=["SRC-REPO"],
        limitations=["Published release does not prove production deployment."],
    ))

    # Files
    file_defs = [
        ("FILE-MAIN", "app/main.py", Language.PYTHON, "HIGH"),
        ("FILE-ROUTES", "app/api/routes.py", Language.PYTHON, "HIGH"),
        ("FILE-AUTH", "app/auth/deps.py", Language.PYTHON, "HIGH"),
        ("FILE-DB", "app/db/query.py", Language.PYTHON, "MEDIUM"),
        ("FILE-SETTINGS", "config/settings.py", Language.PYTHON, "HIGH"),
        ("FILE-PYPROJECT", "pyproject.toml", Language.TOML, "MEDIUM"),
        ("FILE-LOCK", "poetry.lock", Language.TEXT, "MEDIUM"),
        ("FILE-SBOM", "sbom.cdx.json", Language.JSON, "MEDIUM"),
        ("FILE-README", "README.md", Language.MARKDOWN, "LOW"),
        ("FILE-DOCKER", "Dockerfile", Language.DOCKERFILE, "MEDIUM"),
        ("FILE-CI", ".github/workflows/ci.yml", Language.YAML, "MEDIUM"),
        ("FILE-TEST-HEALTH", "tests/test_health.py", Language.PYTHON, "LOW"),
    ]
    for fid, path, lang, sec in file_defs:
        c.add_file(SourceFile(
            id=fid,
            repository_id="REPO-PAYMENTS-API",
            commit_id="C-HEAD",
            path=path,
            language=lang,
            size=1024,
            security_relevance=sec,
            test_status="TEST" if path.startswith("tests/") else "NOT_TEST",
            configuration_status="CONFIG" if path.startswith("config/") or path in {"pyproject.toml", "poetry.lock", "sbom.cdx.json"} else "NOT_CONFIG",
        ))

    # Evidence
    c.add_evidence(Evidence(
        id="EV-REPO-META",
        source_id="SRC-REPO",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        file_path=None,
        excerpt="Repository snapshot metadata: default branch main, current commit abc123def456, Python FastAPI-like service.",
        parsed_fields={
            "default_branch": "main",
            "current_commit": "C-HEAD",
            "languages": ["PYTHON"],
            "frameworks": ["FASTAPI"],
        },
    ))
    c.add_evidence(Evidence(
        id="EV-MAIN",
        source_id="SRC-REPO",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        file_path="app/main.py",
        symbol="SYM-APP",
        start_line=1,
        end_line=20,
        excerpt="Application startup creates FastAPI app and includes API router.",
        parsed_fields={
            "entrypoint": True,
            "framework": "FASTAPI",
            "calls": ["SYM-INCLUDE-ROUTER"],
        },
    ))
    c.add_evidence(Evidence(
        id="EV-ROUTES",
        source_id="SRC-REPO",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        file_path="app/api/routes.py",
        symbol="SYM-GET-USER",
        start_line=12,
        end_line=28,
        excerpt="Route GET /users/{user_id} handled by get_user; handler calls fetch_user_by_id. No explicit authorization dependency observed on this route.",
        parsed_fields={
            "route": "/users/{user_id}",
            "method": "GET",
            "handler": "SYM-GET-USER",
            "auth_dependency_observed": False,
            "authorization_dependency_observed": False,
            "calls": ["SYM-FETCH-USER"],
            "input_sources": ["path_parameter:user_id"],
            "sinks": ["database_query:fetch_user_by_id"],
        },
    ))
    c.add_evidence(Evidence(
        id="EV-AUTH",
        source_id="SRC-REPO",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        file_path="app/auth/deps.py",
        symbol="SYM-REQUIRE-ADMIN",
        start_line=5,
        end_line=15,
        excerpt="Authorization dependency require_admin exists and is used by some admin routes, but not observed on user lookup route.",
        parsed_fields={
            "authorization_control": "require_admin",
            "used_by_routes": ["/admin/*"],
            "not_used_by_routes": ["/users/{user_id}"],
        },
    ))
    c.add_evidence(Evidence(
        id="EV-DB",
        source_id="SRC-REPO",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        file_path="app/db/query.py",
        symbol="SYM-FETCH-USER",
        start_line=8,
        end_line=18,
        excerpt="Database helper fetch_user_by_id uses parameterized query pattern according to static parser.",
        parsed_fields={
            "parameterized_query_observed": True,
            "input_sources": ["function_argument:user_id"],
            "sinks": ["database_query"],
        },
        limitations=["Parameterization observation is static and does not prove all runtime paths safe."],
    ))
    c.add_evidence(Evidence(
        id="EV-HIST-SECRET",
        source_id="SRC-REPO",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-SECRET",
        file_path="config/settings.py",
        symbol=None,
        start_line=10,
        end_line=10,
        excerpt="Historical configuration contained an AWS-access-key-shaped candidate. Value redacted and fingerprinted only. Removed in later commit C-FIX-SECRET.",
        parsed_fields={
            "secret_type": "aws_access_key_candidate",
            "redacted_preview": "AKIA****",
            "fingerprint": fingerprint_secret("AKIAIOSFODNN7EXAMPLE-SYNTHETIC"),
            "removed_in_head": True,
            "tested": False,
            "used": False,
        },
        limitations=[
            "Raw secret not stored.",
            "Candidate validity not tested.",
            "History removal does not equal revocation.",
        ],
    ))
    c.add_evidence(Evidence(
        id="EV-MANIFEST",
        source_id="SRC-REPO",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        file_path="pyproject.toml",
        excerpt="Manifest declares fastapi>=0.110, pydantic>=2, pytest as dev dependency.",
        parsed_fields={
            "declared_dependencies": {
                "fastapi": ">=0.110",
                "pydantic": ">=2",
                "pytest": "^8.0",
            }
        },
    ))
    c.add_evidence(Evidence(
        id="EV-LOCK",
        source_id="SRC-LOCK",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        file_path="poetry.lock",
        excerpt="Lockfile resolves fastapi 0.111.0, pydantic 2.7.1, starlette 0.37.2, pytest 8.2.0.",
        parsed_fields={
            "resolved_dependencies": {
                "fastapi": "0.111.0",
                "pydantic": "2.7.1",
                "starlette": "0.37.2",
                "pytest": "8.2.0",
            }
        },
    ))
    c.add_evidence(Evidence(
        id="EV-SBOM",
        source_id="SRC-SBOM",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        file_path="sbom.cdx.json",
        excerpt="SBOM lists fastapi 0.110.2 and pydantic 2.7.1; fastapi version conflicts with lockfile.",
        parsed_fields={
            "components": {
                "fastapi": "0.110.2",
                "pydantic": "2.7.1",
            }
        },
        limitations=["SBOM may be stale or build-specific."],
    ))
    c.add_evidence(Evidence(
        id="EV-README",
        source_id="SRC-README",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        file_path="README.md",
        excerpt="README states: all API routes require authentication and authorization.",
        parsed_fields={
            "claim": "all_api_routes_require_authorization",
            "scope": "routes",
        },
        limitations=["Documentation claim is not implementation truth."],
    ))
    c.add_evidence(Evidence(
        id="EV-CI",
        source_id="SRC-CI",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        file_path=".github/workflows/ci.yml",
        excerpt="CI workflow uses third-party action some-org/action@v1 without immutable commit pin.",
        parsed_fields={
            "third_party_actions": [
                {"uses": "some-org/action@v1", "pinned_to_sha": False}
            ],
            "secrets_references": ["CI_SECRET_REF_PLACEHOLDER"],
        },
        limitations=["CI config is not actual pipeline execution evidence."],
    ))
    c.add_evidence(Evidence(
        id="EV-TEST",
        source_id="SRC-TEST",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        file_path="tests/test_health.py",
        excerpt="Test suite includes health endpoint test passing; no authorization regression test for /users/{user_id}.",
        parsed_fields={
            "tests": ["test_health"],
            "missing_tests": ["test_users_route_authorization"],
            "passed": True,
        },
        limitations=["Test pass does not prove security."],
    ))
    c.add_evidence(Evidence(
        id="EV-UPSTREAM",
        source_id="SRC-UPSTREAM",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-ANCIENT",
        excerpt="Repository metadata indicates fork/common ancestor with fastapi-template at commit 000011112222.",
        parsed_fields={
            "upstream_repository": "REPO-FASTAPI-TEMPLATE",
            "common_ancestor_commit": "C-ANCIENT",
            "fork_state": "SUPPORTED_FORK",
        },
    ))

    # Documentation claims
    c.add_documentation_claim({
        "claim": "all_api_routes_require_authorization",
        "scope": "routes",
        "source_ids": ["SRC-README"],
        "evidence_ids": ["EV-README"],
    })

    # Symbols
    c.add_symbol(Symbol(
        id="SYM-APP",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        file_id="FILE-MAIN",
        name="app",
        symbol_type=SymbolType.ENTRYPOINT,
        start_line=1,
        end_line=20,
        calls=["SYM-INCLUDE-ROUTER"],
        entrypoint=True,
        confidence=0.95,
        evidence_ids=["EV-MAIN"],
    ))
    c.add_symbol(Symbol(
        id="SYM-INCLUDE-ROUTER",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        file_id="FILE-MAIN",
        name="include_router",
        symbol_type=SymbolType.FUNCTION,
        calls=["SYM-ROUTE-USERS"],
        confidence=0.92,
        evidence_ids=["EV-MAIN"],
    ))
    c.add_symbol(Symbol(
        id="SYM-ROUTE-USERS",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        file_id="FILE-ROUTES",
        name="GET /users/{user_id}",
        symbol_type=SymbolType.ROUTE,
        route="/users/{user_id}",
        method="GET",
        handler="SYM-GET-USER",
        calls=["SYM-GET-USER"],
        confidence=0.94,
        evidence_ids=["EV-ROUTES"],
    ))
    c.add_symbol(Symbol(
        id="SYM-GET-USER",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        file_id="FILE-ROUTES",
        name="get_user",
        symbol_type=SymbolType.HANDLER,
        start_line=12,
        end_line=28,
        calls=["SYM-FETCH-USER"],
        confidence=0.94,
        evidence_ids=["EV-ROUTES"],
        limitations=["No explicit authorization dependency observed."],
    ))
    c.add_symbol(Symbol(
        id="SYM-FETCH-USER",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        file_id="FILE-DB",
        name="fetch_user_by_id",
        symbol_type=SymbolType.FUNCTION,
        start_line=8,
        end_line=18,
        confidence=0.90,
        evidence_ids=["EV-DB"],
    ))
    c.add_symbol(Symbol(
        id="SYM-REQUIRE-ADMIN",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        file_id="FILE-AUTH",
        name="require_admin",
        symbol_type=SymbolType.FUNCTION,
        start_line=5,
        end_line=15,
        confidence=0.92,
        evidence_ids=["EV-AUTH"],
    ))

    # Components / Services
    c.add_component(Component(
        id="COMPONENT-API",
        repository_id="REPO-PAYMENTS-API",
        name="payments-api",
        component_type="WEB_SERVICE",
        files=["FILE-MAIN", "FILE-ROUTES"],
        symbols=["SYM-APP", "SYM-ROUTE-USERS", "SYM-GET-USER"],
        description="FastAPI-like HTTP API component.",
        source_ids=["SRC-REPO"],
        evidence_ids=["EV-MAIN", "EV-ROUTES"],
        confidence=0.92,
    ))
    c.add_component(Component(
        id="COMPONENT-AUTH",
        repository_id="REPO-PAYMENTS-API",
        name="auth",
        component_type="SECURITY_CONTROL",
        files=["FILE-AUTH"],
        symbols=["SYM-REQUIRE-ADMIN"],
        description="Authentication/authorization dependency module.",
        source_ids=["SRC-REPO"],
        evidence_ids=["EV-AUTH"],
        confidence=0.90,
    ))
    c.add_component(Component(
        id="COMPONENT-DB",
        repository_id="REPO-PAYMENTS-API",
        name="db",
        component_type="DATA_ACCESS",
        files=["FILE-DB"],
        symbols=["SYM-FETCH-USER"],
        description="Database query helper component.",
        source_ids=["SRC-REPO"],
        evidence_ids=["EV-DB"],
        confidence=0.88,
    ))
    c.add_service(Service(
        id="SERVICE-PAYMENTS-API",
        repository_id="REPO-PAYMENTS-API",
        name="payments-api",
        deployment_unit="Dockerfile",
        entrypoint_symbol_ids=["SYM-APP"],
        route_symbols=["SYM-ROUTE-USERS"],
        dependencies=["DEP-FRA", "DEP-PYDANTIC", "DEP-STARLETTE"],
        source_ids=["SRC-REPO", "SRC-LOCK"],
        evidence_ids=["EV-MAIN", "EV-LOCK"],
        confidence=0.90,
        limitations=["Deployment unit presence does not prove deployed runtime."],
    ))

    # Dependencies
    c.add_dependency(Dependency(
        id="DEP-FRA",
        consumer="REPO-PAYMENTS-API",
        provider="PyPI-like",
        package="fastapi",
        ecosystem="pypi",
        declared_version=">=0.110",
        resolved_version="0.111.0",
        scope="RUNTIME",
        directness="DIRECT",
        source_ids=["SRC-REPO", "SRC-LOCK"],
        evidence_ids=["EV-MANIFEST", "EV-LOCK"],
        license="MIT",
    ))
    c.add_dependency(Dependency(
        id="DEP-PYDANTIC",
        consumer="REPO-PAYMENTS-API",
        provider="PyPI-like",
        package="pydantic",
        ecosystem="pypi",
        declared_version=">=2",
        resolved_version="2.7.1",
        scope="RUNTIME",
        directness="DIRECT",
        source_ids=["SRC-REPO", "SRC-LOCK"],
        evidence_ids=["EV-MANIFEST", "EV-LOCK"],
        license="MIT",
    ))
    c.add_dependency(Dependency(
        id="DEP-STARLETTE",
        consumer="REPO-PAYMENTS-API",
        provider="PyPI-like",
        package="starlette",
        ecosystem="pypi",
        declared_version=None,
        resolved_version="0.37.2",
        scope="RUNTIME",
        directness="TRANSITIVE",
        source_ids=["SRC-LOCK"],
        evidence_ids=["EV-LOCK"],
        license="BSD-3-Clause",
    ))
    c.add_dependency(Dependency(
        id="DEP-PYTEST",
        consumer="REPO-PAYMENTS-API",
        provider="PyPI-like",
        package="pytest",
        ecosystem="pypi",
        declared_version="^8.0",
        resolved_version="8.2.0",
        scope="DEV",
        directness="DIRECT",
        source_ids=["SRC-REPO", "SRC-LOCK"],
        evidence_ids=["EV-MANIFEST", "EV-LOCK"],
        license="MIT",
    ))

    # SBOM components
    c.add_sbom_component(SBOMComponent(
        id="SBOM-FASTAPI",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        purl="pkg:pypi/fastapi@0.110.2",
        name="fastapi",
        version="0.110.2",
        license="MIT",
        source_ids=["SRC-SBOM"],
        evidence_ids=["EV-SBOM"],
        limitations=["Version conflicts with lockfile."],
    ))
    c.add_sbom_component(SBOMComponent(
        id="SBOM-PYDANTIC",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        purl="pkg:pypi/pydantic@2.7.1",
        name="pydantic",
        version="2.7.1",
        license="MIT",
        source_ids=["SRC-SBOM"],
        evidence_ids=["EV-SBOM"],
    ))

    # License
    c.add_license(LicenseInfo(
        id="LIC-REPO",
        repository_id="REPO-PAYMENTS-API",
        declared_license="Proprietary or internal license placeholder",
        file_level_notices=["README license section present"],
        dependency_licenses={
            "fastapi": "MIT",
            "pydantic": "MIT",
            "starlette": "BSD-3-Clause",
            "pytest": "MIT",
        },
        conflict_candidates=[],
        source_ids=["SRC-REPO", "SRC-LOCK"],
        evidence_ids=["EV-REPO-META", "EV-LOCK"],
        legal_review_required=True,
        limitations=["CODEINT does not make legal compliance determinations."],
    ))

    # Secret candidate
    c.add_secret_candidate(SecretCandidate(
        id="SEC-HIST-AWS",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-SECRET",
        file_path="config/settings.py",
        line=10,
        secret_type="aws_access_key_candidate",
        redacted_preview="AKIA****",
        fingerprint=fingerprint_secret("AKIAIOSFODNN7EXAMPLE-SYNTHETIC"),
        state=SecretState.REMOVED_IN_HEAD_NOT_REVOKED,
        first_seen="2026-03-01T00:00:00Z",
        last_seen="2026-09-15T00:00:00Z",
        removed_in_head=True,
        source_ids=["SRC-REPO"],
        evidence_ids=["EV-HIST-SECRET"],
        limitations=[
            "Raw secret not exposed.",
            "Validity not tested.",
            "No credential use/authentication performed.",
        ],
    ))

    # Config item
    c.add_config_item(ConfigItem(
        id="CFG-DATABASE-URL",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        key="DATABASE_URL",
        value_type="environment_variable_reference",
        redacted_value="${DATABASE_URL}",
        fingerprint=sha256_short("DATABASE_URL"),
        environment="RUNTIME",
        source_ids=["SRC-REPO"],
        evidence_ids=["EV-REPO-META"],
        limitations=["Environment variable reference is not a secret value."],
    ))

    # Tests / Coverage
    c.add_test(Test(
        id="TEST-HEALTH",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        name="test_health",
        target_symbols=[],
        passed=True,
        coverage="unknown",
        source_ids=["SRC-TEST"],
        evidence_ids=["EV-TEST"],
        limitations=["Test pass does not prove security."],
    ))
    c.add_coverage(Coverage(
        id="COV-PARTIAL",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        line_coverage=0.42,
        branch_coverage=None,
        function_coverage=None,
        scope="tests/test_health.py only",
        source_ids=["SRC-TEST"],
        evidence_ids=["EV-TEST"],
        limitations=["Coverage report partial; security-relevant route not covered."],
    ))

    # Provenance / Similarity
    c.add_provenance(Provenance(
        id="PROV-FORK",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-ANCIENT",
        subject="REPO-PAYMENTS-API",
        origin="REPO-FASTAPI-TEMPLATE",
        state=ProvenanceState.FORK_DERIVED,
        upstream_repository_id="REPO-FASTAPI-TEMPLATE",
        upstream_commit_id="C-ANCIENT",
        evidence_ids=["EV-UPSTREAM"],
        limitations=["Fork does not imply ownership, endorsement, or authorship of all code."],
    ))
    c.add_similarity(CodeSimilarity(
        id="SIM-UTIL-TEMPLATE",
        left_repository_id="REPO-PAYMENTS-API",
        right_repository_id="REPO-FASTAPI-TEMPLATE",
        left_commit_id="C-HEAD",
        right_commit_id="C-ANCIENT",
        scope="app/utils.py-like helper",
        state=SimilarityState.COMMON_TEMPLATE,
        similarity_score=0.82,
        method="AST/token similarity placeholder",
        evidence_ids=["EV-UPSTREAM"],
        limitations=["Similarity can arise from templates/tutorials/common standards; not plagiarism proof."],
    ))

    # Security findings
    c.add_finding(SecurityFinding(
        id="FIND-AUTH-GAP",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        finding_type=FindingType.ACCESS_CONTROL_GAP_CANDIDATE,
        state=FindingState.INCONCLUSIVE,
        title="User lookup route lacks explicit authorization dependency",
        description=(
            "Static analysis observes route GET /users/{user_id} handled by get_user calling fetch_user_by_id. "
            "An authorization dependency require_admin exists in the codebase but is not observed on this route. "
            "This is an access-control gap candidate, not a proven vulnerability."
        ),
        file_path="app/api/routes.py",
        symbol="SYM-GET-USER",
        start_line=12,
        end_line=28,
        severity="HIGH",
        reachability=ReachabilityState.UNKNOWN,
        deployment_context="UNKNOWN",
        source_ids=["SRC-REPO", "SRC-README"],
        evidence_ids=["EV-ROUTES", "EV-AUTH", "EV-README"],
        introduced_in="C-ROUTE-ADDED",
        limitations=[
            "Global middleware may mitigate; runtime configuration unresolved.",
            "No live probing or bypass testing performed.",
            "Production deployment commit unknown.",
        ],
        remediation=[
            "Apply shared authorization dependency/guard to route.",
            "Add regression tests for resource-level authorization.",
            "Validate middleware order and global guards.",
        ],
    ))
    c.add_finding(SecurityFinding(
        id="FIND-SECRET-HIST",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-SECRET",
        finding_type=FindingType.SECRET_CANDIDATE,
        state=FindingState.OBSERVED,
        title="Historical secret-shaped candidate in configuration",
        description=(
            "A secret-shaped string candidate was observed in historical commit C-SECRET and removed in C-FIX-SECRET. "
            "The value is redacted and fingerprinted only. Validity was not tested."
        ),
        file_path="config/settings.py",
        symbol=None,
        start_line=10,
        end_line=10,
        severity="MEDIUM",
        reachability=ReachabilityState.UNKNOWN,
        deployment_context="UNKNOWN",
        source_ids=["SRC-REPO"],
        evidence_ids=["EV-HIST-SECRET"],
        introduced_in="C-SECRET",
        fixed_in="C-FIX-SECRET",
        limitations=[
            "Candidate may be example/test/fake/expired/rotated.",
            "Removal from HEAD does not equal revocation.",
            "No secret use/testing/redeeming performed.",
        ],
        specialist_handoff="CREDINT",
        remediation=[
            "Route to CREDINT for authorized exposure handling.",
            "Rotate through authorized workflow if confirmed valid.",
            "Review history/forks/artifacts/cache for persistence.",
        ],
    ))
    c.add_finding(SecurityFinding(
        id="FIND-DOC-DRIFT",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        finding_type=FindingType.DOCUMENTATION_DRIFT,
        state=FindingState.OBSERVED,
        title="README authorization claim conflicts with observed route dependency",
        description="README claims all API routes require authorization, but static analysis observes a route without explicit authorization dependency.",
        file_path="README.md",
        symbol=None,
        severity="MEDIUM",
        source_ids=["SRC-README", "SRC-REPO"],
        evidence_ids=["EV-README", "EV-ROUTES"],
        limitations=["Documentation may be stale; implementation is stronger evidence for code behavior."],
        remediation=["Update documentation or implementation to eliminate drift."],
    ))
    c.add_finding(SecurityFinding(
        id="FIND-SBOM-STALE",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        finding_type=FindingType.SBOM_STALE,
        state=FindingState.INCONCLUSIVE,
        title="SBOM fastapi version conflicts with lockfile",
        description="SBOM lists fastapi 0.110.2 while lockfile resolves fastapi 0.111.0.",
        file_path="sbom.cdx.json",
        symbol=None,
        severity="LOW",
        source_ids=["SRC-SBOM", "SRC-LOCK"],
        evidence_ids=["EV-SBOM", "EV-LOCK"],
        limitations=["SBOM may correspond to different build variant or be stale."],
        specialist_handoff="PACKAGEINT / SUPPLYCHAININT",
        remediation=["Regenerate SBOM from authoritative lockfile/build artifact."],
    ))
    c.add_finding(SecurityFinding(
        id="FIND-TEST-GAP",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        finding_type=FindingType.TEST_COVERAGE_GAP,
        state=FindingState.OBSERVED,
        title="No authorization regression test for user lookup route",
        description="Test corpus includes health test but lacks authorization regression test for GET /users/{user_id}.",
        file_path="tests/test_health.py",
        symbol=None,
        severity="MEDIUM",
        source_ids=["SRC-TEST"],
        evidence_ids=["EV-TEST"],
        limitations=["Missing tests reduce assurance but do not prove vulnerability."],
        remediation=["Add authorized authorization regression tests."],
    ))
    c.add_finding(SecurityFinding(
        id="FIND-CI-SUPPLY",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        finding_type=FindingType.CI_SUPPLY_CHAIN_CONTEXT,
        state=FindingState.OBSERVED,
        title="Mutable third-party CI action reference",
        description="CI workflow uses some-org/action@v1 without immutable commit pin.",
        file_path=".github/workflows/ci.yml",
        symbol=None,
        severity="MEDIUM",
        source_ids=["SRC-CI"],
        evidence_ids=["EV-CI"],
        limitations=["CI config observation is not pipeline compromise evidence."],
        specialist_handoff="SUPPLYCHAININT",
        remediation=["Pin third-party actions to immutable commit SHAs."],
    ))
    c.add_finding(SecurityFinding(
        id="FIND-FORK",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-ANCIENT",
        finding_type=FindingType.FORK_LINEAGE,
        state=FindingState.OBSERVED,
        title="Repository lineage from template fork",
        description="Repository metadata indicates supported fork/common ancestor from fastapi-template.",
        file_path=None,
        symbol=None,
        severity="INFO",
        source_ids=["SRC-UPSTREAM", "SRC-REPO"],
        evidence_ids=["EV-UPSTREAM"],
        limitations=["Fork does not imply ownership, endorsement, or authorship of all code."],
    ))
    c.add_finding(SecurityFinding(
        id="FIND-SIMILAR",
        repository_id="REPO-PAYMENTS-API",
        commit_id="C-HEAD",
        finding_type=FindingType.CODE_SIMILARITY,
        state=FindingState.OBSERVED,
        title="Template similarity in helper code",
        description="Helper code shows structural similarity consistent with common template origin.",
        file_path="app/utils.py",
        symbol=None,
        severity="INFO",
        source_ids=["SRC-UPSTREAM"],
        evidence_ids=["EV-UPSTREAM"],
        limitations=["Similarity is not plagiarism or authorship proof."],
    ))

    c.prepare()
    return c


# =====================================================================
# RESULT BUILDER
# =====================================================================

def graph_version_hash(c: CodeInt) -> str:
    seed_obj = {
        "repo": sorted((rid, r.current_commit, r.visibility.value) for rid, r in c.repositories.items()),
        "files": sorted((fid, f.repository_id, f.commit_id, f.path, f.language.value) for fid, f in c.files.items()),
        "symbols": sorted((sid, s.repository_id, s.commit_id, s.name, s.symbol_type.value, s.reachability_state.value) for sid, s in c.symbols.items()),
        "deps": sorted((did, d.package, d.declared_version or "", d.resolved_version or "", d.directness) for did, d in c.dependencies.items()),
        "findings": sorted((fid, f.finding_type.value, f.state.value, round(float(f.confidence), 3)) for fid, f in c.findings.items()),
    }
    return sha256_short(json.dumps(jsonable(seed_obj), sort_keys=True))


def build_source_graph(c: CodeInt) -> Dict[str, Any]:
    edges = []
    for src in c.sources.values():
        if src.derived_from:
            edges.append({
                "source": src.derived_from,
                "target": src.id,
                "relationship_type": "DERIVED_FROM",
            })
    return {
        "nodes": [s.id for s in c.sources.values()],
        "edges": edges,
    }


def build_source_dependency_graph(c: CodeInt) -> Dict[str, List[str]]:
    families: Dict[str, List[str]] = defaultdict(list)
    for sid in c.sources:
        fam = c.get_source_family(sid) or "UNKNOWN"
        families[fam].append(sid)
    return {k: sorted(v) for k, v in families.items()}


def build_code_graph(c: CodeInt) -> Dict[str, Any]:
    nodes = []
    edges = []

    for fid, f in c.files.items():
        nodes.append({"id": fid, "type": "SourceFile", "label": f.path, "language": f.language.value})
    for sid, s in c.symbols.items():
        nodes.append({
            "id": sid,
            "type": "Symbol",
            "label": s.name,
            "symbol_type": s.symbol_type.value,
            "reachability": s.reachability_state.value,
        })
        edges.append({"source": s.file_id, "target": sid, "relationship_type": "CONTAINS"})
        for callee in s.calls:
            edges.append({"source": sid, "target": callee, "relationship_type": "CALLS"})
        if s.route:
            edges.append({"source": sid, "target": s.handler or "", "relationship_type": "HANDLED_BY"})
            edges.append({"source": sid, "target": s.route, "relationship_type": "EXPOSES_ROUTE"})

    for did, d in c.dependencies.items():
        nodes.append({"id": did, "type": "Dependency", "label": f"{d.package}@{d.resolved_version or d.declared_version}"})
        edges.append({"source": d.consumer, "target": did, "relationship_type": "DEPENDS_ON"})

    return {"nodes": nodes, "edges": edges}


def build_reachability_payload(c: CodeInt) -> Dict[str, Any]:
    return {
        "entrypoints": sorted(c.entrypoint_ids),
        "reachable_symbols": sorted(c.reachable_symbols),
        "route_handler_map": c.route_handler_map,
        "deployment_context_known": c.deployment_context_known,
        "guardrails": [
            "Code-level reachability is not production reachability.",
            "Reachability is not exploitability.",
            "No live endpoint probing performed.",
        ],
    }


def build_secret_handling_payload(c: CodeInt) -> Dict[str, Any]:
    return {
        "secret_candidates": list(c.secret_candidates.values()),
        "raw_secret_exposed": False,
        "secret_tested": False,
        "secret_used": False,
        "policy": [
            "CODEINT fingerprints and redacts secret candidates.",
            "CODEINT does not use, test, redeem, or authenticate with secrets.",
            "Historical removal does not equal revocation.",
            "Exposed secret handling is handed to CREDINT.",
        ],
    }


def build_result(c: CodeInt, status: Status) -> Dict[str, Any]:
    dual = c.dual_ai_review()
    summary = c.analyst_summary(dual)
    source_families = build_source_dependency_graph(c)

    finding_independence = {
        fid: c.independence_state(f.source_ids)
        for fid, f in c.findings.items()
    }

    supported_facts = [f for f in c.findings.values() if f.state in {FindingState.OBSERVED, FindingState.RISKY_PATTERN}]
    vulnerability_candidates = [f for f in c.findings.values() if f.state == FindingState.VULNERABILITY_CANDIDATE]
    inconclusive = [f for f in c.findings.values() if f.state == FindingState.INCONCLUSIVE]

    replay_manifest = {
        "generated_at": now_iso(),
        "pipeline_version": PIPELINE_VERSION,
        "graph_version": graph_version_hash(c),
        "core_principle": (
            "SOURCE ARTIFACT -> PRESERVE -> IDENTIFY -> PARSE -> NORMALIZE -> SYMBOL/COMPONENT EXTRACTION -> "
            "DEPENDENCY GRAPH -> CONTROL/DATA FLOW -> SECURITY-RELEVANT OBSERVATIONS -> PROVENANCE -> "
            "TEMPORAL ANALYSIS -> SOURCE RELIABILITY -> FACT GATE -> TECHNICAL ASSESSMENT"
        ),
        "static_first": True,
        "code_execution": "NOT_PERFORMED",
        "secret_use": "NOT_PERFORMED",
        "exploit_generation": "NOT_PERFORMED",
        "source_lineage": source_families,
        "finding_independence": finding_independence,
        "temporal_rule": "Findings are pinned to repository/commit; historical code states preserved.",
        "policy_exclusions": [
            "No unauthorized repository access.",
            "No stolen credentials/tokens.",
            "No secret use/testing.",
            "No unknown code execution.",
            "No exploit/payload generation.",
            "No malware improvement.",
            "No EDR/AV bypass.",
            "No persistence/stealth design.",
            "No third-party repository tampering.",
        ],
    }

    return {
        "case_id": c.case.case_id,
        "task_id": c.case.task_id,
        "objective": c.case.objective,
        "questions": c.case.questions,
        "scope": c.case.scope,
        "authorization": c.case.authorization,
        "status": status.value,
        "source_ids": sorted(c.sources.keys()),
        "evidence_ids": sorted(c.evidence.keys()),
        "repositories": list(c.repositories.values()),
        "branches": list(c.branches.values()),
        "commits": list(c.commits.values()),
        "tags": list(c.tags.values()),
        "releases": list(c.releases.values()),
        "languages": sorted({l.value for r in c.repositories.values() for l in r.languages}),
        "frameworks": sorted({f.value for r in c.repositories.values() for f in r.frameworks}),
        "build_systems": sorted({b.value for r in c.repositories.values() for b in r.build_systems}),
        "package_managers": sorted({p.value for r in c.repositories.values() for p in r.package_managers}),
        "source_files": list(c.files.values()),
        "symbols": list(c.symbols.values()),
        "components": list(c.components.values()),
        "services": list(c.services.values()),
        "entrypoints": sorted(c.entrypoint_ids),
        "routes": [s for s in c.symbols.values() if s.symbol_type == SymbolType.ROUTE],
        "api_endpoints": [s for s in c.symbols.values() if s.route],
        "cli_commands": [],
        "schemas": [],
        "databases": [component.id for component in c.components.values() if component.component_type.lower() in {"database","db","database_component"}],
        "queues": [],
        "external_services": [],
        "cloud_sdks": [],
        "configurations": list(c.config_items.values()),
        "environment_variables": [item for item in c.config_items.values() if item.value_type == "environment_variable_reference"],
        "secret_candidates": build_secret_handling_payload(c),
        "dependencies": list(c.dependencies.values()),
        "direct_dependencies": [d for d in c.dependencies.values() if d.directness == "DIRECT"],
        "transitive_dependencies": [d for d in c.dependencies.values() if d.directness == "TRANSITIVE"],
        "packages": sorted({d.package for d in c.dependencies.values()}),
        "resolved_versions": {d.package: d.resolved_version for d in c.dependencies.values() if d.resolved_version},
        "sboms": list(c.sbom_components.values()),
        "vex_records": [],
        "licenses": list(c.licenses.values()),
        "ci_cd_pipelines": [{"file_id":file.id,"file_path":file.path,"repository_id":file.repository_id,"limitations":["File metadata does not establish pipeline execution."]} for file in c.files.values() if file.path.startswith(".github/workflows/")],
        "build_jobs": [],
        "artifacts": [{"type":"release","id":release.id,"version":release.version,"artifact_hashes":release.artifact_hashes,"deployment_known":False} for release in c.releases.values()],
        "containers": [{"file_id":file.id,"file_path":file.path,"limitations":["Container file metadata does not establish a deployed image."]} for file in c.files.values() if file.path.rsplit("/",1)[-1]=="Dockerfile"],
        "iac_resources": [],
        "tests": list(c.tests.values()),
        "coverage_context": list(c.coverages.values()),
        "security_controls": sorted({control for repository in c.repositories.values() for control in repository.security_controls}),
        "authentication_context": [],
        "authorization_context": [finding for finding in c.findings.values() if finding.finding_type==FindingType.ACCESS_CONTROL_GAP_CANDIDATE],
        "session_context": [],
        "crypto_context": [],
        "database_context": [component for component in c.components.values() if component.component_type.lower() in {"database","db","database_component"}],
        "filesystem_context": [],
        "network_context": [],
        "process_execution_context": [],
        "serialization_context": [],
        "input_validation_context": [],
        "logging_context": [],
        "telemetry_context": [],
        "code_similarity": list(c.similarities.values()),
        "fork_lineage": [p for p in c.provenance.values() if p.state == ProvenanceState.FORK_DERIVED],
        "code_provenance": list(c.provenance.values()),
        "code_ownership_context": [],
        "maintainer_context": [],
        "documentation_drift": [f for f in c.findings.values() if f.finding_type == FindingType.DOCUMENTATION_DRIFT],
        "security_findings": list(c.findings.values()),
        "vulnerability_candidates": vulnerability_candidates,
        "malicious_behavior_candidates": [f for f in c.findings.values() if f.finding_type == FindingType.MALICIOUS_BEHAVIOR_CANDIDATE],
        "reachability_states": {sid: s.reachability_state.value for sid, s in c.symbols.items()},
        "reachability_analysis": build_reachability_payload(c),
        "timeline_updates": [{"time":commit.timestamp,"event":commit.message or "Supplied commit metadata","commit_id":commit.id,"source_ids":[sid for sid in commit.source_ids if sid in c.sources]} for commit in c.commits.values() if commit.timestamp],
        "observations": list(c.evidence.values()),
        "candidate_facts": list(c.findings.values()),
        "supported_facts": supported_facts,
        "partial_facts": inconclusive,
        "disputed_facts": [],
        "source_reliability": {sid: s.reliability for sid, s in c.sources.items()},
        "source_limitations": {sid: [s.notes] for sid, s in c.sources.items() if s.notes},
        "source_pedigree": {sid: c.get_source_family(sid) for sid in c.sources},
        "source_independence": {
            "source_families": source_families,
            "finding_independence": finding_independence,
        },
        "contradictions": c.contradictions,
        "hypotheses": c.hypotheses,
        "falsification_results": [
            {
                "hypothesis_id": h.id,
                "status": h.status.value,
                "falsification_conditions": h.falsification_conditions,
                "limitations": h.limitations,
            }
            for h in c.hypotheses
        ],
        "privacy_flags": [
            PrivacyFlag.CASE_SCOPED.value,
            PrivacyFlag.AUTHORIZED_SOURCE_ONLY.value,
            PrivacyFlag.NO_PRIVATE_REPO_ACCESS.value,
            PrivacyFlag.NO_SECRET_USE.value,
            PrivacyFlag.NO_RAW_SECRET_EXPOSURE.value,
            PrivacyFlag.NO_UNKNOWN_CODE_EXECUTION.value,
            PrivacyFlag.LOCAL_ONLY_DEFAULT.value,
            PrivacyFlag.PROPRIETARY_CODE_CONFIDENTIAL.value,
        ],
        "legal_flags": [
            "License interpretation requires LEGALINT/human review.",
            "Authorship/blame claims require explicit authorized metadata and human review.",
        ],
        "unknowns": [
            "Deployed production commit/artifact unknown.",
            "Runtime middleware/feature flags unknown.",
            "Secret validity unknown.",
            "Vulnerability exploitability unknown.",
            "SBOM correspondence to deployed artifact unknown.",
            "CI actual execution history unavailable.",
        ],
        "knowledge_gaps": c.gaps,
        "recommended_next_actions": c.actions,
        "specialist_handoffs": c.handoffs,
        "recommendations": c.recommendations,
        "limitations": ["Synthetic sample corpus." if c.case.sample else "Provided local corpus; no live repository access.",
            "No unknown code execution or secret testing.",
            "Native findings are local analysis, not canonical verified facts.",
            "Source risk, documentation and SBOMs do not independently establish production behavior."] + c.validation_errors,
        "analyst_summary": summary,
        "dual_ai_review": dual,
        "code_graph": build_code_graph(c),
        "source_graph": build_source_graph(c),
        "source_dependency_graph": source_families,
        "replay_manifest": replay_manifest,
    }


# =====================================================================
# PIPELINES
# =====================================================================

def run_sample_pipeline() -> Dict[str, Any]:
    c = build_sample_codeint()
    return build_result(c, Status.PARTIAL)


def run_unconfigured_pipeline(case: Case) -> Dict[str, Any]:
    c = CodeInt(case)

    c.gaps.append(KnowledgeGap(
        id="GAP-NO-SOURCE",
        gap_type=GapType.DEPLOYED_VERSION_UNKNOWN,
        description="No authorized source corpus, repository snapshot, lockfile, SBOM, CI config, tests, or documentation is configured.",
        importance="HIGH",
        recommended_source="Provide authorized repository snapshot or sanitized local source corpus.",
        specialist="CODEINT",
        expected_information_value=0.95,
    ))

    c.actions = [NextAction(
        id="ACT-CONFIGURE-SOURCE",
        description=(
            "Configure authorized source-code inputs or supply sanitized local repository snapshot. "
            "Do not access private repos without authorization, use stolen credentials, test secrets, "
            "execute unknown code, or generate exploits."
        ),
        priority=1,
        privacy_impact="LOW",
        expected_gain=0.95,
        specialist=None,
        requires_human_approval=False,
    )]

    c.handoffs = []
    c.recommendations = []
    c.hypotheses = []

    dual = {
        "primary_code_analyst": "No source evidence available.",
        "independent_code_skeptic_issues": [
            "No repository/source corpus configured.",
            "No parser output available.",
            "No dependency/SBOM/reachability conclusion possible.",
            "No security finding can be validated.",
        ],
        "verdict": "INSUFFICIENT_EVIDENCE",
        "note": "No independent AI review was performed.",
    }

    summary = (
        "CODE UNRESOLVED: No configured source corpus. "
        "No files, functions, dependencies, secrets, vulnerabilities, authors, or deployments were fabricated. "
        "Provide authorized source or run sample mode."
    )

    result = build_result(c, Status.BLOCKED_CONFIGURATION)
    result["analyst_summary"] = summary
    dual.update(review_mode="DETERMINISTIC_CHECKLIST", independent_review_performed=False)
    result["dual_ai_review"] = dual
    return result


def blocked_policy_result(case: Case, violations: List[Dict[str, str]]) -> Dict[str, Any]:
    return {
        "case_id": case.case_id,
        "task_id": case.task_id,
        "objective": case.objective,
        "status": Status.BLOCKED_POLICY.value,
        "policy_violations": violations,
        "message": (
            "Prohibited source-code intelligence request detected. CODEINT supports authorized defensive, "
            "static-first source-code intelligence only. It does not access private repos without authorization, "
            "use/test secrets, execute unknown code, generate exploits/payloads, improve malware, bypass EDR/AV, "
            "create persistence, or tamper with repositories/CI."
        ),
        "lawful_alternatives": [
            "Analyze authorized/public/user-supplied source statically.",
            "Fingerprint and redact secret candidates; hand off exposure to CREDINT.",
            "Identify risky patterns and access-control gap candidates without exploit steps.",
            "Resolve dependencies/SBOM/provenance defensively.",
            "Require human approval for patches, disclosure, or consequential engineering decisions.",
        ],
        "privacy_flags": [
            PrivacyFlag.NO_SECRET_USE.value,
            PrivacyFlag.NO_UNKNOWN_CODE_EXECUTION.value,
            PrivacyFlag.NO_PRIVATE_REPO_ACCESS.value,
            PrivacyFlag.PROPRIETARY_CODE_CONFIDENTIAL.value,
        ],
        "limitations": [
            "No source-code analysis performed.",
            "No files/functions/dependencies fabricated.",
            "No secrets exposed or used.",
        ],
    }


def run_pipeline(case: Case) -> Dict[str, Any]:
    text = " ".join(
        [
            case.objective,
            *case.questions,
            *case.repositories,
            *case.commits,
            case.authorization or "",
            " ".join(case.scope),
        ]
    )
    violations = policy_guard(text)
    if violations:
        return blocked_policy_result(case, violations)

    if case.sample:
        return run_sample_pipeline()

    return run_unconfigured_pipeline(case)


# =====================================================================
# CLI
# =====================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "TRACEATLAS CODEINT local defensive static-first source-code intelligence pipeline. "
            "Sample mode uses synthetic authorized-repository-style data."
        )
    )
    parser.add_argument("--sample", action="store_true", help="Run built-in synthetic CODEINT sample.")
    parser.add_argument("--objective", help="Defensive source-code intelligence objective.")
    parser.add_argument("--question", action="append", default=[], help="Analytic question. Repeatable.")
    parser.add_argument("--repo", action="append", default=[], help="Repository ID. Repeatable.")
    parser.add_argument("--commit", action="append", default=[], help="Commit ID. Repeatable.")
    parser.add_argument("--time-range", help="Time range hint.")

    args = parser.parse_args()

    if args.sample or not args.objective:
        case = sample_case()
    else:
        case = Case(
            case_id=new_id("CASE-", args.objective),
            task_id=new_id("TASK-", args.objective),
            objective=args.objective,
            questions=args.question,
            repositories=args.repo,
            commits=args.commit,
            time_range=args.time_range,
            sample=False,
        )

    result = run_pipeline(case)
    print(json.dumps(jsonable(result), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

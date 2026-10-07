"""Shared trust-domain models: evidence, observations, facts, sources,
bias/reliability/independence assessments, insights and hypotheses.

These are real typed dataclasses with validation — not prompt templates.
Key invariants enforced here (§9): a Fact without evidence is NOT a Fact;
construction raises ``FactWithoutEvidenceError`` instead of silently allowing
unsupported "facts" into the pipeline.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm(text: str) -> str:
    """Normalise a statement for deduplication / contradiction matching."""
    return re.sub(r"\s+", " ", text.strip().lower().rstrip(".")).strip()


class TrustError(RuntimeError):
    """Base class for hard trust-pipeline violations."""


class FactWithoutEvidenceError(TrustError):
    """Raised when something is asserted as a Fact with no evidence ids."""


class HypothesisBeforeFactGateError(TrustError):
    """Raised when hypothesis generation is attempted before the Fact Gate."""


class ConfidenceLevel(str, Enum):
    VERY_LOW = "very_low"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    VERY_HIGH = "very_high"
    UNKNOWN = "unknown"


class ReliabilityLevel(str, Enum):
    """Qualitative source reliability (§11). Numeric scores are deliberately
    NOT fabricated — they would be fake precision unless calibrated."""

    VERY_LOW = "very_low"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    VERY_HIGH = "very_high"
    UNKNOWN = "unknown"


class BiasType(str, Enum):
    POLITICAL = "political_bias"
    COMMERCIAL = "commercial_bias"
    INSTITUTIONAL = "institutional_bias"
    ADVOCACY = "advocacy_bias"
    SELF_INTEREST = "self_interest"
    PROMOTIONAL = "promotional_bias"
    ADVERSARIAL = "adversarial_bias"
    SAMPLING = "sampling_bias"
    SURVIVORSHIP = "survivorship_bias"
    GEOGRAPHIC = "geographic_bias"
    LINGUISTIC = "linguistic_bias"
    TEMPORAL = "temporal_bias"
    PUBLICATION = "publication_bias"
    SOURCE_POSITION = "source_position"


class IndependenceStatus(str, Enum):
    INDEPENDENT = "independent"
    PARTIALLY_DEPENDENT = "partially_dependent"
    DEPENDENT = "dependent"
    UNKNOWN = "unknown"


class PrimaryOrSecondary(str, Enum):
    PRIMARY = "primary"
    SECONDARY = "secondary"
    UNKNOWN = "unknown"


class VerificationStatus(str, Enum):
    UNVALIDATED = "unvalidated"
    SUPPORTED = "supported"
    PARTIAL = "partial"
    DISPUTED = "disputed"
    INSUFFICIENT = "insufficient"
    REJECTED = "rejected"
    OBSERVATION_ONLY = "observation_only"


class FactDecision(str, Enum):
    ACCEPT_AS_SUPPORTED_FACT = "accept_as_supported_fact"
    ACCEPT_AS_PARTIAL_FACT = "accept_as_partial_fact"
    KEEP_AS_OBSERVATION = "keep_as_observation"
    DISPUTED = "disputed"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    REJECT = "reject"


class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    ACTIVE = "active"
    TESTING = "testing"
    STRENGTHENED = "strengthened"
    WEAKENED = "weakened"
    SUPPORTED = "supported"
    DISPUTED = "disputed"
    FALSIFIED = "falsified"
    INCONCLUSIVE = "inconclusive"
    ARCHIVED = "archived"


class ReviewOutcome(str, Enum):
    AGREE = "agree"
    PARTIAL_AGREEMENT = "partial_agreement"
    DISAGREE = "disagree"
    PASS1_ONLY = "pass1_only"
    PASS2_ONLY = "pass2_only"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


# --------------------------------------------------------------------- sources

@dataclass
class SourceRecord:
    """A captured source document with lineage information.

    ``upstream_source_id`` / ``publisher`` / ``fingerprint`` feed the
    independence analysis (§12): five copies of one upstream dataset must
    never become five independent confirmations.
    """

    title: str
    url: str = ""
    publisher: str = ""
    kind: str = "website"  # website|registry|archive|api|dataset|feed|social|document
    author_type: str = "unknown"  # first_party|government|commercial|media|advocacy|anonymous|researcher|unknown
    captured_at: str = field(default_factory=utcnow)
    event_time: str | None = None
    language: str = "en"
    country: str = ""
    upstream_source_id: str | None = None   # e.g. same newswire/dataset this derives from
    derived_from_id: str | None = None      # direct copy/quotation chain
    content_hash: str = ""
    id: str = field(default_factory=lambda: new_id("src"))

    def set_content(self, text: str) -> None:
        self.content_hash = hashlib.sha256(_norm(text).encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return to_jsonable(self)


@dataclass
class EvidenceRecord:
    """Raw captured bytes/artifact that observations can cite (§8: RAW DATA → EVIDENCE)."""

    description: str
    source_id: str
    artifact_hash: str = ""
    captured_by: str = ""       # employee id that captured it
    captured_at: str = field(default_factory=utcnow)
    media_type: str = "text"
    excerpt: str = ""
    id: str = field(default_factory=lambda: new_id("ev"))

    def to_dict(self) -> dict:
        return to_jsonable(self)


@dataclass
class Observation:
    """What an analyst directly observed in evidence. Analysis-grade, not yet fact."""

    statement: str
    evidence_ids: list[str] = field(default_factory=list)
    source_ids: list[str] = field(default_factory=list)
    entity_ids: list[str] = field(default_factory=list)
    employee_id: str = ""
    task_id: str = ""
    case_id: str = ""
    observed_at: str = field(default_factory=utcnow)
    id: str = field(default_factory=lambda: new_id("obs"))

    def __post_init__(self) -> None:
        if not self.evidence_ids:
            raise ValueError(f"Observation {self.statement!r} requires at least one evidence id")

    @property
    def normalized(self) -> str:
        return _norm(self.statement)

    def to_dict(self) -> dict:
        return to_jsonable(self)


# ------------------------------------------------------------------------ facts

@dataclass
class BiasAssessment:
    """§10 output. Explains incentives/limitations — never auto-discards."""

    source_id: str
    bias_types: list[BiasType] = field(default_factory=list)
    possible_incentives: list[str] = field(default_factory=list)
    known_limitations: list[str] = field(default_factory=list)
    primary_or_secondary: PrimaryOrSecondary = PrimaryOrSecondary.UNKNOWN
    independence_status: IndependenceStatus = IndependenceStatus.UNKNOWN
    reliability_factors: list[str] = field(default_factory=list)
    risk_level: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    explanation: str = ""
    id: str = field(default_factory=lambda: new_id("bias"))

    def to_dict(self) -> dict:
        return to_jsonable(self)


@dataclass
class ReliabilityAssessment:
    """§11 — kept separate from bias. Qualitative only; no fake numbers."""

    source_id: str
    level: ReliabilityLevel = ReliabilityLevel.UNKNOWN
    authority: str = ""
    proximity_to_event: str = ""
    primary_or_secondary: PrimaryOrSecondary = PrimaryOrSecondary.UNKNOWN
    freshness: str = ""
    transparency: str = ""
    methodology: str = ""
    corroboration: str = ""
    consistency: str = ""
    completeness: str = ""
    explanation: str = ""
    id: str = field(default_factory=lambda: new_id("rel"))

    def to_dict(self) -> dict:
        return to_jsonable(self)


@dataclass
class IndependenceAssessment:
    """§12 — clusters sources so dependent copies don't multiply confirmation."""

    source_ids: list[str] = field(default_factory=list)
    cluster_id: str = ""
    status: IndependenceStatus = IndependenceStatus.UNKNOWN
    shared_basis: str = ""  # same publisher / same upstream dataset / mirror / syndication...
    explanation: str = ""
    id: str = field(default_factory=lambda: new_id("ind"))

    def to_dict(self) -> dict:
        return to_jsonable(self)


@dataclass
class Fact:
    """§9. A Fact REQUIRES evidence ids and source ids. No evidence → not a fact."""

    statement: str
    case_id: str
    evidence_ids: list[str]
    source_ids: list[str]
    observation_ids: list[str] = field(default_factory=list)
    entity_ids: list[str] = field(default_factory=list)
    relationship_ids: list[str] = field(default_factory=list)
    event_time: str | None = None
    observed_at: str = field(default_factory=utcnow)
    retrieved_at: str = field(default_factory=utcnow)
    verification_status: VerificationStatus = VerificationStatus.UNVALIDATED
    source_independence: IndependenceStatus = IndependenceStatus.UNKNOWN
    independent_cluster_count: int = 0
    source_bias_assessment_ids: list[str] = field(default_factory=list)
    source_reliability: ReliabilityLevel = ReliabilityLevel.UNKNOWN
    limitations: list[str] = field(default_factory=list)
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    decision: FactDecision | None = None
    id: str = field(default_factory=lambda: new_id("fact"))

    def __post_init__(self) -> None:
        if not self.evidence_ids:
            raise FactWithoutEvidenceError(
                f"Fact {self.statement!r} has no evidence ids — not a fact (§9)"
            )
        if not self.source_ids:
            raise FactWithoutEvidenceError(
                f"Fact {self.statement!r} has no source ids — not a fact (§9)"
            )

    @property
    def normalized(self) -> str:
        return _norm(self.statement)

    def to_dict(self) -> dict:
        return to_jsonable(self)


@dataclass
class Insight:
    """§15 — analysis derived ONLY from gated facts. Insight is not a fact."""

    statement: str
    supporting_fact_ids: list[str]
    why_it_matters: str = ""
    scope: str = ""
    limitations: list[str] = field(default_factory=list)
    confidence: ConfidenceLevel = ConfidenceLevel.MODERATE
    importance: ConfidenceLevel = ConfidenceLevel.MODERATE
    case_id: str = ""
    id: str = field(default_factory=lambda: new_id("ins"))

    def __post_init__(self) -> None:
        if not self.supporting_fact_ids:
            raise ValueError(f"Insight {self.statement!r} must cite supporting fact ids")

    def to_dict(self) -> dict:
        return to_jsonable(self)


@dataclass
class Hypothesis:
    """§16. Consumes approved facts/observations only (enforced by the engine)."""

    question: str
    statement: str
    case_id: str
    supporting_facts: list[str] = field(default_factory=list)      # fact ids
    opposing_facts: list[str] = field(default_factory=list)
    supporting_observations: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    source_bias_effects: list[str] = field(default_factory=list)
    source_independence: IndependenceStatus = IndependenceStatus.UNKNOWN
    alternative_explanations: list[str] = field(default_factory=list)
    falsification_conditions: list[str] = field(default_factory=list)
    required_evidence: list[str] = field(default_factory=list)
    next_test: str = ""
    exploratory: bool = False   # True ⇒ built on insufficient facts; LOW-CONFIDENCE label forced
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    id: str = field(default_factory=lambda: new_id("hyp"))

    def __post_init__(self) -> None:
        if self.exploratory:
            # §8: with an empty/insufficient fact set, hypotheses may exist only
            # as explicitly-labelled LOW-CONFIDENCE exploratory hypotheses.
            self.confidence = ConfidenceLevel.LOW
            if "[EXPLORATORY" not in self.statement.upper():
                self.statement = f"[EXPLORATORY / LOW CONFIDENCE] {self.statement}"

    def to_dict(self) -> dict:
        return to_jsonable(self)


@dataclass
class Contradiction:
    """Two material statements that cannot both hold."""

    statement_a: str
    statement_b: str
    ref_a: str = ""
    ref_b: str = ""
    severity: ConfidenceLevel = ConfidenceLevel.MODERATE
    resolution: str = "open"  # open | resolved_a | resolved_b | both_retained | temporal_scope_differs
    case_id: str = ""
    id: str = field(default_factory=lambda: new_id("ctr"))

    def to_dict(self) -> dict:
        return to_jsonable(self)


def entity_ref(kind: str, value: str) -> str:
    """Stable deterministic reference for an entity mention (domain, IP, org...)."""
    h = hashlib.sha256(f"{kind}:{_norm(value)}".encode()).hexdigest()[:12]
    return f"{kind}_{h}"


def any_to_dict(obj: Any) -> dict:
    return to_jsonable(obj)

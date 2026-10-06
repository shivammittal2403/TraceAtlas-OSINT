"""QuerySpec: provider-neutral intermediate query representation (§26).

A QuerySpec captures *intent* (terms, exclusions, site constraint, filetypes,
date range...). It is NOT a search string. Each provider's compiler translates
a QuerySpec into engine-specific syntax, dropping/translating operators the
engine does not support — never blindly pasting Google dorks everywhere (§5).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from traceatlas.core.identifiers import new_id

ExecutionMode = Literal["EXHAUSTIVE", "BALANCED", "FAST", "VERIFICATION", "CUSTOM"]
RunStatus = Literal["QUEUED", "RUNNING", "RATE_LIMITED", "PARTIAL", "COMPLETED",
                    "FAILED", "SKIPPED", "POLICY_BLOCKED"]


@dataclass
class DateRange:
    after: str = ""   # ISO date, inclusive lower bound (event/publication time)
    before: str = ""  # ISO date, inclusive upper bound


@dataclass
class QuerySpec:
    """Generic, engine-independent query intent (§26)."""
    terms: list[str] = field(default_factory=list)
    exact_terms: list[str] = field(default_factory=list)
    excluded_terms: list[str] = field(default_factory=list)
    site: str = ""                                  # domain-limited search
    filetypes: list[str] = field(default_factory=list)
    title_terms: list[str] = field(default_factory=list)
    url_terms: list[str] = field(default_factory=list)
    body_terms: list[str] = field(default_factory=list)
    date_range: DateRange | None = None
    language: str = ""
    region: str = ""
    entity_type: str = ""            # ORGANIZATION | PERSON | DOMAIN | CVE | ...
    objective: str = ""              # why this query exists (§27)
    hypothesis_tested: str = ""      # hypothesis id for §22 hypothesis-driven dorking
    falsification_query: bool = False  # §22: query designed to DISPROVE, not confirm
    required_source_type: str = ""   # web | code | archive | social | news | academic
    priority: float = 0.5            # 0..1 planner score (§7)

    def signature(self) -> str:
        """Stable semantic signature used for dedup of equivalent queries (§28)."""
        parts = [
            ",".join(sorted(t.lower() for t in self.terms)),
            ",".join(sorted(t.lower() for t in self.exact_terms)),
            ",".join(sorted(t.lower() for t in self.excluded_terms)),
            self.site.lower(),
            ",".join(sorted(f.lower().lstrip(".") for f in self.filetypes)),
            ",".join(sorted(t.lower() for t in self.title_terms)),
            ",".join(sorted(t.lower() for t in self.url_terms)),
            ",".join(sorted(t.lower() for t in self.body_terms)),
            (f"{self.date_range.after}~{self.date_range.before}" if self.date_range else ""),
            self.language.lower(), self.region.lower(),
        ]
        return "|".join(parts)

    def is_empty(self) -> bool:
        return not (self.terms or self.exact_terms or self.site
                    or self.title_terms or self.url_terms or self.body_terms)

    def to_dict(self) -> dict:
        return {
            "terms": self.terms, "exact_terms": self.exact_terms,
            "excluded_terms": self.excluded_terms, "site": self.site,
            "filetypes": self.filetypes, "title_terms": self.title_terms,
            "url_terms": self.url_terms, "body_terms": self.body_terms,
            "date_range": ({"after": self.date_range.after,
                             "before": self.date_range.before}
                           if self.date_range else None),
            "language": self.language, "region": self.region,
            "entity_type": self.entity_type, "objective": self.objective,
            "hypothesis_tested": self.hypothesis_tested,
            "falsification_query": self.falsification_query,
            "required_source_type": self.required_source_type,
            "priority": self.priority,
        }


@dataclass
class CompiledQuery:
    """A QuerySpec compiled for one specific provider (§26)."""
    provider_id: str
    query_string: str
    supported_ops: list[str] = field(default_factory=list)
    dropped_ops: list[str] = field(default_factory=list)   # translated away (§5)
    params: dict = field(default_factory=dict)             # API params beyond string
    valid: bool = True
    invalid_reason: str = ""

    def to_dict(self) -> dict:
        return {"provider_id": self.provider_id, "query_string": self.query_string,
                "supported_ops": self.supported_ops, "dropped_ops": self.dropped_ops,
                "params": self.params, "valid": self.valid,
                "invalid_reason": self.invalid_reason}


@dataclass
class PlannedQuery:
    """One logical query inside a plan, with its family and scoring metadata."""
    query_id: str
    spec: QuerySpec
    family: str = ""                 # e.g. DOCUMENT_PDF, INFRASTRUCTURE
    purpose: str = ""                # human-readable reason (§9)
    expected_value: float = 0.5      # information-gain score (§7)
    source_uniqueness: float = 0.5   # expected new-source coverage
    cost_estimate: float = 0.0       # arbitrary cost units from budget model
    wave: int = 0                    # iteration number (feedback loop §21)
    follow_up_of: str = ""           # parent query id for discovered-entity follow-ups
    tags: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: new_id("qry"))

    def to_dict(self) -> dict:
        return {"query_id": self.query_id, "id": self.id, "family": self.family,
                "purpose": self.purpose, "expected_value": self.expected_value,
                "source_uniqueness": self.source_uniqueness,
                "cost_estimate": self.cost_estimate, "wave": self.wave,
                "follow_up_of": self.follow_up_of, "tags": self.tags,
                "spec": self.spec.to_dict()}

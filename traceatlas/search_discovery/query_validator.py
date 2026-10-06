"""Deterministic query validation + dedup + prioritization + budget (§7, §27, §28).

AI-proposed queries are treated as UNTRUSTED INPUT: they execute only after
passing the same deterministic validator and safety policy as generated ones.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from traceatlas.search_discovery.dorks.safe_policy import check_query_safety
from traceatlas.search_discovery.query import PlannedQuery, QuerySpec
from traceatlas.search_discovery.query_builder import _safe

_DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]+(\.[a-z0-9-]+)+$")
_MAX_TERMS = 12


@dataclass
class ValidationReport:
    ok: list[PlannedQuery] = field(default_factory=list)
    rejected: list[tuple[PlannedQuery, str]] = field(default_factory=list)
    downgraded: list[tuple[PlannedQuery, str]] = field(default_factory=list)


def validate_query(pq: PlannedQuery) -> tuple[bool, str]:
    """Deterministic checks before execution (§27/§28). Returns (ok, reason)."""
    s = pq.spec
    if s.is_empty():
        return False, "empty query: no terms/site/title/url/body constraints"
    n_terms = len(s.terms) + len(s.exact_terms) + len(s.body_terms)
    if n_terms > _MAX_TERMS:
        return False, f"overly complex query ({n_terms} terms) — likely noise"
    for t in (s.terms + s.exact_terms + s.excluded_terms + s.title_terms
              + s.url_terms + s.body_terms):
        if not _safe(t):
            return False, f"unsafe or malformed term: {t!r}"
    if s.site and not _DOMAIN_RE.match(s.site.lower()):
        return False, f"invalid site domain: {s.site!r}"
    for ft in s.filetypes:
        if not re.match(r"^[a-z0-9]{1,6}$", ft.lower().lstrip(".")):
            return False, f"invalid filetype: {ft!r}"
    if s.date_range:
        for d in (s.date_range.after, s.date_range.before):
            if d and not re.match(r"^\d{4}-\d{2}-\d{2}$", d):
                return False, f"invalid date: {d!r}"
        if s.date_range.after and s.date_range.before and \
                s.date_range.after > s.date_range.before:
            return False, "date range inverted (impossible window)"
    # single generic word with no constraint is too broad (§28)
    if len(s.terms) == 1 and not (s.exact_terms or s.site or s.filetypes
                                  or s.title_terms or s.url_terms
                                  or s.body_terms or s.date_range):
        tok = s.terms[0].lower()
        if len(tok.split()) == 1 and len(tok) <= 6:
            return False, "overly broad single-word query"
    # scope check via compiled preview against safety policy (§45)
    preview = " ".join(s.exact_terms + s.terms + s.excluded_terms
                       + ([f"site:{s.site}"] if s.site else []))
    decision = check_query_safety(preview, family=pq.family)
    if not decision.allowed:
        return False, f"policy blocked: {decision.reason}"
    return True, ""


def deduplicate_queries(queries: list[PlannedQuery]) -> list[PlannedQuery]:
    """Drop exact-signature and near-identical semantic duplicates (§28)."""
    seen: dict[str, PlannedQuery] = {}
    out: list[PlannedQuery] = []
    for q in queries:
        sig = q.spec.signature()
        prev = seen.get(sig)
        if prev is None:
            seen[sig] = q
            out.append(q)
        else:
            # keep the higher-value variant, record nothing destructive
            if q.expected_value > prev.expected_value:
                out[out.index(prev)] = q
                seen[sig] = q
    return out


def prioritize(queries: list[PlannedQuery], *, mode: str = "BALANCED"
               ) -> list[PlannedQuery]:
    """Score-order queries; mode controls how aggressively we prune (§8)."""
    scored = sorted(queries, key=lambda q: (-(q.expected_value * 0.7
                                              + q.spec.priority * 0.3),
                                            q.family))
    if mode == "FAST":
        return scored[: max(5, len(scored) // 4)]
    if mode == "VERIFICATION":
        return [q for q in scored
                if q.spec.hypothesis_tested or "verification" in q.tags] or scored
    if mode == "EXHAUSTIVE":
        return scored
    return scored  # BALANCED/CUSTOM: full list, value-ordered


@dataclass
class QueryBudget:
    """Cost/quota plan executed by the scheduler (§8, §41)."""
    max_queries: int = 200
    max_provider_calls: int = 600
    max_cost_units: float = 100.0
    spent_calls: int = 0
    spent_cost: float = 0.0

    def can_afford(self, provider_cost: float, pages: int = 1) -> bool:
        return (self.spent_calls + pages <= self.max_provider_calls
                and self.spent_cost + provider_cost * pages <= self.max_cost_units)

    def consume(self, provider_cost: float, pages: int = 1) -> None:
        self.spent_calls += pages
        self.spent_cost += provider_cost * pages

    def exhausted(self) -> bool:
        return self.spent_calls >= self.max_provider_calls or \
            self.spent_cost >= self.max_cost_units

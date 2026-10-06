"""Search result + evidence-capture models (§10, §15, §16).

Key invariants:
- A search-result hit is *retrieval observation* evidence; the page it points
  to is separate content evidence. Snippets are never treated as full evidence
  when the source can be retrieved lawfully (§10).
- The same document found via 4 engines becomes ONE evidence cluster with FOUR
  retrieval observations — never four confirmations (§15/§16, §44).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal
from urllib.parse import urldefrag, urlsplit

from traceatlas.core.identifiers import new_id
from traceatlas.core.validation import utcnow

ResultStatus = Literal["NEW", "DUPLICATE", "POLICY_BLOCKED", "ACQUIRED",
                       "ACQUISITION_FAILED"]

IndependenceClass = Literal["INDEPENDENT", "PARTIALLY_DEPENDENT",
                            "DEPENDENT", "UNKNOWN"]


def normalize_url(url: str) -> str:
    """Canonical URL for dedup: lowercase scheme/host, strip fragment, default
    www., trailing slash and utm_* tracking params (§15)."""
    if not url:
        return ""
    url, _frag = urldefrag(url.strip())
    parts = urlsplit(url.lower())
    scheme = parts.scheme or "http"
    host = parts.netloc
    if host.startswith("www."):
        host = host[4:]
    path = re.sub(r"/+$", "", parts.path) or "/"
    qp = []
    for pair in (parts.query.split("&") if parts.query else []):
        if not pair:
            continue
        key = pair.split("=")[0]
        if key.startswith("utm_") or key in ("gclid", "ref_src"):
            continue
        qp.append(pair)
    query = "&".join(sorted(qp))
    return f"{scheme}://{host}{path}" + (f"?{query}" if query else "")


def content_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalized_fingerprint(title: str, snippet: str) -> str:
    """Content fingerprint independent of URL (catches mirrors/syndication)."""
    text = " ".join(f"{title} {snippet}".lower().split())
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()[:32]


@dataclass
class RetrievalObservation:
    """One engine seeing one document. Four engines => four observations,
    still ONE underlying evidence item."""
    provider: str
    query_id: str
    rank: int = 0
    retrieved_at: datetime = field(default_factory=utcnow)
    raw_title: str = ""
    raw_snippet: str = ""

    def to_dict(self) -> dict:
        return {"provider": self.provider, "query_id": self.query_id,
                "rank": self.rank, "retrieved_at": self.retrieved_at.isoformat(),
                "raw_title": self.raw_title, "raw_snippet": self.raw_snippet}


@dataclass
class SearchResult:
    """Normalized result row (§10). Ties a retrieval observation to its
    deduplicated evidence cluster."""
    result_id: str
    query_id: str
    provider: str
    rank: int = 0
    title: str = ""
    url: str = ""
    display_url: str = ""
    snippet: str = ""
    published_at: str = ""          # source-stated publication time (may be absent)
    retrieved_at: datetime = field(default_factory=utcnow)
    language: str = ""
    source_domain: str = ""
    content_type: str = "web"       # web | code | document | social | archive | paste
    status: ResultStatus = "NEW"
    evidence_id: str = ""           # cluster this result maps to
    duplicate_of_result_id: str = ""
    content_hash: str = ""
    normalized_hash: str = ""       # normalized URL hash
    fingerprint: str = ""           # near-dup content fingerprint

    def __post_init__(self) -> None:
        if not self.source_domain and self.url:
            host = urlsplit(self.url).netloc.lower()
            self.source_domain = host[4:] if host.startswith("www.") else host
        if not self.normalized_hash and self.url:
            self.normalized_hash = hashlib.sha256(
                normalize_url(self.url).encode()).hexdigest()[:32]
        if not self.fingerprint:
            self.fingerprint = normalized_fingerprint(self.title, self.snippet)

    def to_dict(self) -> dict:
        return {
            "result_id": self.result_id, "query_id": self.query_id,
            "provider": self.provider, "rank": self.rank, "title": self.title,
            "url": self.url, "display_url": self.display_url,
            "snippet": self.snippet, "published_at": self.published_at,
            "retrieved_at": self.retrieved_at.isoformat(), "language": self.language,
            "source_domain": self.source_domain, "content_type": self.content_type,
            "status": self.status, "evidence_id": self.evidence_id,
            "duplicate_of_result_id": self.duplicate_of_result_id,
            "content_hash": self.content_hash,
            "normalized_hash": self.normalized_hash,
            "fingerprint": self.fingerprint,
        }


@dataclass
class EvidenceCluster:
    """Deduplicated document-level evidence with full retrieval provenance."""
    cluster_id: str
    canonical_url: str
    publisher_domain: str
    upstream_source_id: str = ""        # lineage: original author/publisher (§16)
    observations: list[RetrievalObservation] = field(default_factory=list)
    member_result_ids: list[str] = field(default_factory=list)
    content_sha256: str = ""            # set once page content captured
    raw_bytes: bytes = b""              # preserved raw capture (§11)
    captured_at: datetime | None = None
    independence: IndependenceClass = "UNKNOWN"
    duplicate_provenance: list[dict] = field(default_factory=list)  # never deleted (§15)

    @property
    def distinct_providers(self) -> set[str]:
        return {o.provider for o in self.observations}

    def to_dict(self) -> dict:
        return {
            "cluster_id": self.cluster_id, "canonical_url": self.canonical_url,
            "publisher_domain": self.publisher_domain,
            "upstream_source_id": self.upstream_source_id,
            "observations": [o.to_dict() for o in self.observations],
            "member_result_ids": self.member_result_ids,
            "content_sha256": self.content_sha256,
            "size_bytes": len(self.raw_bytes),
            "captured_at": self.captured_at.isoformat() if self.captured_at else None,
            "independence": self.independence,
            "distinct_provider_count": len(self.distinct_providers),
            "duplicate_provenance": self.duplicate_provenance,
        }


def _shingles(text: str, k: int) -> set[str]:
    toks = text.lower().split()
    if len(toks) < k:
        return {" ".join(toks)} if toks else set()
    return {" ".join(toks[i:i + k]) for i in range(len(toks) - k + 1)}


def shingle_jaccard(a: str, b: str, k: int = 5) -> float:
    """Near-duplicate detection over whitespace-normalized text (§15 shingling)."""
    sa, sb = _shingles(a, k), _shingles(b, k)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


NEAR_DUP_THRESHOLD = 0.85

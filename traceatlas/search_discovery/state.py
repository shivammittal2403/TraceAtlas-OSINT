"""Persistent state containers for one search/discovery session (§9, §15, §16).

QueryMatrix is the auditable query/engine table; ResultStore performs URL /
content-hash / near-duplicate dedup preserving full provenance; the store also
computes source-independence classes over evidence clusters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from traceatlas.core.identifiers import new_id
from traceatlas.core.validation import utcnow
from traceatlas.search_discovery.query import PlannedQuery, RunStatus
from traceatlas.search_discovery.result import (EvidenceCluster,
                                                 NEAR_DUP_THRESHOLD,
                                                 RetrievalObservation,
                                                 SearchResult,
                                                 normalize_url, shingle_jaccard)


@dataclass
class MatrixRow:
    """One query x engine cell of the QUERY/ENGINE MATRIX (§9)."""
    row_id: str = field(default_factory=lambda: new_id("mtx"))
    query_id: str = ""
    query_family: str = ""
    compiled_query: str = ""
    generic_query: dict = field(default_factory=dict)
    engine: str = ""
    reason: str = ""                 # why this engine for this query (§25)
    priority: float = 0.0
    expected_value: float = 0.0
    authorization: str = "public"    # authorized scope tag
    status: RunStatus = "QUEUED"
    started_at: datetime | None = None
    finished_at: datetime | None = None
    result_count: int = 0
    new_unique_results: int = 0
    duplicate_results: int = 0
    errors: list[str] = field(default_factory=list)
    cost: float = 0.0
    latency_ms: float = 0.0
    pages_fetched: int = 0
    dropped_ops: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {k: (v.isoformat() if isinstance(v, datetime) else v)
                for k, v in self.__dict__.items()}


class QueryMatrix:
    def __init__(self) -> None:
        self.rows: list[MatrixRow] = []

    def add(self, row: MatrixRow) -> MatrixRow:
        self.rows.append(row)
        return row

    def for_query(self, query_id: str) -> list[MatrixRow]:
        return [r for r in self.rows if r.query_id == query_id]

    def counts_by_status(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.rows:
            out[r.status] = out.get(r.status, 0) + 1
        return out

    def to_rows_dicts(self) -> list[dict]:
        return [r.to_dict() for r in self.rows]


class ResultStore:
    """Deduplicating evidence store (§15, §16).

    Three-layer dedup: normalized URL -> content SHA-256 -> near-duplicate
    shingle fingerprint. Duplicates never delete evidence; they append a
    retrieval observation to the existing cluster and record provenance.
    """

    def __init__(self) -> None:
        self.clusters: dict[str, EvidenceCluster] = {}
        self.results: dict[str, SearchResult] = {}
        self._by_norm_hash: dict[str, str] = {}       # url hash -> cluster id
        self._by_content: dict[str, str] = {}         # sha256 -> cluster id
        self._by_fingerprint: dict[str, str] = {}     # exact title+snippet fp
        self.new_evidence_count = 0
        self.duplicate_count = 0

    # ------------------------------------------------------------- ingest
    def add_result(self, result: SearchResult) -> tuple[SearchResult, bool]:
        """Return (result, is_new_cluster). Sets result.evidence_id."""
        existing = (self._by_norm_hash.get(result.normalized_hash)
                    or self._by_fingerprint.get(result.fingerprint))
        if existing:
            cluster = self.clusters[existing]
            cluster.observations.append(RetrievalObservation(
                provider=result.provider, query_id=result.query_id,
                rank=result.rank, raw_title=result.title,
                raw_snippet=result.snippet))
            cluster.member_result_ids.append(result.result_id)
            cluster.duplicate_provenance.append({
                "url": result.url, "provider": result.provider,
                "query_id": result.query_id, "reason": "normalized_url_or_fingerprint"})
            result.status = "DUPLICATE"
            result.evidence_id = existing
            result.duplicate_of_result_id = cluster.member_result_ids[0]
            self.duplicate_count += 1
        else:
            cluster = EvidenceCluster(
                cluster_id=new_id("clu"),
                canonical_url=normalize_url(result.url),
                publisher_domain=result.source_domain)
            cluster.observations.append(RetrievalObservation(
                provider=result.provider, query_id=result.query_id,
                rank=result.rank, raw_title=result.title,
                raw_snippet=result.snippet))
            cluster.member_result_ids.append(result.result_id)
            # near-dup check against existing clusters by content shingles
            probe = f"{result.title} {result.snippet}"
            for cid, cl in self.clusters.items():
                if cl.publisher_domain == cluster.publisher_domain:
                    continue
                other = " ".join(f"{o.raw_title} {o.raw_snippet}"
                                 for o in cl.observations[:3])
                if other and shingle_jaccard(probe, other) >= NEAR_DUP_THRESHOLD:
                    # mirror/syndication: fold into existing cluster (§15)
                    cl.observations.extend(cluster.observations)
                    cl.member_result_ids.append(result.result_id)
                    cl.duplicate_provenance.append({
                        "url": result.url, "provider": result.provider,
                        "query_id": result.query_id, "reason": "near_duplicate_shingles",
                        "jaccard": round(shingle_jaccard(probe, other), 3)})
                    result.status = "DUPLICATE"
                    result.evidence_id = cid
                    self._by_norm_hash[result.normalized_hash] = cid
                    self._by_fingerprint[result.fingerprint] = cid
                    self.results[result.result_id] = result
                    self.duplicate_count += 1
                    return result, False
            self.clusters[cluster.cluster_id] = cluster
            self._by_norm_hash[result.normalized_hash] = cluster.cluster_id
            self._by_fingerprint[result.fingerprint] = cluster.cluster_id
            result.status = "NEW"
            result.evidence_id = cluster.cluster_id
            self.new_evidence_count += 1
        self.results[result.result_id] = result
        return result, result.status == "NEW"

    def attach_content(self, cluster_id: str, raw: bytes, *,
                       upstream_source_id: str = "") -> str:
        """Record captured page bytes; hash-level dedup merges copies (§15)."""
        import hashlib
        digest = hashlib.sha256(raw).hexdigest()
        cluster = self.clusters[cluster_id]
        twin = self._by_content.get(digest)
        if twin and twin != cluster_id:
            target = self.clusters[twin]
            target.observations.extend(cluster.observations)
            target.duplicate_provenance.append({
                "url": cluster.canonical_url, "reason": "identical_content_sha256",
                "merged_cluster": cluster_id})
            cluster.content_sha256 = digest
            cluster.raw_bytes = b""
            cluster.independence = "DEPENDENT"
            self._by_norm_hash = {k: (twin if v == cluster_id else v)
                                  for k, v in self._by_norm_hash.items()}
            for rid in cluster.member_result_ids:
                self.results[rid].evidence_id = twin
            return twin
        cluster.raw_bytes = raw
        cluster.content_sha256 = digest
        cluster.captured_at = utcnow()
        if upstream_source_id:
            cluster.upstream_source_id = upstream_source_id
        self._by_content[digest] = cluster_id
        return cluster_id

    # ----------------------------------------------------- independence (§16)
    def classify_independence(self) -> dict[str, str]:
        """Publisher/upstream-based independence over clusters.

        Same publisher domain OR same upstream lineage => DEPENDENT even if
        found via many engines. Engines are retrieval channels, not sources.
        """
        by_upstream: dict[str, list[str]] = {}
        for cid, cl in self.clusters.items():
            key = cl.upstream_source_id or f"domain:{cl.publisher_domain}"
            by_upstream.setdefault(key, []).append(cid)
        report: dict[str, str] = {}
        for key, ids in by_upstream.items():
            if len(ids) == 1:
                cls = "INDEPENDENT"
            elif all(self.clusters[i].publisher_domain ==
                     self.clusters[ids[0]].publisher_domain for i in ids):
                cls = "DEPENDENT"          # mirrors/copies of one publisher
            else:
                cls = "PARTIALLY_DEPENDENT"  # syndication across domains
            for i in ids:
                self.clusters[i].independence = cls
                report[i] = cls
        return report

    def independent_confirmation_count(self, cluster_id: str) -> int:
        """How many INDEPENDENT clusters share the same upstream lineage —
        never count engines (§16)."""
        cl = self.clusters.get(cluster_id)
        if not cl:
            return 0
        key = cl.upstream_source_id or f"domain:{cl.publisher_domain}"
        return sum(1 for c in self.clusters.values()
                   if (c.upstream_source_id or f"domain:{c.publisher_domain}") == key)

    def snapshot(self) -> dict:
        return {"clusters": {cid: cl.to_dict() for cid, cl in self.clusters.items()},
                "results": {rid: r.to_dict() for rid, r in self.results.items()},
                "new_evidence_count": self.new_evidence_count,
                "duplicate_count": self.duplicate_count}

"""Source independence clustering (§12).

Five dependent sources cannot become five independent confirmations.
Clusters sources sharing: upstream dataset, publisher, direct derivation,
identical content hash (mirror/exact copy) or quotation chain.
"""

from __future__ import annotations

from collections import defaultdict

from traceatlas.trust.case_memory import CaseMemory
from traceatlas.trust.model import IndependenceAssessment, IndependenceStatus


def _root(parent_map: dict[str, str | None], node: str) -> str:
    seen: set[str] = set()
    while parent_map.get(node) and node not in seen:
        seen.add(node)
        nxt = parent_map[node]
        if nxt is None:
            break
        node = nxt
    return node


def cluster_sources(source_ids: list[str], memory: CaseMemory) -> list[IndependenceAssessment]:
    """Union-find over lineage edges: derived_from / upstream / same publisher /
    identical content hash."""
    parent: dict[str, str | None] = {sid: None for sid in source_ids}

    def union(a: str, b: str) -> None:
        ra, rb = _root(parent, a), _root(parent, b)
        if ra != rb:
            parent[rb] = ra

    by_id = {sid: memory.sources.get(sid) for sid in source_ids}
    for sid in source_ids:
        s = by_id[sid]
        if s is None:
            continue
        if s.derived_from_id in parent:
            union(sid, s.derived_from_id)
        if s.upstream_source_id in parent:
            union(sid, s.upstream_source_id)

    # same publisher ⇒ dependent copies of each other's reporting
    pub_groups: dict[str, list[str]] = defaultdict(list)
    for sid in source_ids:
        s = by_id[sid]
        if s and s.publisher:
            pub_groups[s.publisher.lower()].append(sid)
    for group in pub_groups.values():
        for other in group[1:]:
            union(group[0], other)

    # identical normalized content ⇒ mirror / exact copy
    hash_groups: dict[str, list[str]] = defaultdict(list)
    for sid in source_ids:
        s = by_id[sid]
        if s and s.content_hash:
            hash_groups[s.content_hash].append(sid)
    for group in hash_groups.values():
        for other in group[1:]:
            union(group[0], other)

    clusters: dict[str, list[str]] = defaultdict(list)
    for sid in source_ids:
        clusters[_root(parent, sid)].append(sid)

    assessments: list[IndependenceAssessment] = []
    for root, members in clusters.items():
        basis_bits = []
        for m in members:
            s = by_id[m]
            if s is None:
                continue
            if s.upstream_source_id in members:
                basis_bits.append(f"{m} derives from upstream dataset {s.upstream_source_id}")
            if s.derived_from_id in members:
                basis_bits.append(f"{m} is a copy/quotation of {s.derived_from_id}")
        status = (IndependenceStatus.INDEPENDENT if len(members) == 1
                  else IndependenceStatus.DEPENDENT)
        assessments.append(IndependenceAssessment(
            source_ids=sorted(members),
            cluster_id=f"cluster_{root[-12:]}",
            status=status,
            shared_basis="; ".join(sorted(set(basis_bits))) or (
                "single source" if len(members) == 1 else "same publisher/content"),
            explanation=(f"{len(members)} source(s) collapse to one independent cluster"
                         if len(members) > 1 else "independent single-source cluster"),
        ))
    return assessments


def independent_cluster_count(source_ids: list[str], memory: CaseMemory) -> int:
    return sum(1 for a in cluster_sources(source_ids, memory)
               if a.status in (IndependenceStatus.INDEPENDENT,
                               IndependenceStatus.PARTIALLY_DEPENDENT))


def check_independence(source_ids: list[str], memory: CaseMemory
                       ) -> tuple[IndependenceStatus, int, list[IndependenceAssessment]]:
    assessments = cluster_sources(source_ids, memory)
    n_clusters = len(assessments)
    if n_clusters <= 1:
        status = (IndependenceStatus.DEPENDENT if len(source_ids) > 1
                  else IndependenceStatus.UNKNOWN)
    elif n_clusters < len(source_ids):
        status = IndependenceStatus.PARTIALLY_DEPENDENT
    else:
        status = IndependenceStatus.INDEPENDENT
    for a in assessments:
        existing = next((x for x in memory.independence_assessments.values()
                         if sorted(x.source_ids) == sorted(a.source_ids)), None)
        if existing is None:
            memory.add_assessment(a)
    return status, n_clusters, assessments

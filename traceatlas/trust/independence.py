"""Standalone source-independence API (§12) re-exporting the gate clustering.

Kept as its own module so Trust employees (Source Independence Analyst) and the
hypothesis engine can call it without importing the gate internals.
"""

from __future__ import annotations

from traceatlas.trust.case_memory import CaseMemory
from traceatlas.trust.fact_gate.independence_check import (
    check_independence,
    cluster_sources,
    independent_cluster_count,
)
from traceatlas.trust.model import IndependenceStatus


def independent_support(source_ids: list[str], memory: CaseMemory) -> dict:
    """§20 output shape: raw supports vs independent clusters."""
    status, n_clusters, assessments = check_independence(source_ids, memory)
    return {
        "raw_source_documents": len(source_ids),
        "independent_clusters": n_clusters,
        "status": status.value,
        "clusters": [{"cluster_id": a.cluster_id, "members": a.source_ids,
                      "basis": a.shared_basis} for a in assessments],
        "note": ("dependent copies collapsed: N sources ≠ N independent confirmations"
                 if n_clusters < len(source_ids) else "all cited sources are independent"),
    }


__all__ = ["check_independence", "cluster_sources", "independent_cluster_count",
           "independent_support", "IndependenceStatus"]

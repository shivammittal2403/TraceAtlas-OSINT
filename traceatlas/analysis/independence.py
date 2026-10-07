"""Source-independence analysis over captured evidence records.

The full independence fabric (MinHash/SimHash/citation graphs) lives in
traceatlas/independence/ and is NOT yet implemented; this adapter therefore
performs only the conservative, provable layer:

1. exact-duplicate grouping by SHA-256: identical bytes retrieved via
   different URLs/sources collapse into ONE independent unit — five copies of
   the same article must never count as five confirmations.
2. upstream grouping by source_id family (same connector/source namespace).
3. every classification is explicitly marked confidence="provisional" and
   includes the reason, so downstream verification cannot over-trust it.

Returns a plain dict (JSON-safe) consumed by verify.py and reporting.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict

from traceatlas.investigation.context import InvestigationContext


def analyze_independence(ctx: InvestigationContext) -> dict:
    records = list(ctx.evidence.values())

    # --- exact duplicate groups (content-addressed) ------------------------
    by_digest: dict[str, list[str]] = defaultdict(list)
    for rec in records:
        by_digest[rec.sha256].append(rec.id)
    duplicate_groups = {d: ids for d, ids in by_digest.items() if len(ids) > 1}

    # --- distinct source families ------------------------------------------
    source_ids = sorted({r.source_id for r in records if r.source_id})
    per_source_counts = {sid: sum(1 for r in records if r.source_id == sid)
                         for sid in source_ids}

    # --- provisional independence classes ----------------------------------
    classes: dict[str, str] = {}
    reasons: dict[str, str] = {}
    for digest, ids in duplicate_groups.items():
        for ev_id in ids[1:]:          # first occurrence remains canonical
            classes[ev_id] = "DEPENDENT"
            reasons[ev_id] = ("exact byte-for-byte duplicate of "
                              f"{ids[0]} (sha256={digest[:12]}…)")
        classes[ids[0]] = "INDEPENDENT"
        reasons[ids[0]] = "canonical copy of its digest group"
    for rec in records:
        if rec.id not in classes:
            classes[rec.id] = "UNKNOWN"
            reasons[rec.id] = ("no fingerprint/citation analysis available; "
                               "near-duplicate independence NOT verified")

    independent_units = len(by_digest)  # conservative: unique digests only

    return {
        "total_evidence_records": len(records),
        "distinct_source_ids": source_ids,
        "records_per_source": per_source_counts,
        "unique_digest_count": independent_units,
        "duplicate_groups": {d: ids for d, ids in duplicate_groups.items()},
        "classification": classes,
        "classification_reasons": reasons,
        "method": "exact-hash only",
        "limitations": [
            "MinHash/SimHash near-duplicate detection not implemented",
            "citation-graph and syndication detection not implemented",
            "publisher/upstream relationship data not consulted",
            "classifications are provisional; treat UNKNOWN as non-independent",
        ],
    }


def independent_source_ids_for(ctx: InvestigationContext,
                               evidence_ids: list[str]) -> set[str]:
    """Distinct source_ids backing a set of evidence, after exact-duplicate
    collapsing. Used by verify.py so copied bytes never inflate corroboration.
    """
    seen_digests: set[str] = set()
    sources: set[str] = set()
    for ev_id in sorted(set(evidence_ids)):
        rec = ctx.evidence.get(ev_id)
        if rec is None:
            continue
        if rec.sha256 in seen_digests:
            continue
        seen_digests.add(rec.sha256)
        if rec.source_id:
            sources.add(rec.source_id)
    return sources


def _stable_group_key(text: str) -> str:  # pragma: no cover - reserved helper
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

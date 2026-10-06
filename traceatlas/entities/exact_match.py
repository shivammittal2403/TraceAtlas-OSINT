"""Exact-match candidate generation over normalized keys."""

from __future__ import annotations

from typing import Iterable


def exact_matches(records: Iterable[dict], key_field: str) -> list[tuple[str, str]]:
    """Group record ids sharing an identical normalized key value."""
    by_key: dict[str, list[str]] = {}
    for rec in records:
        k = str(rec.get(key_field, "")).strip().lower()
        rid = rec.get("id", "")
        if k and rid:
            by_key.setdefault(k, []).append(rid)
    pairs: list[tuple[str, str]] = []
    for ids in by_key.values():
        ids = sorted(set(ids))
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                pairs.append((ids[i], ids[j]))
    return pairs

"""Fuzzy name similarity via token Jaccard (bounded, explainable)."""

from __future__ import annotations

import re

_STOPWORDS = {"mr", "mrs", "ms", "dr", "inc", "llc", "ltd", "the", "of"}


def _tokens(name: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9']+", name.lower()) if t and t not in _STOPWORDS}


def jaccard_similarity(a: str, b: str) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def fuzzy_pairs(names: list[tuple[str, str]], threshold: float = 0.5) -> list[tuple[str, str, float]]:
    out = []
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            sim = jaccard_similarity(names[i][1], names[j][1])
            if sim >= threshold:
                out.append((names[i][0], names[j][0], round(sim, 4)))
    return out

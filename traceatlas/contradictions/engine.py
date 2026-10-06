"""Contradiction detection over observation pairs (value conflicts only)."""

from __future__ import annotations

from traceatlas.core.contradiction import Contradiction
from traceatlas.core.enums import RiskLevel
from traceatlas.core.observation import Observation


def detect_value_conflicts(observations: list[Observation]) -> list[Contradiction]:
    """Same subject+predicate but different object => value conflict."""
    by_key: dict[tuple[str, str], list[Observation]] = {}
    for o in observations:
        by_key.setdefault((o.subject, o.predicate), []).append(o)
    out: list[Contradiction] = []
    for group in by_key.values():
        if len({g.obj for g in group}) <= 1:
            continue
        ordered = sorted(group, key=lambda x: x.id)
        for i in range(len(ordered)):
            for j in range(i + 1, len(ordered)):
                a, b = ordered[i], ordered[j]
                if a.obj != b.obj:
                    out.append(
                        Contradiction(
                            case_id=a.case_id,
                            left_ref=a.id,
                            right_ref=b.id,
                            kind="value_conflict",
                            severity=RiskLevel.MODERATE,
                        )
                    )
    return out

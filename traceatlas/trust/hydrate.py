"""Rebuild a CaseMemory from its serialized ``to_dict()`` snapshot.

The inverse of ``CaseMemory.to_dict``: every canonical record type is restored
with its ORIGINAL ids and timestamps, so replayed state compares equal to the
state that was persisted (§ replay / recovery requirements). Unknown record
ids referenced by facts/observations are preserved as dangling citations and
reported — they are never silently dropped or rewritten.

This module performs no I/O; callers pass the dict (see db/repositories for
persistence adapters that use it).
"""

from __future__ import annotations

from dataclasses import fields

from traceatlas.trust.case_memory import (
    CaseMemory,
    EntityRecord,
    EventRecord,
    RelationshipRecord,
)
from traceatlas.trust.model import (
    BiasAssessment,
    Contradiction,
    EvidenceRecord,
    Fact,
    Hypothesis,
    IndependenceAssessment,
    Insight,
    Observation,
    ReliabilityAssessment,
    SourceRecord,
)


class HydrationError(ValueError):
    """Raised when a snapshot cannot be restored into canonical case state."""


def _known_names(cls) -> set[str]:
    return {f.name for f in fields(cls)}


def _build(cls, payload: dict) -> object:
    """Instantiate ``cls`` from ``payload``, ignoring unknown keys.

    Enum-valued fields are passed as raw string values; the dataclasses here
    declare plain defaults and never coerce on construction, so this stays
    lossless against ``to_jsonable`` output.
    """
    allowed = _known_names(cls)
    kwargs = {k: v for k, v in payload.items() if k in allowed}
    try:
        return cls(**kwargs)
    except TypeError as exc:  # missing required field etc.
        raise HydrationError(f"cannot restore {cls.__name__}: {exc}") from exc
    except ValueError as exc:  # e.g. FactWithoutEvidenceError via __post_init__
        raise HydrationError(f"cannot restore {cls.__name__}: {exc}") from exc


def hydrate_case_memory(snapshot: dict) -> tuple[CaseMemory, list[str]]:
    """Return ``(memory, warnings)`` restored from a ``to_dict()`` snapshot.

    Warnings list dangling references (e.g. an observation citing evidence that
    is absent from the snapshot). Dangling references do not abort hydration;
    historical state must be restorable even when partially damaged, but the
    caller must know about it.
    """
    case_id = snapshot.get("case_id") or ""
    if not case_id:
        raise HydrationError("snapshot has no case_id")
    mem = CaseMemory(case_id)
    warnings: list[str] = []

    def _add_all(key: str, cls: type, register) -> None:
        for item in snapshot.get(key, []) or []:
            obj = _build(cls, item)
            register(obj)

    _add_all("sources", SourceRecord, mem.add_source)

    for ev_payload in snapshot.get("evidence", []) or []:
        ev = _build(EvidenceRecord, ev_payload)
        if ev.source_id not in mem.sources:
            warnings.append(f"evidence {ev.id} cites unknown source {ev.source_id}")
        mem.evidence[ev.id] = ev
        mem._audit("hydrate_evidence", ev.id)

    assessments = snapshot.get("source_assessments", {}) or {}
    for key, cls in (("bias", BiasAssessment),
                     ("reliability", ReliabilityAssessment),
                     ("independence", IndependenceAssessment)):
        for item in assessments.get(key, []) or []:
            mem.add_assessment(_build(cls, item))

    for item in snapshot.get("observations", []) or []:
        obs = _build(Observation, item)
        for eid in obs.evidence_ids:
            if eid not in mem.evidence:
                warnings.append(f"observation {obs.id} cites unknown evidence {eid}")
        mem.observations[obs.id] = obs
        mem._audit("hydrate_observation", obs.id)

    for item in snapshot.get("facts", []) or []:
        fact = _build(Fact, item)
        for eid in fact.evidence_ids:
            if eid not in mem.evidence:
                warnings.append(f"fact {fact.id} cites unknown evidence {eid}")
        mem.facts[fact.id] = fact
        mem._audit("hydrate_fact", fact.id)

    for item in snapshot.get("insights", []) or []:
        ins = _build(Insight, item)
        for fid in ins.supporting_fact_ids:
            if fid not in mem.facts:
                warnings.append(f"insight {ins.id} cites unknown fact {fid}")
        mem.insights[ins.id] = ins
        mem._audit("hydrate_insight", ins.id)

    for item in snapshot.get("hypotheses", []) or []:
        hyp = _build(Hypothesis, item)
        mem.hypotheses[hyp.id] = hyp
        mem._audit("hydrate_hypothesis", hyp.id)

    for item in snapshot.get("contradictions", []) or []:
        ctr = _build(Contradiction, item)
        mem.contradictions[ctr.id] = ctr
        mem._audit("hydrate_contradiction", ctr.id)

    for item in snapshot.get("entities", []) or []:
        ent = _build(EntityRecord, item)
        mem.entities[ent.id] = ent
    for item in snapshot.get("relationships", []) or []:
        rel = _build(RelationshipRecord, item)
        mem.relationships[rel.id] = rel
    for item in snapshot.get("events", []) or []:
        evt = _build(EventRecord, item)
        mem.events[evt.id] = evt

    mem.gaps = list(snapshot.get("gaps", []) or [])
    mem.next_actions = list(snapshot.get("next_actions", []) or [])
    # audit_log is append-only history; restore verbatim rather than re-auditing
    mem.audit_log.extend(snapshot.get("audit_log", []) or [])
    return mem, warnings

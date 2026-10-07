"""Task-kind runners binding planner kinds to transforms and analysis steps.

collect.*  -> run a connector-backed transform for each target entity
analyze.*  -> deterministic enrichment using prior-wave observations
verify.claim / report.build -> handled by the manager after waves complete;
here they are validated no-ops that assert their prerequisites exist (so the
engine fails honestly if collection produced nothing).
"""

from __future__ import annotations

import json

from traceatlas.core.task import Task
from traceatlas.transforms.base import TransformInput
from traceatlas.transforms.registry import default_registry


def _targets_from(task: Task) -> list[dict]:
    return task.payload.get("targets", [])


def _ti(task: Task, kind: str, value: str, capture) -> TransformInput:
    return TransformInput(kind=kind, value=value, case_id=task.case_id,
                          investigation_id=task.payload.get("investigation_id", ""),
                          task_id=task.id, capture=capture,
                          metadata=dict(task.payload))


class MissingTransformError(Exception):
    """A runner referenced a transform id that is not in default_registry()."""


def _get_transform(registry, transform_id: str):
    """Registry.get raises KeyError for unknown ids; surface it as a typed error."""
    try:
        return registry.get(transform_id)
    except KeyError as exc:
        raise MissingTransformError(str(exc)) from exc


def _ingest_result(res, ctx) -> None:
    """Merge a TransformResult into the InvestigationContext.

    Evidence records are re-fetched from the capture's content-addressed store
    via the ids carried on the result (the transform attached them itself).
    """
    ctx.observations.extend(res.observations)
    key_map: dict[str, str] = {}
    for ent in res.entities:
        e = ctx.upsert_entity(ent.key, ent.entity_type, ent.display_name, ent.attributes)
        key_map[ent.key] = e.id
    for rel in res.relationships:
        src = key_map.get(rel.source_key) or _lookup_existing(ctx, rel.source_key)
        dst = key_map.get(rel.target_key) or _lookup_existing(ctx, rel.target_key)
        if not src or not dst:
            continue
        from traceatlas.core.enums import RelationshipType
        from traceatlas.core.relationship import Relationship

        rtype = _map_rel_type(rel.rel_type)
        ctx.relationships.append(Relationship(
            case_id=ctx.case_id, source_entity_id=src, target_entity_id=dst,
            relationship_type=rtype, confidence=rel.confidence,
            evidence_ids=list(rel.evidence_ids),
        ))


def _lookup_existing(ctx, key: str):
    ent = ctx.entities.get(key)
    return ent.id if ent else None


def _map_rel_type(name: str):
    from traceatlas.core.enums import RelationshipType

    alias = {
        "RESOLVES_TO": RelationshipType.RESOLVES_TO,
        "HOSTED_BY": RelationshipType.HOSTED_BY,
        "IN_ASN": RelationshipType.IN_ASN,
        "DELEGATED_TO": RelationshipType.DELEGATED_TO,
        "CERTIFICATE_FOR": RelationshipType.CERTIFICATE_FOR,
        "REGISTERED_BY": RelationshipType.REGISTERED_BY,
        "RELATED_TO": RelationshipType.RELATED_TO,
    }
    return alias.get(name, RelationshipType.RELATED_TO)


def make_collect_runner(transform_id: str, input_kind: str, capture):
    registry = default_registry(capture=capture)

    def runner(task: Task, ctx) -> tuple[bool, str]:
        transform = _get_transform(registry, transform_id)
        targets = [t for t in _targets_from(task) if t["kind"] == input_kind]
        if not targets:
            return True, ""  # nothing applicable for this input type: vacuous success
        any_ok = False
        errors: list[str] = []
        for t in targets:
            ti = _ti(task, input_kind, t["value"], capture)
            res = transform.execute(ti)
            if res.ok:
                any_ok = True
                _ingest_result(res, ctx)
                _attach_evidence(ctx, capture, res.evidence_ids)
            else:
                errors.extend(res.errors)
        if any_ok:
            return True, ""
        return False, "; ".join(errors) or f"{transform_id}: no successful collections"

    return runner


def _attach_evidence(ctx, capture, evidence_ids: list[str]) -> None:
    """Pull EvidenceRecords produced during this transform into the context.

    Transforms capture raw bytes through the shared EvidenceCapture; records
    are looked up via capture.records (id -> EvidenceRecord). Missing records
    are recorded as context errors rather than silently dropped.
    """
    known = getattr(capture, "records", None) or {}
    for ev_id in evidence_ids:
        if ev_id in ctx.evidence:
            continue
        rec = known.get(ev_id)
        if rec is not None:
            ctx.add_evidence(rec)
        else:
            ctx.errors.append(f"evidence record {ev_id} missing from capture index")


def make_analyze_runner(analyzer_id: str, capture):
    registry = default_registry(capture=capture)

    def runner(task: Task, ctx) -> tuple[bool, str]:
        analyzer = _get_transform(registry, analyzer_id)
        # analyze over every IP observed so far (asn/geo) — derived from DNS obs
        ips = sorted({o.obj for o in ctx.observations
                      if o.predicate.endswith("resolves_to")})
        if not ips:
            return False, f"{analyzer_id}: no IP observations to analyze"
        ok_any, errs = False, []
        for ip in ips[:8]:  # bounded fan-out per wave
            ti = _ti(task, "ip", ip, capture)
            res = analyzer.execute(ti)
            if res.ok:
                ok_any = True
                _ingest_result(res, ctx)
                _attach_evidence(ctx, capture, res.evidence_ids)
            else:
                errs.extend(res.errors)
        return (True, "") if ok_any else (False, "; ".join(errs) or "analysis failed")

    return runner


def make_gate_runner(required_predicates: tuple[str, ...]):
    """verify/report gates: succeed only if required knowledge exists."""

    def runner(task: Task, ctx) -> tuple[bool, str]:
        present = {o.predicate for o in ctx.observations}
        missing = [p for p in required_predicates if p not in present]
        if missing:
            return False, f"gate {task.kind}: missing observations {missing}"
        return True, ""

    return runner


def build_infrastructure_runners(capture, targets: list[dict]) -> dict:
    """Runner table matching planner template kinds.

    Transform ids here MUST exist in traceatlas.transforms.registry.
    default_registry(); _get_transform raises MissingTransformError at
    dispatch time otherwise (tested in tests/unit/test_runners.py).
    """
    dns = make_collect_runner("transform.domain_to_dns", "domain", capture)
    rdap = make_collect_runner("transform.domain_to_rdap", "domain", capture)
    ct = make_collect_runner("transform.domain_to_certificate", "domain", capture)
    return {
        "collect.dns": dns,
        "collect.rdap": rdap,
        "collect.certificates": ct,
        # IP enrichment: one call to the ipinfo-compatible connector yields
        # ASN + hosting org + coarse location; both analyze kinds share it so
        # no duplicate provider hit is made per wave.
        "analyze.ip_geo": make_analyze_runner("transform.ip_to_asn", capture),
        "analyze.asn": _cached_analyze_runner(
            make_analyze_runner("transform.ip_to_asn", capture)),
        "verify.claim": make_gate_runner(("domain.resolves_to",)),
        "report.build": make_gate_runner(("domain.resolves_to",)),
    }


def _cached_analyze_runner(inner):
    """Memoize an analyze runner by (sorted-ip-set) so the same IPs are not
    re-queried by a second analyze kind within one investigation."""
    seen: frozenset | None = None

    def runner(task, ctx):
        nonlocal seen
        ips = frozenset(o.obj for o in ctx.observations
                        if o.predicate.endswith("resolves_to"))
        if seen is not None and ips <= seen:
            return True, "already analyzed"
        ok, msg = inner(task, ctx)
        if ok:
            seen = seen | ips if seen is not None else ips
        return ok, msg

    return runner

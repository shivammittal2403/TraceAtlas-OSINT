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


def _ingest_result(res, ctx) -> None:
    """Merge a TransformResult into the InvestigationContext."""
    for ev_id in res.evidence_ids:
        rec = getattr(ctx, "_evidence_records", {}).get(ev_id)
        if rec is not None:
            ctx.add_evidence(rec)
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
        transform = registry.get(transform_id)
        if transform is None:
            return False, f"transform {transform_id} not registered"
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
            else:
                errors.extend(res.errors)
        if any_ok:
            return True, ""
        return False, "; ".join(errors) or f"{transform_id}: no successful collections"

    return runner


def make_analyze_runner(analyzer_id: str, capture):
    registry = default_registry(capture=capture)

    def runner(task: Task, ctx) -> tuple[bool, str]:
        analyzer = registry.get(analyzer_id)
        if analyzer is None:
            return False, f"analyzer {analyzer_id} not registered"
        # analyze over every IP observed so far (ip_geo/asn) — derived from DNS obs
        ips = sorted({o.obj for o in ctx.observations
                      if o.predicate.endswith("resolves_to")})
        if not ips:
            return False, f"{analyzer_id}: no IP observations to analyze"
        ok_any, errs = False, []
        for ip in ips[:8]:  # bounded fan-out per wave
            ti = _ti(task, "ipv4", ip, capture)
            res = analyzer.execute(ti)
            if res.ok:
                ok_any = True
                _ingest_result(res, ctx)
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
    """Runner table matching planner template kinds."""
    dns = make_collect_runner("dns.resolve", "domain", capture)
    rdap = make_collect_runner("rdap.domain", "domain", capture)
    ct = make_collect_runner("certificates.ct", "domain", capture)
    return {
        "collect.dns": dns,
        "collect.rdap": rdap,
        "collect.certificates": ct,
        "analyze.ip_geo": make_analyze_runner("ip.geo", capture),
        "analyze.asn": make_analyze_runner("ip.asn", capture),
        "verify.claim": make_gate_runner(("domain.resolves_to",)),
        "report.build": make_gate_runner(("domain.resolves_to",)),
    }

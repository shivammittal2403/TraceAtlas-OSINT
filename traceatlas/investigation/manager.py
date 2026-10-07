"""Top-level investigation manager: the full OBJECTIVE -> REPORT pipeline.

Orchestrates: parse objective -> validate scope/authorization -> build plan ->
execute engine waves -> graph build -> claims -> independence -> contradictions
-> verification -> gaps -> next-best-action -> report + replay manifest.

This is the single entry point used by CLI, API and the AI Employee.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from traceatlas.core.case import Case
from traceatlas.core.claim import Claim
from traceatlas.core.enums import ClaimStatus, InvestigationStatus
from traceatlas.core.information_gap import InformationGap
from traceatlas.core.objective import Objective
from traceatlas.core.objective_spec import ObjectiveSpec
from traceatlas.evidence.capture import EvidenceCapture, ReplayManifest
from traceatlas.evidence.store import EvidenceStore
from traceatlas.graph.builder import build_graph
from traceatlas.investigation.audit import AuditTrail
from traceatlas.investigation.checkpoints import CheckpointStore
from traceatlas.investigation.context import InvestigationContext
from traceatlas.investigation.engine import EngineResult, InvestigationEngine
from traceatlas.investigation.kill_switch import KillSwitch
from traceatlas.investigation.runners import build_infrastructure_runners
from traceatlas.objectives.parser import parse_objective
from traceatlas.planning.planner import build_plan


@dataclass
class InvestigationOutcome:
    case: Case
    objective: Objective
    spec: ObjectiveSpec
    engine_result: EngineResult
    graph: object = None
    claims: list[Claim] = field(default_factory=list)
    gaps: list[InformationGap] = field(default_factory=list)
    contradictions: list = field(default_factory=list)
    independence: dict = field(default_factory=dict)
    next_actions: list = field(default_factory=list)
    report_html: str = ""
    replay_manifest_json: str = ""
    status: InvestigationStatus = InvestigationStatus.COMPLETED

    def to_dict(self) -> dict:
        return {
            "case": self.case.to_dict(),
            "objective": self.objective.to_dict(),
            "spec": self.spec.to_dict(),
            "engine": self.engine_result.summary,
            "claims": [c.to_dict() for c in self.claims],
            "gaps": [g.to_dict() for g in self.gaps],
            "independence": self.independence,
            "next_actions": [a.to_dict() if hasattr(a, "to_dict") else a
                             for a in self.next_actions],
            "status": self.status.value,
        }


class InvestigationManager:
    def __init__(self, evidence_root: Path | str = ".traceatlas-evidence",
                 budget_units: float = 100.0, max_parallel: int = 4,
                 allow_live: bool = True) -> None:
        self.capture = EvidenceCapture(store=EvidenceStore(root=evidence_root))
        self.budget_units = budget_units
        self.max_parallel = max_parallel
        self.allow_live = allow_live
        self.audit = AuditTrail()
        self.checkpoints = CheckpointStore()

    # ------------------------------------------------------------------ api
    def run_investigation(self, title: str, objective_text: str,
                          out_dir: Path | str | None = None) -> InvestigationOutcome:
        case = Case(title=title)
        objective = Objective(case_id=case.id, text=objective_text)
        self.audit.emit(case.id, "objective.received", actor="manager",
                        subject_id=objective.id, detail={"text": objective_text})

        spec = parse_objective(objective)
        if spec.needs_human_clarification and spec.ambiguities:
            # honest behavior: proceed with public-only defaults but record it
            self.audit.emit(case.id, "objective.ambiguity", actor="manager",
                            subject_id=objective.id, detail={"items": spec.ambiguities})

        targets = _extract_targets(spec)
        if not targets:
            outcome = self._empty_outcome(case, objective, spec)
            outcome.gaps.append(InformationGap(
                case_id=case.id,
                question="No target identified in objective text — which "
                         "domain/IP/company/person should be investigated?",
                blocking_required_answer=True,
                candidate_actions=["ask_human"]))
            outcome.status = InvestigationStatus.NEEDS_HUMAN
            return outcome

        plan = build_plan(spec)
        ctx = InvestigationContext(case_id=case.id,
                                   investigation_id=plan.objective_spec_id,
                                   objective_spec_id=spec.id,
                                   budget_max_cost_units=self.budget_units)
        runners = build_infrastructure_runners(self.capture, targets)
        engine = InvestigationEngine(runners=runners, max_parallel=self.max_parallel,
                                     budget_units=self.budget_units, audit=self.audit,
                                     kill_switch=KillSwitch(check_file_each_dispatch=False),
                                     checkpoint_store=self.checkpoints)
        eres = engine.run(plan, ctx)

        # ---- knowledge products -------------------------------------------
        from traceatlas.analysis.claims import derive_claims
        from traceatlas.analysis.contradictions import detect_contradictions
        from traceatlas.analysis.gaps import find_gaps
        from traceatlas.analysis.independence import analyze_independence
        from traceatlas.analysis.nba import next_best_actions
        from traceatlas.analysis.verify import verify_claims

        claims = derive_claims(ctx)
        contradictions = detect_contradictions(ctx, claims)
        independence = analyze_independence(ctx)
        verify_claims(claims, ctx, contradictions, independence)
        gaps = find_gaps(spec, ctx, claims)
        actions = next_best_actions(gaps, ctx, eres)

        graph = build_graph(list(ctx.entities.values()), ctx.relationships)

        from traceatlas.reporting.report import render_report
        report_html = render_report(case, objective, spec, ctx, graph, claims,
                                    contradictions, gaps, independence, eres)

        manifest_json = _build_manifest(self.capture, ctx)

        outcome = InvestigationOutcome(
            case=case, objective=objective, spec=spec, engine_result=eres,
            graph=graph, claims=claims, gaps=gaps, contradictions=contradictions,
            independence=independence, next_actions=actions,
            report_html=report_html, replay_manifest_json=manifest_json,
            status=_map_status(eres),
        )
        if out_dir:
            self.persist(outcome, Path(out_dir))
        self.audit.emit(case.id, "investigation.finished", actor="manager",
                        detail=outcome.to_dict()["engine"])
        return outcome

    def persist(self, outcome: InvestigationOutcome, out_dir: Path) -> None:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "report.html").write_text(outcome.report_html, encoding="utf-8")
        (out_dir / "replay_manifest.json").write_text(outcome.replay_manifest_json,
                                                      encoding="utf-8")
        (out_dir / "graph.json").write_text(
            json.dumps(outcome.graph.to_dict(), indent=2, default=str), encoding="utf-8")
        (out_dir / "knowledge.json").write_text(
            json.dumps(outcome.to_dict(), indent=2, default=str), encoding="utf-8")
        ev_dir = out_dir / "evidence"
        ev_dir.mkdir(exist_ok=True)
        for rec in outcome.engine_result.context.evidence.values():
            try:
                blob = self.capture.store.get(rec.case_id, rec.sha256)
                (ev_dir / f"{rec.id}.bin").write_bytes(blob)
                (ev_dir / f"{rec.id}.meta.json").write_text(
                    json.dumps(rec.to_dict(), indent=2, default=str), encoding="utf-8")
            except Exception:  # noqa: BLE001 - missing blob must not lose the rest
                continue

    def _empty_outcome(self, case, objective, spec) -> InvestigationOutcome:
        ctx = InvestigationContext(case_id=case.id, investigation_id="none")
        eres = EngineResult(status="failed", context=ctx, stop_reason="NO_TARGET")
        return InvestigationOutcome(case=case, objective=objective, spec=spec,
                                    engine_result=eres,
                                    status=InvestigationStatus.NEEDS_HUMAN)


def _extract_targets(spec: ObjectiveSpec) -> list[dict]:
    """Normalized {kind,value} targets from parsed spec."""
    out = []
    seen = set()
    for ent in spec.target_entities:
        t = ent if isinstance(ent, dict) else {"type": getattr(ent, "type", ""),
                                               "value": getattr(ent, "value", "")}
        kind, value = str(t.get("type", "")), str(t.get("value", ""))
        if kind == "url" and "://" in value:
            host = value.split("//", 1)[1].split("/")[0]
            kind, value = "domain", host.lower()
        key = f"{kind}:{value}"
        if value and key not in seen:
            seen.add(key)
            out.append({"kind": kind, "value": value})
    return out


def _map_status(eres: EngineResult) -> InvestigationStatus:
    return {
        "completed": InvestigationStatus.COMPLETED,
        "failed": InvestigationStatus.FAILED,
        "cancelled": InvestigationStatus.CANCELLED,
        "budget_exhausted": InvestigationStatus.COMPLETED,
    }.get(eres.status, InvestigationStatus.FAILED)


def _build_manifest(capture: EvidenceCapture, ctx: InvestigationContext) -> str:
    m = ReplayManifest()
    for rec in ctx.evidence.values():
        # Reconstruct minimal CapturedEvidence view for manifest serialization.
        class _Wrap:
            def __init__(self, r):
                self.record = r
                from traceatlas.core.provenance import Provenance, ProvenanceStep
                self.provenance = Provenance(subject_id=r.id, steps=[ProvenanceStep(
                    kind="capture", actor=r.connector_id or "unknown",
                    input_refs=[r.url] if r.url else [], output_ref=r.id)])
                self.digest = r.sha256
        m.add(_Wrap(rec))
    return m.to_json()

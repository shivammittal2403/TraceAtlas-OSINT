"""ChiefIntelligenceManager (§2, §22, §44).

Top of the workforce. Real orchestration code implementing the mandatory
pipeline order (§37):

    WORKER RESULTS → EVIDENCE VALIDATION → OBSERVATION NORMALIZATION
    → FACT CANDIDATES → FACT GATE → RELIABILITY → BIAS → INDEPENDENCE
    → APPROVED FACT SET → INSIGHTS → HYPOTHESES → COMPETING HYPOTHESES
    → FALSIFICATION → DUAL REVIEW → FINAL SYNTHESIS (quality-gated)

The Chief does not search directly; it delegates to DepartmentManagers,
ingests their structured results into CaseMemory, runs the trust pipeline and
controls every stage transition. Hypothesis generation is physically impossible
before the Fact Gate has run (enforced by HypothesisEngine + EngineState).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.ai_workforce.manager import DepartmentManager
from traceatlas.ai_workforce.result import EmployeeResult, ManagerResult, ResultStatus
from traceatlas.ai_workforce.supervision import ComplianceSupervisor, QualitySupervisor
from traceatlas.ai_workforce.task import Task
from traceatlas.trust.case_memory import CaseMemory
from traceatlas.trust.fact_gate.candidate import FactCandidate
from traceatlas.trust.fact_gate.gate import FactGate
from traceatlas.trust.hypotheses import HypothesisEngine
from traceatlas.trust.model import (
    EvidenceRecord,
    Observation,
    SourceRecord,
    TrustError,
)
from traceatlas.trust.reliability import SourceReliabilityAnalyzer
from traceatlas.trust.source_bias.analyzer import SourceBiasAnalyzer


@dataclass
class Mission:
    objective: str
    case_id: str
    questions: list[str] = field(default_factory=list)
    departments_required: list[str] = field(default_factory=list)
    budget_cost: float = 50.0
    id: str = ""


@dataclass
class FinalAssessment:
    mission: Mission
    fact_summary: dict
    hypothesis_summary: dict
    disagreements: list[str]
    contradictions: list[dict]
    gaps: list[str]
    next_actions: list[str]
    quality_report: dict
    stop_reason: str
    replay: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "mission": {"objective": self.mission.objective, "questions": self.mission.questions},
            "facts": self.fact_summary,
            "hypotheses": self.hypothesis_summary,
            "disagreements": self.disagreements,
            "contradictions": self.contradictions,
            "gaps": self.gaps,
            "next_actions": self.next_actions,
            "quality_gate": self.quality_report,
            "stop_reason": self.stop_reason,
            "replay": self.replay,
        }


class ChiefIntelligenceManager:
    def __init__(self, memory: CaseMemory,
                 compliance: ComplianceSupervisor | None = None) -> None:
        self.memory = memory
        self.managers: dict[str, DepartmentManager] = {}
        self.compliance = compliance or ComplianceSupervisor()
        self.quality = QualitySupervisor()
        self.gate = FactGate(memory)
        self.hyp_engine = HypothesisEngine(memory)
        self.bias_analyzer = SourceBiasAnalyzer()
        self.rel_analyzer = SourceReliabilityAnalyzer()
        self.stage_log: list[str] = []
        self.pending_hypothesis_requests: list[dict] = []

    # ------------------------------------------------------------- org setup
    def register_manager(self, manager: DepartmentManager) -> None:
        self.managers[manager.department] = manager

    def select_departments(self, mission: Mission) -> list[DepartmentManager]:
        return [self.managers[d] for d in mission.departments_required if d in self.managers]

    # ------------------------------------------------- ingest worker results
    def ingest_department_result(self, result: ManagerResult) -> None:
        """Evidence/observation normalization (§37 steps 1–3). Managers cannot
        write canonical facts — only candidates flow onward."""
        self._stage("ingest_department_result")
        for emp_res in result.merged_results:
            self._ingest_employee_result(emp_res)

    def _ingest_employee_result(self, res: EmployeeResult) -> None:
        for obs in res.observations:
            stmt = obs.get("statement", "")
            ev_ids = list(obs.get("evidence_ids", []))
            src_ids = list(obs.get("source_ids", []))
            if not stmt or not ev_ids:
                continue  # ungrounded observation never enters canonical state
            known_ev = [e for e in ev_ids if e in self.memory.evidence]
            if len(known_ev) != len(ev_ids):
                res.limitations.append("observation referenced unknown evidence; skipped")
                continue
            self.memory.add_observation(Observation(
                statement=stmt, evidence_ids=ev_ids, source_ids=src_ids,
                employee_id=res.employee_id, task_id=res.task_id,
                case_id=self.memory.case_id))
        for ent in res.entities:
            self.memory.upsert_entity(ent.kind, ent.value)
        for cf in res.candidate_facts:
            cand = FactCandidate(
                statement=cf.statement, case_id=self.memory.case_id,
                observation_ids=list(cf.observation_ids),
                evidence_ids=list(cf.evidence_ids),
                source_ids=list(cf.source_ids),
                entity_ids=list(cf.entity_ids))
            gate_out = self.gate.evaluate(cand)
            if gate_out.fact_id:
                fact = self.memory.facts[gate_out.fact_id]
                for eid in fact.evidence_ids:
                    sid = self.memory.evidence[eid].source_id
                    self._ensure_source_assessments(sid)

    def _ensure_source_assessments(self, source_id: str) -> None:
        """Bias + reliability assessed for every source feeding gated facts (§10/§11)."""
        src = self.memory.sources.get(source_id)
        if src is None:
            return
        if not any(b.source_id == source_id for b in self.memory.bias_assessments.values()):
            self.memory.add_assessment(self.bias_analyzer.assess(src))
        if not any(r.source_id == source_id for r in self.memory.reliability_assessments.values()):
            self.memory.add_assessment(self.rel_analyzer.assess(src))

    # --------------------------------------------------------- fact-gate mark
    def finalize_fact_stage(self) -> dict:
        """Runs after all department results ingested. Unlocks hypotheses."""
        self._stage("fact_gate_complete")
        self.hyp_engine.mark_fact_gate_complete()
        # bias & independence stages are complete because gate ran per-candidate
        self.hyp_engine.mark_bias_complete()
        self.hyp_engine.mark_independence_complete()
        summary = self.memory.fact_summary()
        self._stage("bias_and_independence_complete")
        return summary

    # ------------------------------------------------------ hypothesis control
    def request_hypotheses(self, question: str, statements: list[str], **kwargs) -> list:
        """Chief-controlled hypothesis generation (§2). If the fact stage has
        not been finalized, this BLOCKS rather than silently proceeding."""
        if not self.hyp_engine.state.fact_gate_ran:
            raise TrustError(
                "Chief Manager refuses hypothesis generation before Fact Gate (§8/§37)")
        return self.hyp_engine.generate(question, statements, **kwargs)

    # ------------------------------------------------------------ final stage
    def approve_final_synthesis(self, report_text: str = "",
                                disclosed_limitations: list[str] | None = None,
                                ) -> FinalAssessment:
        q = self.quality.check_case(self.memory, report_text, disclosed_limitations)
        stop_reason = ("COMPLETED" if q.passed else
                       "NEEDS_HUMAN_INPUT: quality gate violations "
                       f"{q.violations}")
        replay = {
            "stages": list(self.stage_log),
            "gate_decisions": [{"candidate": d.candidate_id, "decision": d.decision.value,
                                "reasons": list(d.reasons)} for d in self.gate.decisions],
            "tasks_seen": len(self.memory.audit_log),
        }
        return FinalAssessment(
            mission=self.current_mission if hasattr(self, "current_mission") else
                    Mission(objective="(no mission recorded)", case_id=self.memory.case_id),
            fact_summary=self.memory.fact_summary(),
            hypothesis_summary=self.hyp_engine.hypothesis_summary(),
            disagreements=[d for m in
                           (mgr.completed_results for mgr in self.managers.values())
                           for r in m for d in r.disagreements],
            contradictions=[c.to_dict() for c in self.memory.contradictions.values()
                            if c.resolution == "open"],
            gaps=list(self.memory.gaps),
            next_actions=list(self.memory.next_actions),
            quality_report=q.to_dict(),
            stop_reason=stop_reason,
            replay=replay,
        )

    # ------------------------------------------------------------------ brief
    def jarvis_brief(self) -> str:
        """§32 JARVIS BRIEF built from structured state — facts before hypotheses."""
        fs = self.memory.fact_summary()
        lines = ["MISSION:", (self.current_mission.objective
                              if hasattr(self, "current_mission") else "(none)"), ""]
        lines += ["TEAM STATUS:"]
        for dept, mgr in self.managers.items():
            done = len(mgr.completed_results)
            lines.append(f"  {dept}: {done} department result(s)")
        lines += ["", "FACTS:"]
        for f in fs["verified_facts"] + fs["partial_facts"]:
            lines.append(f"  {f['id'][:12]} {f['statement']} ({f['confidence']})")
        lines += ["", "SOURCE BIAS:"]
        for note in fs["source_bias_notes"]:
            lines.append(f"  - {note}")
        lines += ["", f"INDEPENDENT SUPPORT: {len(fs['independent_sources'])} cluster(s)", ""]
        hs = self.hyp_engine.hypothesis_summary() if self.hyp_engine.state.fact_gate_ran \
            else {"hypotheses": []}
        lines += ["HYPOTHESES:"]
        for h in hs.get("hypotheses", []):
            lines.append(f"  {h.get('id', '')[:12]} {h.get('statement', '')} [{h.get('status', '')}]")
        if not hs.get("hypotheses"):
            lines.append("  (none generated — fact-first gate respected)")
        lines += ["", "NEXT ACTION:"]
        for a in (self.memory.next_actions or ["await further collection"]):
            lines.append(f"  - {a}")
        return "\n".join(lines)

    # ----------------------------------------------------------------- helpers
    def assign_mission(self, mission: Mission, tasks_by_dept: dict[str, list[Task]]
                       ) -> dict[str, ManagerResult]:
        """Delegate: chief creates/decomposes into typed tasks per department."""
        self.current_mission = mission
        self._stage("mission_assigned")
        out: dict[str, ManagerResult] = {}
        for dept, tasks in tasks_by_dept.items():
            mgr = self.managers.get(dept)
            if mgr is None:
                out[dept] = ManagerResult(manager_id="missing", task_id="-",
                                          status=ResultStatus.BLOCKED,
                                          department_assessment=f"no manager for {dept}")
                continue
            for t in tasks:
                out[dept] = mgr.receive_task(t)
                self.ingest_department_result(out[dept])
        return out

    def _stage(self, name: str) -> None:
        self.stage_log.append(name)

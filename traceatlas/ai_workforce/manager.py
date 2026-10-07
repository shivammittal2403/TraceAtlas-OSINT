"""Manager base class (§3, §22, §36).

A DepartmentManager is real orchestration code: it validates task contracts,
submits them to the ComplianceSupervisor (veto), routes tasks to employees by
skill match (§26), executes employees, merges their structured results
(deduplicate, retain disagreements — §36) and returns a ManagerResult.

Managers never invent data and never bypass the Fact Gate: candidate facts in
results stay candidates until FactGate.evaluate() promotes them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.ai_workforce.employee import Employee
from traceatlas.ai_workforce.permissions import PermissionSet
from traceatlas.ai_workforce.result import (
    CandidateFactPayload,
    EmployeeResult,
    ManagerResult,
    ResultStatus,
)
from traceatlas.ai_workforce.supervision import ComplianceSupervisor
from traceatlas.ai_workforce.task import Task, TaskAssignment


@dataclass
class BudgetLedger:
    """§7/§40 — per-manager cost accounting with hard cap."""

    max_cost: float = 100.0
    spent: float = 0.0

    def remaining(self) -> float:
        return max(0.0, self.max_cost - self.spent)

    def charge(self, amount: float) -> bool:
        if self.spent + amount > self.max_cost:
            return False
        self.spent += amount
        return True


class DepartmentManager:
    manager_id: str = "mgr_generic"
    department: str = "generic"

    def __init__(self, compliance: ComplianceSupervisor | None = None) -> None:
        self.employees: list[Employee] = []
        self.compliance = compliance or ComplianceSupervisor()
        self.budget = BudgetLedger()
        self.received_tasks: list[Task] = []
        self.completed_results: list[ManagerResult] = []

    # ------------------------------------------------------------- membership
    def add_employee(self, employee: Employee) -> None:
        self.employees.append(employee)

    # ------------------------------------------------------------ skill route
    def find_employees_for(self, task: Task) -> list[Employee]:
        """§26 skill routing: employees whose manifest covers ALL required skills."""
        need = set(task.required_skills)
        ranked = [e for e in self.employees if need <= e.skills]
        # prefer healthy, then lower workload (cost-aware tie-break)
        ranked.sort(key=lambda e: (e.health != "ready", e.workload, e.cost_per_call))
        return ranked

    # ---------------------------------------------------------------- receive
    def receive_task(self, task: Task) -> ManagerResult:
        """Mission in → structured department result out. No shortcuts."""
        self.received_tasks.append(task)

        contract_problems = task.validate_contract()
        if contract_problems:
            return self._finish(task, status=ResultStatus.BLOCKED,
                                assessment="task contract invalid: " + "; ".join(contract_problems))

        veto = self.compliance.review_task(task)
        if not veto.passed:
            return self._finish(task, status=ResultStatus.BLOCKED,
                                assessment="compliance veto: " + "; ".join(veto.violations))

        candidates = self.find_employees_for(task)
        if not candidates:
            return self._finish(task, status=ResultStatus.NO_FINDINGS,
                                gaps=[f"no {self.department} employee covers skills "
                                      f"{task.required_skills}"])

        assignments: list[tuple[Employee, TaskAssignment]] = []
        blocked: list[str] = []
        for emp in candidates:
            ok, problems = emp.can_accept(TaskAssignment.from_task(task, self.manager_id, emp.id,
                                                                   mission=task.objective))
            if ok:
                assignments.append((emp, TaskAssignment.from_task(
                    task, self.manager_id, emp.id, mission=task.objective)))
            else:
                blocked.extend(problems)
        if not assignments:
            return self._finish(task, status=ResultStatus.BLOCKED,
                                assessment="all matching employees refused/blocked: "
                                           + "; ".join(sorted(set(blocked))))

        # run every qualified employee (parallel specialists on same question),
        # respecting budget: skip further runs once budget exhausted.
        employee_results: list[EmployeeResult] = []
        for emp, _assign in assignments:
            if not self.budget.charge(emp.cost_per_call):
                employee_results.append(EmployeeResult(
                    employee_id=emp.id, task_id=task.id, status=ResultStatus.BLOCKED,
                    limitations=["department budget exhausted before this employee ran"]))
                continue
            res = emp.run(task)
            employee_results.append(res)

        # injection scan: collected content can NEVER expand permissions; flagged only.
        self.compliance.scan_results(employee_results)

        merged, dups, disagreements = self._synthesize(task, employee_results)
        gaps = sorted({g for r in employee_results for g in r.unknowns})
        handoffs = [h for r in employee_results
                    for h in [{"to": a, "from_employee": r.employee_id, "task": task.id}
                              for a in r.suggested_next_actions
                              if a.startswith("handoff:")]]
        status = ResultStatus.OK
        if all(r.status in (ResultStatus.FAILED, ResultStatus.BLOCKED) for r in employee_results):
            status = ResultStatus.FAILED
        elif any(r.status in (ResultStatus.PARTIAL, ResultStatus.NO_FINDINGS)
                 for r in employee_results):
            status = ResultStatus.PARTIAL

        result = ManagerResult(
            manager_id=self.manager_id, task_id=task.id, status=status,
            merged_results=merged, duplicates_removed=dups,
            disagreements=disagreements,
            department_assessment=self._assess(merged),
            gaps=gaps, handoff_requests=handoffs)
        self.completed_results.append(result)
        return result

    # -------------------------------------------------------------- synthesis
    def _synthesize(self, task: Task,
                    results: list[EmployeeResult]) -> tuple[list[EmployeeResult], int, list[str]]:
        """§36 merge: dedupe identical observations/candidate facts, keep disagreements."""
        seen_obs: set[str] = set()
        seen_facts: set[str] = set()
        dups = 0
        merged: list[EmployeeResult] = []
        for res in results:
            clean = EmployeeResult(employee_id=res.employee_id, task_id=res.task_id,
                                   status=res.status)
            for obs in res.observations:
                key = str(obs.get("statement", "")).strip().lower()
                if key and key in seen_obs:
                    dups += 1
                    continue
                seen_obs.add(key)
                clean.observations.append(obs)
            for cf in res.candidate_facts:
                key = cf.statement.strip().lower()
                if key in seen_facts:
                    dups += 1
                    continue
                seen_facts.add(key)
                clean.candidate_facts.append(cf)
            clean.entities, clean.relationships, clean.events = res.entities, res.relationships, res.events
            clean.evidence_ids, clean.source_ids = res.evidence_ids, res.source_ids
            clean.limitations, clean.unknowns = res.limitations, res.unknowns
            clean.contradictions, clean.bias_notes = res.contradictions, res.bias_notes
            clean.suggested_next_actions = res.suggested_next_actions
            clean.confidence, clean.cost_used, clean.latency_ms = res.confidence, res.cost_used, res.latency_ms
            merged.append(clean)

        # substantive disagreement: employees give conflicting statements about
        # the same subject → record, do NOT average away.
        disagreements: list[str] = []
        claims: dict[str, list[tuple[str, str]]] = {}
        for res in merged:
            for cf in res.candidate_facts:
                subj = cf.statement.split()[0].lower() if cf.statement else "?"
                claims.setdefault(subj, []).append((res.employee_id, cf.statement))
        for subj, pairs in claims.items():
            stmts = {s.lower() for _, s in pairs}
            if len(stmts) > 1 and len(pairs) > 1:
                disagreements.append(
                    f"subject '{subj}': " + " vs ".join(f"{eid}:{s}" for eid, s in pairs))
        return merged, dups, disagreements

    def _assess(self, merged: list[EmployeeResult]) -> str:
        n_facts = sum(len(r.candidate_facts) for r in merged)
        n_obs = sum(len(r.observations) for r in merged)
        return (f"{self.department}: {len(merged)} employee results, "
                f"{n_obs} observations, {n_facts} candidate facts (pending Fact Gate)")

    def _finish(self, task: Task, status: ResultStatus, assessment: str = "",
                gaps: list[str] | None = None) -> ManagerResult:
        result = ManagerResult(manager_id=self.manager_id, task_id=task.id, status=status,
                               department_assessment=assessment, gaps=list(gaps or []))
        self.completed_results.append(result)
        return result

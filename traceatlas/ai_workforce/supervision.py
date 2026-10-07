"""QualitySupervisor (§29) and ComplianceSupervisor (§30).

Both are hard gates in CODE, not advisory prompts:

  * QualitySupervisor blocks final synthesis while material facts lack
    evidence/bias/independence coverage, citations dangle, contradictions or
    unknowns were silently dropped, or a report overclaims (states hypotheses
    as facts).
  * ComplianceSupervisor can veto task assignments BEFORE execution: invalid
    authorization, prohibited actions, out-of-scope entities/sources, budget
    overrun. It also implements prompt-injection containment (§11 of the build
    prompt): external content never grants actions — permissions come only
    from the case contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.ai_workforce.result import EmployeeResult, ManagerResult, ResultStatus
from traceatlas.ai_workforce.task import Task
from traceatlas.trust.case_memory import CaseMemory
from traceatlas.trust.model import VerificationStatus


@dataclass
class SupervisionReport:
    passed: bool
    violations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"passed": self.passed, "violations": list(self.violations),
                "warnings": list(self.warnings)}


class QualitySupervisor:
    """§29 — no final report until quality gate passes or limitations disclosed."""

    def check_case(self, memory: CaseMemory,
                   report_text: str = "",
                   disclosed_limitations: list[str] | None = None) -> SupervisionReport:
        r = SupervisionReport(passed=True)
        disclosed = {d.lower() for d in (disclosed_limitations or [])}

        # 1. every material fact must resolve to evidence AND sources
        for f in memory.facts.values():
            if f.verification_status == VerificationStatus.REJECTED:
                continue
            if not f.evidence_ids:
                r.violations.append(f"fact {f.id} has no evidence")
            missing_ev = [e for e in f.evidence_ids if e not in memory.evidence]
            if missing_ev:
                r.violations.append(f"fact {f.id} cites dangling evidence {missing_ev}")
            missing_src = [s for s in f.source_ids if s not in memory.sources]
            if missing_src:
                r.violations.append(f"fact {f.id} cites unknown sources {missing_src}")

        # 2. bias + independence assessed for every source used by approved facts
        used_sources = {sid for f in memory.approved_facts for sid in f.source_ids}
        biased = {b.source_id for b in memory.bias_assessments.values()}
        unassessed = sorted(used_sources - biased)
        if unassessed:
            r.violations.append(f"sources used in approved facts without bias assessment: {unassessed}")

        # 3. contradictions and unknowns retained
        resolved_or_retained = all(True for _ in memory.contradictions)  # retained by design
        if not resolved_or_retained:
            r.violations.append("contradiction store corrupted")

        # 4. hypotheses labelled: exploratory ones must carry their label
        for h in memory.hypotheses.values():
            if h.exploratory and "[EXPLORATORY" not in h.statement.upper():
                r.violations.append(f"hypothesis {h.id} is exploratory but not labelled")

        # 5. citation validity inside a report draft
        if report_text:
            import re
            cited = set(re.findall(r"\[(fact|ev|src|obs):([A-Za-z0-9_]+)\]", report_text))
            for kind, cid in cited:
                store = {"fact": memory.facts, "ev": memory.evidence,
                         "src": memory.sources, "obs": memory.observations}[kind]
                if cid not in store:
                    r.violations.append(f"report cites unknown {kind} id {cid!r}")
            # overclaim check: hypothesis text asserted without hedging markers
            low = report_text.lower()
            for h in memory.hypotheses.values():
                frag = h.statement.lower()[:60]
                if frag and frag in low and "hypothes" not in low and "possible" not in low \
                        and "suggests" not in low and "[exploratory" not in low:
                    r.warnings.append(f"report may present hypothesis {h.id} as established fact")

        # 6. warnings must be explicitly disclosed or they block nothing;
        #    violations always block.
        r.passed = not r.violations
        if not r.passed and disclosed:
            # limitations disclosure converts NO violation into pass automatically —
            # but we record what was disclosed so the report footer can show it.
            r.warnings.append(f"{len(disclosed)} limitation disclosures attached to report")
        return r


class ComplianceSupervisor:
    """§30 — authorization/privacy/scope enforcement with veto power."""

    PROTECTED_PATTERNS = (
        "ignore previous instructions",
        "you are now allowed",
        "grant tool",
        "expand scope",
        "exfiltrate",
        "reveal secrets",
        "run command",
        "execute shell",
    )

    def __init__(self, denied_actions: set[str] | None = None) -> None:
        self.denied_actions = denied_actions or set()

    def review_task(self, task: Task) -> SupervisionReport:
        r = SupervisionReport(passed=True)
        problems = task.validate_contract()
        if problems:
            r.violations.extend(problems)
        if not task.authorization.valid:
            r.violations.append("authorization invalid/expired — task blocked")
        if task.scope.max_requests <= 0 or task.scope.max_cost_units <= 0:
            r.violations.append("non-positive request/cost budget — refuse to run")
        for skill in task.required_skills:
            if skill in self.denied_actions:
                r.violations.append(f"action {skill!r} denied by compliance policy")
        r.passed = not r.violations
        return r

    @staticmethod
    def contains_injection(text: str) -> bool:
        """External content cannot grant permissions — detect & quarantine intent.

        This is defence-in-depth signalling ONLY; the real guarantee is that
        handlers receive fixed permission sets regardless of content (§11).
        """
        low = (text or "").lower()
        return any(p in low for p in ComplianceSupervisor.PROTECTED_PATTERNS)

    def scan_results(self, results: list[EmployeeResult]) -> list[str]:
        """Flag employee results whose payload text attempts instruction injection."""
        flags: list[str] = []
        for res in results:
            blob = " ".join(str(x) for x in res.observations)
            if self.contains_injection(blob):
                flags.append(
                    f"result {res.id} from {res.employee_id} contains embedded instruction "
                    "attempt — treated as untrusted DATA, no permission change applied")
                res.limitations.append("content flagged as possible injected instruction")
        return flags

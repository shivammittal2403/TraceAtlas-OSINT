"""Dual-analysis engine facade (§1, §12, §43).

Pipeline (mandatory order):
  RAW RESULT -> DETERMINISTIC VALIDATION (§8)
             -> AI PASS 1 PRIMARY ANALYST (§4)
             -> AI PASS 2 INDEPENDENT CRITICAL ANALYST (§5, isolation §33)
             -> CROSS-CHECK (§6)
             -> EVIDENCE COMPARISON / FACTUALITY GROUNDING (§2, §8)
             -> CONTRADICTION + TEMPORAL + ENTITY + RELATIONSHIP CHECKERS
             -> SOURCE-INDEPENDENCE CHECK (§20)
             -> ADJUDICATION when triggered (§7, §39)
             -> FINAL SYNTHESIS (§35) with honest degradation (§31).

The engine never converts model agreement into facts: AI_REASONING_AGREEMENT
and EVIDENCE_CORROBORATION are tracked on separate axes (§2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from traceatlas.ai.gateway import AIGateway, AllModelsUnavailableError
from traceatlas.analysis.adjudication_policy import AdjudicationPolicy
from traceatlas.analysis.contradiction_checker import check_contradictions
from traceatlas.analysis.cross_check_core import run_cross_check
from traceatlas.analysis.deterministic_grounding import ground_pass
from traceatlas.analysis.entity_checker import check_entities
from traceatlas.analysis.evidence_context import EvidenceContext
from traceatlas.analysis.finalize_core import build_final_synthesis
from traceatlas.analysis.imported_data import analyze_imported_payload
from traceatlas.analysis.prompts import PRIMARY_SYSTEM, SECONDARY_SYSTEM
from traceatlas.analysis.relationship_checker import check_relationships
from traceatlas.analysis.result import (AdjudicationResult, CrossCheckResult,
                                        FinalSynthesis, PassAnalysis)
from traceatlas.analysis.source_independence_core import independence_for_statement
from traceatlas.analysis.temporal_checker import check_temporal
from traceatlas.analysis.validation_gate import validate_connector_result
from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable
from traceatlas.core.validation import utcnow


@dataclass
class DualAnalysisRun:
    """Complete record of one raw-result -> synthesis pass (§42 chain)."""
    run_id: str = field(default_factory=lambda: new_id("arun"))
    case_id: str = ""
    validation_status: str = "UNKNOWN"
    validation_issues: list[str] = field(default_factory=list)
    primary: PassAnalysis | None = None
    secondary: PassAnalysis | None = None
    grounding_primary: dict = field(default_factory=dict)
    grounding_secondary: dict = field(default_factory=dict)
    cross_check: CrossCheckResult | None = None
    independence: dict = field(default_factory=dict)
    contradictions: list[dict] = field(default_factory=list)
    temporal: list[dict] = field(default_factory=list)
    entities: list[dict] = field(default_factory=list)
    relationships: list[dict] = field(default_factory=list)
    adjudication: AdjudicationResult | None = None
    synthesis: FinalSynthesis | None = None
    degraded: bool = False            # deterministic-only mode (§31)
    model_diversity: str = "HIGH"     # LOW when same model both passes (§26)
    started_at: datetime = field(default_factory=utcnow)
    finished_at: datetime | None = None

    def to_dict(self) -> dict:
        return to_jsonable(self)


class DualAnalysisEngine:
    def __init__(self, gateway: AIGateway, *,
                 primary_model: str, secondary_model: str | None = None,
                 adjudicator_model: str | None = None,
                 fallback_local_model: str = "",
                 policy: AdjudicationPolicy | None = None):
        self.gateway = gateway
        self.primary_model = primary_model
        self.secondary_model = secondary_model or primary_model
        self.adjudicator_model = adjudicator_model or \
            gateway.configured_models().get("adjudicator") or self.secondary_model
        self.fallback_local_model = fallback_local_model
        self.policy = policy or AdjudicationPolicy()
        self.model_diversity = ("LOW" if self.primary_model == self.secondary_model
                                else "HIGH")

    # ------------------------------------------------------------------ chain
    def _chain(self, base: str) -> list[tuple[str, str]]:
        """PRIMARY -> SECONDARY -> LOCAL FALLBACK (§31)."""
        out: list[tuple[str, str]] = []
        for mid, tier in ((self.secondary_model, "secondary"),
                          (self.fallback_local_model, "local_fallback")):
            if mid and mid != base and (mid, tier) not in out:
                out.append((mid, tier))
        return out

    def _run_pass(self, role: str, system: str, ctx: EvidenceContext,
                  model: str) -> PassAnalysis:
        prompt = (f"EVIDENCE CONTEXT (JSON):\n{ctx.render_for_prompt()}\n\n"
                  "Produce your analysis now as a single JSON object.")
        return self.gateway.generate_structured(
            role=role, prompt=prompt, schema=PassAnalysis, system=system,
            model_id=model, chain=self._chain(model), temperature=0.1,
            sensitive=True)

    def analyze(self, ctx: EvidenceContext, *, http_status: int = 200,
                required_fields: list[str] | None = None,
                importance: str = "high",
                involves_identity_merge: bool = False,
                involves_attribution: bool = False) -> DualAnalysisRun:
        run = DualAnalysisRun(case_id=ctx.case_id,
                              model_diversity=self.model_diversity)

        # ---- stage 0: deterministic validation BEFORE any AI (§8) ----------
        agg_status = "VALID"
        for item in ctx.evidence:
            vr = validate_connector_result(item.payload, http_status=http_status,
                                           required_fields=required_fields)
            item.validation_status = vr.status
            item.validation_issues = list(vr.issues)
            if vr.status != "VALID":
                agg_status = vr.status
        run.validation_status = agg_status
        if ctx.determinate_validation is not None:
            run.validation_issues.extend(ctx.determinate_validation.issues)
        run.validation_issues.extend(
            i for e in ctx.evidence for i in e.validation_issues)

        invalid = agg_status in ("INVALID", "MALFORMED", "SCHEMA_DRIFT")

        # ---- stage 1/2: dual independent passes (§4, §5, §33) -------------
        try:
            if invalid:
                # AI may describe the failure but must not repair evidence (§8)
                raise _EvidenceRejected(agg_status)
            run.primary = self._run_pass("primary", PRIMARY_SYSTEM, ctx,
                                         self.primary_model)
            # isolation: secondary sees ONLY evidence context, never pass 1
            run.secondary = self._run_pass("secondary", SECONDARY_SYSTEM, ctx,
                                          self.secondary_model)
        except (_EvidenceRejected, AllModelsUnavailableError) as exc:
            run.degraded = True
            run.validation_issues.append(f"deterministic-degraded-mode: {exc}")
            run.finished_at = utcnow()
            run.cross_check = CrossCheckResult(case_id=ctx.case_id, items=[],
                                               summary={"DEGRADED": 1})
            run.synthesis = build_final_synthesis(ctx, run)
            return run

        # ---- deterministic grounding BEFORE trusting either pass ----------
        run.grounding_primary = ground_pass(run.primary, ctx)
        run.grounding_secondary = ground_pass(run.secondary, ctx)

        # ---- cross-check statement-by-statement (§6) ----------------------
        run.cross_check = run_cross_check(ctx, run.primary, run.secondary,
                                          run.grounding_primary,
                                          run.grounding_secondary)

        # ---- specialized checkers ----------------------------------------
        run.independence = independence_for_statement(ctx, run.cross_check)
        run.contradictions = check_contradictions(ctx, run.cross_check)
        run.temporal = check_temporal(ctx, run.cross_check)
        run.entities = check_entities(ctx, run.cross_check)
        run.relationships = check_relationships(ctx, run.cross_check,
                                                run.entities)

        # ---- adjudication only when triggered (§7, §39) --------------------
        triggers = self.policy.triggers_for(run, importance=importance,
                                            identity_merge=involves_identity_merge,
                                            attribution=involves_attribution)
        if triggers:
            run.adjudication = self._adjudicate(ctx, run, triggers)

        # ---- final synthesis (§35) ---------------------------------------
        run.synthesis = build_final_synthesis(ctx, run)
        run.finished_at = utcnow()
        return run

    def _adjudicate(self, ctx: EvidenceContext, run: DualAnalysisRun,
                    triggers: list[str]) -> AdjudicationResult:
        from traceatlas.analysis.adjudication_core import adjudicate
        return adjudicate(self.gateway, ctx, run,
                          model=self.adjudicator_model,
                          chain=self._chain(self.adjudicator_model),
                          triggers=triggers)

    # ----------------------------------------------------- imported data (§21)
    def analyze_imported(self, payload: dict, *, case_id: str,
                         questions: list[dict] | None = None) -> dict:
        return analyze_imported_payload(self, payload, case_id=case_id,
                                        questions=questions or [])


class _EvidenceRejected(RuntimeError):
    pass

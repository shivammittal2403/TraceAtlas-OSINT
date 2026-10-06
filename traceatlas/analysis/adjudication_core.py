"""Third-stage adjudicator (§7).

Receives original evidence + both passes + comparison + independence results
and issues per-statement verdicts. Deterministic pre-resolution happens first:
where grounding already decides the matter (e.g. both sides cite nothing real)
the engine assigns INCONCLUSIVE/UNSUPPORTED WITHOUT burning a model call. The
model is asked only for what evidence cannot decide — and may not invent
tie-breaking facts.
"""

from __future__ import annotations

import json

from traceatlas.ai.gateway import AIGateway, AllModelsUnavailableError
from traceatlas.analysis.adjudication_policy import MATERIAL_STATUSES
from traceatlas.analysis.evidence_context import EvidenceContext
from traceatlas.analysis.prompts import ADJUDICATOR_SYSTEM
from traceatlas.analysis.result import (AdjudicatedStatement,
                                        AdjudicationResult)


def _needs_model(item, g1: dict, g2: dict) -> bool:
    r1 = g1.get(item.statement, {})
    r2 = g2.get(item.statement, {})
    if r1.get("grounding") == "uncited_or_unknown" or \
       r2.get("grounding") == "uncited_or_unknown":
        return False          # deterministic: hallucination candidate
    return True


def deterministic_prepass(item, g1: dict, g2: dict) -> AdjudicatedStatement | None:
    """Resolve without a model where evidence already decides (§7 economy)."""
    r1 = g1.get(item.statement, {})
    r2 = g2.get(item.statement, {})
    if item.agreement_status in MATERIAL_STATUSES or item.agreement_status in (
            "PASS1_ONLY",):
        if r1.get("grounding") == "uncited_or_unknown" or \
           r2.get("grounding") == "uncited_or_unknown":
            return AdjudicatedStatement(
                statement=item.statement, verdict="UNSUPPORTED",
                reason="no cited evidence resolves against the evidence set",
                evidence_ids=[], requires_human_review=False)
        if item.independence == "dependent":
            return AdjudicatedStatement(
                statement=item.statement, verdict="PARTIALLY_SUPPORTED",
                reason="cited sources share one upstream origin; single-origin "
                       "support only",
                evidence_ids=item.evidence_ids)
        if item.agreement_status == "DISAGREE":
            return None       # genuine analytic conflict -> model + human path
    return None


def adjudicate(gateway: AIGateway, ctx: EvidenceContext, run, *,
               model: str, chain: list[tuple[str, str]],
               triggers: list[str]) -> AdjudicationResult:
    result = AdjudicationResult(case_id=ctx.case_id, invoked_because=",".join(triggers))
    g1 = run.grounding_primary
    g2 = run.grounding_secondary
    disputed = [i for i in (run.cross_check.items if run.cross_check else [])
                if i.agreement_status in MATERIAL_STATUSES
                or i.agreement_status == "PASS1_ONLY"
                or (i.ai_reasoning_agreement and not i.evidence_corroboration)]
    model_items = []
    for item in disputed:
        pre = deterministic_prepass(item, g1, g2)
        if pre is not None:
            result.decisions.append(pre)
        elif _needs_model(item, g1, g2):
            model_items.append(item)

    if model_items:
        payload = {
            "evidence": [e.as_dict() for e in ctx.evidence],
            "disputed": [i.model_dump() for i in model_items],
            "independence": run.independence.get("per_statement", {}),
            "contradictions": run.contradictions,
            "graph_context": ctx.graph_context,
            "timeline_context": ctx.timeline_context,
        }
        prompt = ("ADJUDICATION INPUT (JSON):\n"
                  + json.dumps(payload, sort_keys=True, default=str)[:24000]
                  + "\nDecide each disputed statement.")
        try:
            out = gateway.generate_structured(
                role="adjudicator", prompt=prompt, schema=AdjudicationResult,
                system=ADJUDICATOR_SYSTEM, model_id=model, chain=chain,
                sensitive=True)
            by_stmt = {d.statement: d for d in out.decisions}
            for item in model_items:
                d = by_stmt.get(item.statement)
                if d is None:
                    result.decisions.append(AdjudicatedStatement(
                        statement=item.statement, verdict="INCONCLUSIVE",
                        reason="adjudicator did not resolve; evidence insufficient"))
                else:
                    # hard guard: adjudicator may not upgrade to SUPPORTED
                    # without corroborated independent evidence
                    if d.verdict == "SUPPORTED" and not item.evidence_corroboration:
                        d.verdict = "PARTIALLY_SUPPORTED"
                        d.reason = (d.reason + " | downgraded: no independent "
                                    "multi-source corroboration").strip(" |")
                    if d.verdict in ("SUPPORTED", "PARTIALLY_SUPPORTED") and \
                            item.temporal_consistency in ("stale", "conflicting"):
                        d.requires_human_review = True
                    result.decisions.append(d)
        except AllModelsUnavailableError:
            for item in model_items:
                result.decisions.append(AdjudicatedStatement(
                    statement=item.statement, verdict="INCONCLUSIVE",
                    reason="adjudicator unavailable — degraded mode keeps the "
                           "claim unresolved rather than guessing",
                    evidence_ids=item.evidence_ids,
                    requires_human_review=item.agreement_status == "DISAGREE"))
    return result

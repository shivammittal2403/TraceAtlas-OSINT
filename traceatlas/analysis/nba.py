"""Next-best-action ranking over detected gaps.

Scoring is deterministic and explainable — every action records WHY it was
selected (rationale field), per the requirement to persist selection reasons:

score = information_gain_weight * expected_gain
      + urgency * blocking
      - cost_penalty * estimated_cost
The highest-scoring actions are returned ranked; when no gaps remain the only
action is STOP with reason OBJECTIVE_SATISFIED / SOURCES_EXHAUSTED taken from
the engine result's stop_reason.
"""

from __future__ import annotations

from traceatlas.core.information_gap import InformationGap
from traceatlas.core.next_action import NextAction
from traceatlas.investigation.engine import EngineResult

_ACTION_KIND = {
    "collect": "collect", "search": "collect", "analyze": "analyze",
    "verify": "verify", "retry": "collect", "accept": "stop",
    "ask_human": "ask_human",
}
_GAIN = {"collect": 0.6, "verify": 0.5, "analyze": 0.4,
         "ask_human": 0.7, "stop": 0.0}


def next_best_actions(gaps: list[InformationGap], ctx,
                      eres: EngineResult) -> list[NextAction]:
    actions: list[NextAction] = []
    remaining_budget = max(0.0, ctx.budget_max_cost_units - ctx.cost_units_spent)

    for gap in gaps:
        for cand in (gap.candidate_actions or ["ask_human"]):
            family = cand.split(".")[0]
            kind = _ACTION_KIND.get(family, "analyze")
            gain = _GAIN.get(kind, 0.3)
            cost = 1.0
            score = (gain * (1.5 if gap.blocking_required_answer else 1.0)
                     - 0.1 * cost)
            if cost > remaining_budget:
                continue  # honestly drop unaffordable actions
            requires_approval = kind == "ask_human"
            actions.append(NextAction(
                description=cand,
                action_kind=kind,
                expected_information_gain=gain,
                estimated_cost_units=cost,
                requires_human_approval=requires_approval,
                rationale=(f"addresses gap '{gap.question[:80]}'; "
                           f"blocking={gap.blocking_required_answer}; "
                           f"score={score:.2f}"),
                score=round(score, 3),
            ))

    if not actions:
        stop_reason = eres.stop_reason or ("BUDGET_EXHAUSTED"
                                           if ctx.budget_exhausted()
                                           else "OBJECTIVE_SATISFIED")
        actions.append(NextAction(
            description="stop", action_kind="stop",
            expected_information_gain=0.0, estimated_cost_units=0.0,
            rationale=f"no affordable gap-closing action remains; engine said "
                      f"{stop_reason}", score=1.0))

    actions.sort(key=lambda a: a.score, reverse=True)
    return actions[:5]

"""Deterministic planner: ObjectiveSpec -> Plan.

The current planner is rule-based and honest about its limits: it maps
investigation types to fixed collection/verification templates. An LLM-backed
semantic planner (semantic_planner.py) exists as an interface stub only.
"""

from __future__ import annotations

from traceatlas.core.objective_spec import ObjectiveSpec
from traceatlas.planning.planner_output import Plan, PlannedTask
from traceatlas.planning.stop_condition_builder import build_stop_conditions
from traceatlas.planning.wave_planner import assign_waves
from traceatlas.planning.cost_planner import estimate_cost
from traceatlas.planning.plan_validator import validate_plan

_TEMPLATES: dict[str, list[tuple[str, list[str], float]]] = {
    "infrastructure": [
        ("collect.dns", [], 1.0),
        ("collect.rdap", [], 1.0),
        ("analyze.ip_geo", ["collect.dns"], 1.0),
        ("analyze.asn", ["collect.dns"], 1.0),
        ("verify.claim", ["analyze.ip_geo", "analyze.asn"], 1.0),
        ("report.build", ["verify.claim"], 1.0),
    ],
    "company": [
        ("collect.registry_search", [], 2.0),
        ("extract.entities", ["collect.registry_search"], 1.0),
        ("graph.build", ["extract.entities"], 1.0),
        ("verify.claim", ["graph.build"], 1.0),
        ("report.build", ["verify.claim"], 1.0),
    ],
    "general": [
        ("collect.web_search", [], 1.0),
        ("extract.entities", ["collect.web_search"], 1.0),
        ("verify.claim", ["extract.entities"], 1.0),
        ("report.build", ["verify.claim"], 1.0),
    ],
}


def build_plan(spec: ObjectiveSpec) -> Plan:
    template = _TEMPLATES.get(spec.investigation_type, _TEMPLATES["general"])
    tasks = [
        PlannedTask(kind=kind, depends_on_kinds=deps, cost_estimate_units=cost,
                    payload={"objective_spec_id": spec.id})
        for kind, deps, cost in template
    ]
    plan = Plan(
        objective_spec_id=spec.id,
        tasks=tasks,
        stop_conditions=build_stop_conditions(spec),
    )
    assign_waves(plan)
    plan.estimated_cost_units = estimate_cost(plan)
    plan.estimated_waves = max((t.wave for t in plan.tasks), default=0) + 1
    problems = validate_plan(plan)
    if problems:
        plan.warnings.extend(problems)
    return plan

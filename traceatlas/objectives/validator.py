"""Validate a produced ObjectiveSpec before planning may consume it."""

from __future__ import annotations

from traceatlas.core.enums import AuthorizationMode
from traceatlas.core.objective_spec import ObjectiveSpec
from traceatlas.exceptions import ValidationError


def validate_spec(spec: ObjectiveSpec) -> list[str]:
    """Return list of problems; empty list means the spec is usable."""
    problems: list[str] = []
    if spec.authorization_mode != AuthorizationMode.PUBLIC_ONLY:
        problems.append(
            "Non-public authorization mode requires a human-signed Authorization record "
            "before execution (policy default enforced by policy.engine)."
        )
    if not spec.required_answers:
        problems.append("Spec has no required answers; planner cannot define completion.")
    if spec.needs_human_clarification and not spec.ambiguities:
        problems.append("needs_human_clarification set without recorded ambiguities.")
    return problems


def ensure_valid(spec: ObjectiveSpec) -> None:
    problems = validate_spec(spec)
    blocking = [p for p in problems if "no required answers" in p]
    if blocking:
        raise ValidationError("; ".join(blocking))

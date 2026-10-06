"""ObjectiveSpec: structured interpretation of a natural-language objective.

Produced by the objectives pipeline (parser/classifier/extractors). It is
always derived data — the raw Objective text remains the canonical statement.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.enums import AuthorizationMode, EntityType
from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable


@dataclass
class RequiredAnswer:
    question: str
    priority: int = 1  # 1 = must answer, 3 = nice to have


@dataclass
class Constraint:
    kind: str          # e.g. "scope", "temporal", "jurisdiction", "prohibition"
    value: str
    source: str = "objective_text"  # or "inferred", "policy_default"


@dataclass
class ObjectiveSpec:
    objective_id: str
    investigation_type: str = "general"
    authorization_mode: AuthorizationMode = AuthorizationMode.PUBLIC_ONLY
    target_entities: list[dict] = field(default_factory=list)  # {type, value}
    entity_types_of_interest: list[EntityType] = field(default_factory=list)
    required_answers: list[RequiredAnswer] = field(default_factory=list)
    constraints: list[Constraint] = field(default_factory=list)
    ambiguities: list[str] = field(default_factory=list)
    needs_human_clarification: bool = False
    spec_version: int = 1
    id: str = field(default_factory=lambda: new_id("spec"))

    def to_dict(self) -> dict:
        return to_jsonable(self)

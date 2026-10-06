"""Build Target records from an ObjectiveSpec's extracted entities."""

from __future__ import annotations

from traceatlas.core.enums import EntityType
from traceatlas.core.objective_spec import ObjectiveSpec
from traceatlas.core.target import Target


def targets_from_spec(case_id: str, spec: ObjectiveSpec) -> list[Target]:
    targets: list[Target] = []
    for ent in spec.target_entities:
        try:
            etype = EntityType(ent["type"])
        except ValueError:
            etype = EntityType.UNKNOWN
        targets.append(Target(case_id=case_id, entity_type=etype, value=ent["value"]))
    return targets

"""Metadata about relationship types (directionality, transitivity)."""

from __future__ import annotations

from dataclasses import dataclass

from traceatlas.core.enums import RelationshipType


@dataclass(frozen=True)
class RelationshipTypeInfo:
    rtype: RelationshipType
    directed: bool
    transitive: bool
    description: str


RELATIONSHIP_TYPES: dict[RelationshipType, RelationshipTypeInfo] = {
    rt: RelationshipTypeInfo(rt, directed=True, transitive=False, description=rt.value)
    for rt in RelationshipType
}
RELATIONSHIP_TYPES[RelationshipType.SAME_ENTITY_AS] = RelationshipTypeInfo(
    RelationshipType.SAME_ENTITY_AS, directed=False, transitive=True,
    description="entity-resolution equivalence",
)

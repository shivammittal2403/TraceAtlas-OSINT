"""Build a GraphModel from Entity/Relationship domain records."""

from __future__ import annotations

from traceatlas.core.entity import Entity
from traceatlas.core.relationship import Relationship
from traceatlas.graph.model import GEdge, GNode, GraphModel


def build_graph(entities: list[Entity], relationships: list[Relationship]) -> GraphModel:
    g = GraphModel()
    for e in entities:
        g.add_node(GNode(id=e.id, label=e.entity_type.value,
                         properties={"display_name": e.display_name}))
    for r in relationships:
        g.add_edge(GEdge(source=r.source_entity_id, target=r.target_entity_id,
                         edge_type=r.relationship_type.value,
                         evidence_ids=list(r.evidence_ids), confidence=r.confidence))
    return g

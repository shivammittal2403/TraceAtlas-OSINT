"""In-memory property graph model with typed edges and evidence links."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class GNode:
    id: str
    label: str
    properties: dict = field(default_factory=dict)


@dataclass
class GEdge:
    source: str
    target: str
    edge_type: str
    properties: dict = field(default_factory=dict)
    evidence_ids: list[str] = field(default_factory=list)
    confidence: float = 0.0


class GraphModel:
    def __init__(self) -> None:
        self.nodes: dict[str, GNode] = {}
        self.edges: list[GEdge] = []
        self._adj: dict[str, list[int]] = {}

    def add_node(self, node: GNode) -> None:
        self.nodes[node.id] = node
        self._adj.setdefault(node.id, [])

    def add_edge(self, edge: GEdge) -> None:
        for nid in (edge.source, edge.target):
            if nid not in self.nodes:
                raise KeyError(f"edge references unknown node {nid}")
        idx = len(self.edges)
        self.edges.append(edge)
        self._adj[edge.source].append(idx)
        if edge.edge_type != "same_entity_as":
            pass  # directed by default

    def neighbors(self, node_id: str) -> list[str]:
        return sorted({self.edges[i].target for i in self._adj.get(node_id, [])})

    def to_dict(self) -> dict:
        return {
            "nodes": [{"id": n.id, "label": n.label, "properties": n.properties}
                      for n in self.nodes.values()],
            "edges": [{"source": e.source, "target": e.target, "type": e.edge_type,
                       "confidence": e.confidence, "evidence_ids": e.evidence_ids}
                      for e in self.edges],
        }

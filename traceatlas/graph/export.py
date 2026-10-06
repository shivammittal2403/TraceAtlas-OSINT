"""Graph exports: JSON and Graphviz DOT (dependency-free)."""

from __future__ import annotations

from traceatlas.core.serialization import to_json
from traceatlas.graph.model import GraphModel


def export_json(graph: GraphModel) -> str:
    return to_json(graph.to_dict(), indent=2)


def export_dot(graph: GraphModel) -> str:
    lines = ["digraph traceatlas {"]
    for n in graph.nodes.values():
        lines.append(f'  "{n.id}" [label="{n.label}"];')
    for e in graph.edges:
        lines.append(f'  "{e.source}" -> "{e.target}" [label="{e.edge_type}"];')
    lines.append("}")
    return "\n".join(lines)

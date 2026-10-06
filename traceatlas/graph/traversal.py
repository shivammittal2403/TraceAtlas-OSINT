"""Deterministic graph traversals: BFS, shortest path, k-hop neighborhood."""

from __future__ import annotations

from collections import deque

from traceatlas.graph.model import GraphModel


def bfs_levels(graph: GraphModel, start: str) -> dict[str, int]:
    levels: dict[str, int] = {start: 0}
    queue = deque([start])
    while queue:
        cur = queue.popleft()
        for nxt in graph.neighbors(cur):
            if nxt not in levels:
                levels[nxt] = levels[cur] + 1
                queue.append(nxt)
    return levels


def shortest_path(graph: GraphModel, start: str, goal: str) -> list[str]:
    levels = bfs_levels(graph, start)
    if goal not in levels:
        return []
    # Reconstruct one shortest path by walking levels backwards.
    path = [goal]
    cur = goal
    while cur != start:
        target_level = levels[cur] - 1
        nxt = next(
            (n for n in graph.nodes
             if levels.get(n) == target_level and cur in graph.neighbors(n)),
            None,
        )
        if nxt is None:
            return []
        path.append(nxt)
        cur = nxt
    return list(reversed(path))


def k_hop(graph: GraphModel, start: str, k: int) -> set[str]:
    return {n for n, lvl in bfs_levels(graph, start).items() if 0 < lvl <= k}

"""Lightweight in-memory entity graph for V1."""

from __future__ import annotations

from collections import defaultdict
from typing import Any


class EntityGraph:
    """Simple directed multi-graph for entity relationships.

    Entities: users, hosts, IPs, databases, events, hypotheses
    Relationships: logged_into, accessed, connected_to, supports, etc.
    """

    def __init__(self) -> None:
        # adjacency: src -> list of (relation, dst, metadata)
        self._edges: dict[str, list[tuple[str, str, dict[str, Any]]]] = defaultdict(list)
        self._nodes: set[str] = set()

    def add_node(self, node_id: str) -> None:
        self._nodes.add(node_id)

    def add_edge(
        self,
        src: str,
        relation: str,
        dst: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._nodes.add(src)
        self._nodes.add(dst)
        self._edges[src].append((relation, dst, metadata or {}))

    def neighbors(self, node_id: str, relation: str | None = None) -> list[tuple[str, str, dict]]:
        edges = self._edges.get(node_id, [])
        if relation is None:
            return edges
        return [e for e in edges if e[0] == relation]

    def get_related_entities(self, node_id: str) -> set[str]:
        related = set()
        for _, dst, _ in self._edges.get(node_id, []):
            related.add(dst)
        # also reverse lookup (simple)
        for src, edges in self._edges.items():
            for rel, dst, _ in edges:
                if dst == node_id:
                    related.add(src)
        return related

    def clear(self) -> None:
        self._edges.clear()
        self._nodes.clear()

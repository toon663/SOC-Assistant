"""Short-term, long-term, and reasoning-graph memory for investigations."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class MemoryItem:
    key: str
    content: Any
    memory_type: str
    source: str = "system"
    created_at: str = field(default_factory=_now)
    confidence: float = 1.0


class MemoryStore:
    """In-memory context store with provenance and a lightweight graph.

    The interfaces map naturally to a persistent vector store, LlamaIndex,
    or Cognee graph when those services are introduced.
    """

    def __init__(self, short_term_limit: int = 1000):
        self.short_term: deque[MemoryItem] = deque(maxlen=short_term_limit)
        self.long_term: dict[str, MemoryItem] = {}
        self.reasoning_nodes: dict[str, dict[str, Any]] = {}
        self.reasoning_edges: list[tuple[str, str, str]] = []

    def remember_short(self, key: str, content: Any, source: str = "agent") -> MemoryItem:
        item = MemoryItem(key, content, "short_term", source)
        self.short_term.append(item)
        return item

    def remember_long(self, key: str, content: Any, source: str = "analyst", confidence: float = 1.0) -> MemoryItem:
        if not 0 <= confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")
        item = MemoryItem(key, content, "long_term", source, confidence=confidence)
        self.long_term[key] = item
        return item

    def add_reasoning_node(self, node_id: str, kind: str, value: Any, **metadata: Any) -> None:
        self.reasoning_nodes[node_id] = {"id": node_id, "kind": kind, "value": value, **metadata}

    def add_reasoning_edge(self, source: str, relation: str, target: str) -> None:
        if source not in self.reasoning_nodes or target not in self.reasoning_nodes:
            raise KeyError("both reasoning nodes must exist before adding an edge")
        self.reasoning_edges.append((source, relation, target))

    def recent(self, limit: int = 20) -> list[MemoryItem]:
        return list(self.short_term)[-limit:]

    def recall(self, key: str) -> Optional[MemoryItem]:
        for item in reversed(self.short_term):
            if item.key == key:
                return item
        return self.long_term.get(key)

    def context(self, limit: int = 20) -> dict[str, Any]:
        return {
            "short_term": [item.__dict__ for item in self.recent(limit)],
            "long_term": [item.__dict__ for item in self.long_term.values()],
            "reasoning_graph": {"nodes": list(self.reasoning_nodes.values()), "edges": self.reasoning_edges},
        }

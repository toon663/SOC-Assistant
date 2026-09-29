"""Dependency-free retrieval over MITRE/NIST-oriented knowledge documents."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Iterable, List


@dataclass
class KnowledgeDocument:
    document_id: str
    title: str
    text: str
    source: str
    tags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RetrievalResult:
    document_id: str
    title: str
    source: str
    score: float
    excerpt: str


class KnowledgeBase:
    """Lexical retrieval baseline with source and evidence tracking."""

    def __init__(self, documents: Iterable[KnowledgeDocument] = ()):
        self.documents: dict[str, KnowledgeDocument] = {}
        self.add_many(documents)

    def add(self, document: KnowledgeDocument) -> None:
        if not document.document_id or not document.text:
            raise ValueError("document_id and text are required")
        self.documents[document.document_id] = document

    def add_many(self, documents: Iterable[KnowledgeDocument]) -> None:
        for document in documents:
            self.add(document)

    def search(self, query: str, top_k: int = 5) -> list[RetrievalResult]:
        if not query.strip():
            return []
        if top_k <= 0:
            return []
        query_terms = self._terms(query)
        results = []
        for document in self.documents.values():
            terms = self._terms(f"{document.title} {document.text} {' '.join(document.tags)}")
            overlap = query_terms & terms
            score = len(overlap) / max(1, len(query_terms))
            if score:
                results.append(RetrievalResult(document.document_id, document.title, document.source, round(score, 4), document.text[:300]))
        return sorted(results, key=lambda item: item.score, reverse=True)[:top_k]

    @staticmethod
    def _terms(text: str) -> set[str]:
        return {term for term in re.findall(r"[a-z0-9_/-]+", text.lower()) if len(term) > 2}


def default_knowledge_base() -> KnowledgeBase:
    return KnowledgeBase(
        [
            KnowledgeDocument("attack-t1059", "Command and Scripting Interpreter", "Execution through command shells and scripting interpreters.", "MITRE ATT&CK", ["execution", "command"]),
            KnowledgeDocument("attack-t1078", "Valid Accounts", "Adversaries may use valid accounts to gain access and persist.", "MITRE ATT&CK", ["credential", "identity"]),
            KnowledgeDocument("nist-respond", "NIST CSF Respond", "Containment, mitigation, communications, and improvements are part of the Respond function.", "NIST CSF", ["response", "containment"]),
            KnowledgeDocument("d3fend-isolation", "Endpoint Isolation", "Endpoint isolation can limit lateral movement while preserving evidence.", "MITRE D3FEND", ["defense", "edr"]),
        ]
    )

"""Dependency-free retrieval over MITRE/NIST-oriented knowledge documents."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Iterable, List
from agents import DemoExternalSystems

from dataclasses import dataclass, field
from typing import Any


@dataclass
class MockSIEM:
    """Simulated Security Information and Event Management system."""

    events: list[dict[str, Any]] = field(default_factory=list)

    def ingest(self, event: dict[str, Any]) -> None:
        self.events.append(dict(event))

    def query(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.events[-limit:]


@dataclass
class MockEDR:
    """Simulated Endpoint Detection and Response system."""

    actions: list[dict[str, Any]] = field(default_factory=list)

    def isolate(self, host: str) -> dict[str, Any]:
        result = {
            "action": "isolate_endpoint",
            "target": host,
            "status": "simulated",
        }
        self.actions.append(result)
        return result


@dataclass
class MockIAM:
    """Simulated Identity and Access Management system."""

    actions: list[dict[str, Any]] = field(default_factory=list)

    def disable(self, user: str) -> dict[str, Any]:
        result = {
            "action": "disable_user",
            "target": user,
            "status": "simulated",
        }
        self.actions.append(result)
        return result


@dataclass
class MockTicketing:
    """Simulated incident ticketing system."""

    tickets: list[dict[str, Any]] = field(default_factory=list)

    def create(self, title: str, description: str) -> str:
        ticket_id = f"SOC-{len(self.tickets) + 1:05d}"

        self.tickets.append({
            "id": ticket_id,
            "title": title,
            "description": description,
        })

        return ticket_id


class IntegrationHub(DemoExternalSystems):
    """Local adapter for SIEM, EDR, IAM, and ticketing systems."""

    def __init__(self):
        self.siem = MockSIEM()
        self.edr = MockEDR()
        self.iam = MockIAM()
        self.ticketing = MockTicketing()

    def create_ticket(self, incident) -> str:
        return self.ticketing.create(
            incident.alert.get("title", "Security incident"),
            f"Incident {incident.incident_id}",
        )

    def isolate_endpoint(self, host=None):
        return self.edr.isolate(host or "unknown")

    def disable_user(self, user=None):
        return self.iam.disable(user or "unknown")

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

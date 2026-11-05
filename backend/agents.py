"""Multi-agent cybersecurity incident-response workflow.

The workflow follows the sequence shown in the architecture diagram:

1. Sentinel Agent: detect anomalies and normalize events.
2. Analyst Agent: enrich context, correlate, deduplicate, and triage risk.
3. Prognostic Agent: request threat intelligence and forecast the risk path.
4. BI Agent: estimate business impact and update operational metrics.
5. Orchestrator Agent: select a playbook, request approval when needed,
   initiate a response, and validate the resulting state.

This module uses standard-library Python only. Replace the demo adapters with
real SIEM, EDR, identity, threat-intelligence, and ticketing integrations.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Protocol
import hashlib
import ipaddress
import json
import math
import re


def utc_now() -> str:
    """Return a timezone-aware UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_SCORE = {
    Severity.LOW: 25,
    Severity.MEDIUM: 50,
    Severity.HIGH: 75,
    Severity.CRITICAL: 95,
}


@dataclass
class SecurityEvent:
    """An event received from a SIEM, EDR, identity system, or similar source."""

    event_id: str
    timestamp: str
    source: str
    event_type: str
    user: Optional[str] = None
    host: Optional[str] = None
    source_ip: Optional[str] = None
    destination: Optional[str] = None
    message: str = ""
    severity: Severity = Severity.LOW
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Incident:
    """Shared state passed between agents."""

    incident_id: str
    events: List[SecurityEvent]
    detected_at: str
    anomaly_score: float = 0.0
    alert: Dict[str, Any] = field(default_factory=dict)
    asset_context: Dict[str, Any] = field(default_factory=dict)
    risk_analysis: Dict[str, Any] = field(default_factory=dict)
    threat_intel: Dict[str, Any] = field(default_factory=dict)
    forecast: Dict[str, Any] = field(default_factory=dict)
    business_impact: Dict[str, Any] = field(default_factory=dict)
    response_options: List[Dict[str, Any]] = field(default_factory=list)
    selected_playbook: Optional[str] = None
    action_result: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)
    audit_log: List[Dict[str, Any]] = field(default_factory=list)

    def record(self, agent: str, action: str, **details: Any) -> None:
        self.audit_log.append(
            {"timestamp": utc_now(), "agent": agent, "action": action, **details}
        )


class ExternalSystems(Protocol):
    """Interface for SIEM, EDR, identity, threat-intelligence, and ticket systems."""

    def lookup_asset(self, user: Optional[str], host: Optional[str]) -> Dict[str, Any]: ...

    def lookup_ip_reputation(self, source_ip: Optional[str]) -> Dict[str, Any]: ...

    def create_ticket(self, incident: Incident) -> str: ...

    def isolate_endpoint(self, host: Optional[str]) -> Dict[str, Any]: ...

    def disable_user(self, user: Optional[str]) -> Dict[str, Any]: ...


class DemoExternalSystems:
    """Safe in-memory adapter for demonstrations and unit tests.

    Response actions only return simulated results; they do not change a real
    endpoint or account.
    """

    def lookup_asset(self, user: Optional[str], host: Optional[str]) -> Dict[str, Any]:
        high_value = bool(host and re.search(r"(prod|db|domain|finance|exec)", host, re.I))
        return {
            "user": user,
            "host": host,
            "asset_owner": "demo-owner",
            "criticality": "high" if high_value else "normal",
            "department": "Engineering" if user and "eng" in user.lower() else "Unknown",
        }

    def lookup_ip_reputation(self, source_ip: Optional[str]) -> Dict[str, Any]:
        if not source_ip:
            return {"ip": None, "reputation": "unknown", "risk_score": 0}
        try:
            address = ipaddress.ip_address(source_ip)
            if address.is_private or address.is_loopback:
                return {"ip": source_ip, "reputation": "internal", "risk_score": 5}
        except ValueError:
            return {"ip": source_ip, "reputation": "invalid", "risk_score": 50}
        return {"ip": source_ip, "reputation": "unknown", "risk_score": 20}

    def create_ticket(self, incident: Incident) -> str:
        return f"DEMO-{incident.incident_id[:8].upper()}"

    def isolate_endpoint(self, host: Optional[str]) -> Dict[str, Any]:
        return {"action": "isolate_endpoint", "target": host, "status": "simulated"}

    def disable_user(self, user: Optional[str]) -> Dict[str, Any]:
        return {"action": "disable_user", "target": user, "status": "simulated"}


class SentinelAgent:
    """Detect anomaly, generate a normalized alert, and log the incident."""

    name = "sentinel"

    def detect_anomaly(self, events: Iterable[SecurityEvent]) -> Incident:
        event_list = list(events)
        if not event_list:
            raise ValueError("At least one security event is required")

        severity_score = max(SEVERITY_SCORE[e.severity] for e in event_list)
        unusual_types = {e.event_type.lower() for e in event_list}
        repetition_bonus = min(20.0, max(0, len(event_list) - 1) * 5.0)
        diversity_bonus = 10.0 if len(unusual_types) > 1 else 0.0
        anomaly_score = min(100.0, severity_score * 0.7 + repetition_bonus + diversity_bonus)

        fingerprint = hashlib.sha256(
            "|".join(sorted(e.event_id for e in event_list)).encode()
        ).hexdigest()
        incident = Incident(
            incident_id=fingerprint,
            events=event_list,
            detected_at=utc_now(),
            anomaly_score=round(anomaly_score, 2),
        )
        incident.alert = {
            "title": f"Potential {event_list[0].event_type} incident",
            "normalized_event_count": len(event_list),
            "severity": self._severity_from_score(anomaly_score).value,
            "fingerprint": fingerprint,
        }
        incident.record(self.name, "detect_anomaly", anomaly_score=incident.anomaly_score)
        incident.record(self.name, "generate_alert", alert=incident.alert)
        incident.record(self.name, "log_incident", normalized_event_count=len(event_list))
        return incident

    @staticmethod
    def _severity_from_score(score: float) -> Severity:
        if score >= 85:
            return Severity.CRITICAL
        if score >= 65:
            return Severity.HIGH
        if score >= 40:
            return Severity.MEDIUM
        return Severity.LOW


class AnalystAgent:
    """Enrich events with asset context and triage correlated risk."""

    name = "analyst"

    def __init__(self, systems: ExternalSystems):
        self.systems = systems

    def analyze(self, incident: Incident) -> Incident:
        primary = incident.events[0]
        incident.asset_context = self.systems.lookup_asset(primary.user, primary.host)

        unique_keys = {
            (event.user, event.host, event.event_type, event.source_ip)
            for event in incident.events
        }
        duplicate_count = len(incident.events) - len(unique_keys)
        impact_modifier = 15 if incident.asset_context.get("criticality") == "high" else 0
        risk_score = min(
            100.0,
            incident.anomaly_score + impact_modifier + min(10, duplicate_count * 2),
        )
        incident.risk_analysis = {
            "risk_score": round(risk_score, 2),
            "correlated_events": len(unique_keys),
            "duplicates_removed": duplicate_count,
            "triage": "urgent" if risk_score >= 70 else "standard",
        }
        incident.record(self.name, "request_asset_context", context=incident.asset_context)
        incident.record(self.name, "analyze_risk_impact", analysis=incident.risk_analysis)
        return incident


class PrognosticAgent:
    """Check threat intelligence and forecast likely risk paths."""

    name = "prognostic"

    def __init__(self, systems: ExternalSystems):
        self.systems = systems

    def forecast_risk(self, incident: Incident) -> Incident:
        source_ip = incident.events[0].source_ip
        incident.threat_intel = self.systems.lookup_ip_reputation(source_ip)
        threat_score = float(incident.threat_intel.get("risk_score", 0))
        base_score = float(incident.risk_analysis.get("risk_score", incident.anomaly_score))
        forecast_score = min(100.0, base_score * 0.7 + threat_score * 0.3)
        path = ["credential misuse", "lateral movement", "data access"]
        if forecast_score < 50:
            path = ["contained anomaly"]
        incident.forecast = {
            "forecast_score": round(forecast_score, 2),
            "risk_path": path,
            "confidence": round(min(0.99, 0.55 + len(incident.events) * 0.05), 2),
        }
        incident.record(self.name, "request_threat_intel", threat_intel=incident.threat_intel)
        incident.record(self.name, "forecast_risk_path", forecast=incident.forecast)
        return incident


class BIAgent:
    """Assess business impact and calculate operational metrics."""

    name = "business_impact"

    def assess(self, incident: Incident) -> Incident:
        criticality = incident.asset_context.get("criticality", "normal")
        forecast_score = float(incident.forecast.get("forecast_score", 0))
        multiplier = 1.4 if criticality == "high" else 1.0
        impact_score = min(100.0, forecast_score * multiplier)
        incident.business_impact = {
            "impact_score": round(impact_score, 2),
            "criticality": criticality,
            "estimated_downtime_minutes": math.ceil(impact_score / 5),
            "affected_service": incident.events[0].destination or "unknown",
        }
        incident.record(self.name, "assess_business_impact", impact=incident.business_impact)
        return incident

    def update_metrics(self, incident: Incident) -> Incident:
        incident.metrics.update(
            {
                "incident_count": 1,
                "alert_to_action_seconds": None,
                "mttr_seconds": None,
                "risk_score": incident.forecast.get("forecast_score", 0),
            }
        )
        incident.record(self.name, "update_metrics", metrics=incident.metrics)
        return incident


class OrchestratorAgent:
    """Create a ticket, match a playbook, and execute approved actions."""

    name = "orchestrator"

    def __init__(self, systems: ExternalSystems, require_approval: bool = True):
        self.systems = systems
        self.require_approval = require_approval

    def create_risk_report(self, incident: Incident) -> Incident:
        ticket_id = self.systems.create_ticket(incident)
        incident.response_options = self._response_options(incident)
        incident.alert["ticket_id"] = ticket_id
        incident.record(self.name, "send_risk_report", ticket_id=ticket_id)
        return incident

    def evaluate_and_respond(
        self, incident: Incident, approved: bool = False
    ) -> Incident:
        incident.selected_playbook = self._select_playbook(incident)
        incident.record(
            self.name,
            "evaluate_response_options",
            selected_playbook=incident.selected_playbook,
        )

        if self.require_approval and not approved:
            incident.action_result = {
                "status": "approval_required",
                "playbook": incident.selected_playbook,
            }
            incident.record(self.name, "pause_for_approval")
            return incident

        primary = incident.events[0]
        actions = []
        if incident.selected_playbook in {"contain_endpoint", "contain_and_disable_user"}:
            actions.append(self.systems.isolate_endpoint(primary.host))
        if incident.selected_playbook == "contain_and_disable_user":
            actions.append(self.systems.disable_user(primary.user))
        incident.action_result = {"status": "executed", "actions": actions}
        incident.record(self.name, "initiate_response", actions=actions)
        incident.record(self.name, "confirm_action", action_result=incident.action_result)
        return incident

    def _select_playbook(self, incident: Incident) -> str:
        score = max(
            float(incident.business_impact.get("impact_score", 0)),
            float(incident.forecast.get("forecast_score", 0)),
        )
        if score >= 85 and incident.events[0].user:
            return "contain_and_disable_user"
        if score >= 60:
            return "contain_endpoint"
        return "monitor_and_investigate"

    def _response_options(self, incident: Incident) -> List[Dict[str, Any]]:
        return [
            {"playbook": "monitor_and_investigate", "requires_approval": False},
            {"playbook": "contain_endpoint", "requires_approval": True},
            {"playbook": "contain_and_disable_user", "requires_approval": True},
        ]


class SecurityOperationsPipeline:
    """Run the complete diagram workflow from events to a response decision."""

    def __init__(
        self,
        systems: Optional[ExternalSystems] = None,
        require_approval: bool = True,
    ):
        systems = systems or DemoExternalSystems()
        self.sentinel = SentinelAgent()
        self.analyst = AnalystAgent(systems)
        self.prognostic = PrognosticAgent(systems)
        self.bi = BIAgent()
        self.orchestrator = OrchestratorAgent(systems, require_approval=require_approval)

    def run(
        self, events: Iterable[SecurityEvent], approved: bool = False
    ) -> Incident:
        incident = self.sentinel.detect_anomaly(events)
        self.analyst.analyze(incident)
        self.prognostic.forecast_risk(incident)
        self.bi.assess(incident)
        self.orchestrator.create_risk_report(incident)
        self.orchestrator.evaluate_and_respond(incident, approved=approved)
        self.bi.update_metrics(incident)
        return incident


def incident_to_dict(incident: Incident) -> Dict[str, Any]:
    """Serialize an incident for an API, log sink, or dashboard."""
    result = asdict(incident)
    result["events"] = [asdict(event) for event in incident.events]
    for event in result["events"]:
        event["severity"] = event["severity"].value
    return result


def demo() -> None:
    """Run a harmless demonstration of the workflow."""
    events = [
        SecurityEvent(
            event_id="evt-001",
            timestamp=utc_now(),
            source="demo-siem",
            event_type="suspicious_login",
            user="eng-user@example.com",
            host="prod-db-01",
            source_ip="203.0.113.42",
            destination="database",
            message="Repeated login failures followed by a successful login",
            severity=Severity.HIGH,
        ),
        SecurityEvent(
            event_id="evt-002",
            timestamp=utc_now(),
            source="demo-edr",
            event_type="process_execution",
            user="eng-user@example.com",
            host="prod-db-01",
            source_ip="203.0.113.42",
            message="Unusual process launched after login",
            severity=Severity.HIGH,
        ),
    ]
    incident = SecurityOperationsPipeline(require_approval=True).run(events)
    print(json.dumps(incident_to_dict(incident), indent=2))


if __name__ == "__main__":
    demo()

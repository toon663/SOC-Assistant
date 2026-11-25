"""Multi-agent cybersecurity incident-response workflow.

The workflow follows the sequence shown in the architecture diagram:

1. Sentinel Agent: detect anomalies and normalize events.
2. Analyst Agent: enrich context, correlate, deduplicate, and triage risk.
3. Prognostic Agent: request threat intelligence and forecast the risk path.
4. BI Agent: estimate business impact and update operational metrics.
5. Orchestrator Agent: a trained model (orchestrator_model.py) scores each
   response action; policy-checked actions wait at the human verification gate,
   then run and are validated. Human decisions train the model further.

This module uses standard-library Python only. Replace the demo adapters with
real SIEM, EDR, identity, threat-intelligence, and ticketing integrations.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from copy import deepcopy
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Protocol
import hashlib
import ipaddress
import json
import logging
import math
import re

from analyst import RelatedEvent, triage
from anomaly import detect_anomalies
from models import ActionRequest, ModelValidationError
from orchestrator_model import ResponseModel, record_feedback
from playbooks import ACTIONS, KNOWN_PLAYBOOKS, NAMED_PLAYBOOKS, RESPONSE_ACTIONS, build_plan, incident_risk, steps_to_actions, targets_for
from policy_engine import PolicyEngine
from security_log import SecurityLogBatch


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
    # Probability (0-1) from an upstream detector such as the Random Forest in
    # Sentinel_Agent. None means the event was submitted without ML scoring.
    detector_score: Optional[float] = None


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
    # The Orchestrator's plan: route, deciding score, policy-checked steps.
    response_plan: Dict[str, Any] = field(default_factory=dict)
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

    def block_ip(self, source_ip: Optional[str]) -> Dict[str, Any]: ...

    def quarantine_file(self, host: Optional[str], file: Optional[str]) -> Dict[str, Any]: ...


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

    def block_ip(self, source_ip: Optional[str]) -> Dict[str, Any]:
        return {"action": "block_ip", "target": source_ip, "status": "simulated"}

    def quarantine_file(self, host: Optional[str], file: Optional[str]) -> Dict[str, Any]:
        return {"action": "quarantine_file", "target": file, "host": host, "status": "simulated"}


class SentinelAgent:
    """Detect anomaly, generate a normalized alert, and log the incident."""

    name = "sentinel"

    def inspect_computer(self, batch: SecurityLogBatch) -> List[SecurityEvent]:
        """Select Windows Security log findings for the existing pipeline."""
        return [
            SecurityEvent(
                event_id=finding["event_id"],
                timestamp=finding["timestamp"],
                source="windows-security-log",
                event_type=finding["event_type"],
                host=finding["host"],
                user=finding["user"],
                source_ip=finding["source_ip"],
                message=finding["message"],
                severity=Severity(finding["severity"]),
                metadata=finding,
            )
            for finding in detect_anomalies(batch)
        ]

    def detect_anomaly(self, events: Iterable[SecurityEvent]) -> Incident:
        event_list = list(events)
        if not event_list:
            raise ValueError("At least one security event is required")

        severity_score = max(self._event_signal(e) for e in event_list)
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
            "title": self._title(event_list[0]),
            "normalized_event_count": len(event_list),
            "severity": self._severity_from_score(anomaly_score).value,
            "fingerprint": fingerprint,
            "occurrence_count": len(event_list),
            "first_seen": min(e.timestamp for e in event_list),
            "last_seen": max(e.timestamp for e in event_list),
        }
        if any(e.detector_score is not None for e in event_list):
            incident.alert.update(self._detection_details(event_list))
        incident.record(self.name, "detect_anomaly", anomaly_score=incident.anomaly_score)
        incident.record(self.name, "generate_alert", alert=incident.alert)
        incident.record(self.name, "log_incident", normalized_event_count=len(event_list))
        return incident

    @staticmethod
    def _title(event: SecurityEvent) -> str:
        if event.metadata.get("sha256"):
            family = event.metadata.get("malware_family") or "unknown family"
            return f"Malware detected: {family} ({event.metadata.get('file_name') or event.metadata['sha256'][:12]})"
        return f"Potential {event.event_type} incident"

    @staticmethod
    def _event_signal(event: SecurityEvent) -> float:
        """Blend evidence-based severity with the detector's probability.

        The Random Forest is trained on weak labels and scores nearly every hit
        close to 1.0, so its probability cannot stand in for severity by itself.
        """
        severity_score = SEVERITY_SCORE[event.severity]
        if event.detector_score is None:
            return severity_score
        return 0.6 * severity_score + 0.4 * event.detector_score * 100

    @staticmethod
    def _detection_details(events: List[SecurityEvent]) -> Dict[str, Any]:
        techniques = sorted(
            {t for e in events for t in e.metadata.get("mitre_techniques", [])}
        )
        reasons = list(
            dict.fromkeys(r for e in events for r in e.metadata.get("reasons", []))
        )
        primary = events[0]
        details = {
            "summary": (
                f"Detector flagged events from "
                f"{primary.destination or primary.source} on "
                f"{primary.host or 'unknown host'}: {'; '.join(reasons) or 'model score'}."
            ),
            "detector_score": max(e.detector_score or 0.0 for e in events),
            "mitre_techniques": techniques,
            "detection_reasons": reasons,
        }
        if primary.metadata.get("sha256"):
            meta = primary.metadata
            details["malware"] = {
                key: meta.get(key)
                for key in (
                    "verdict", "malware_family", "family_probability", "family_candidates",
                    "sha256", "file_path", "file_name", "attack_tactics", "explanation",
                )
            }
            details["summary"] = f"{primary.message} {'; '.join(reasons)}."
        return details

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
    """Triage a Sentinel incident: verdict, priority, evidence, and next steps.

    The rules live in analyst.py. ``related`` is other activity on the same host
    (other incidents, other events from the same collection) used for correlation.
    """

    name = "analyst"

    def __init__(self, systems: ExternalSystems):
        self.systems = systems

    def analyze(self, incident: Incident, related: Iterable[RelatedEvent] = ()) -> Incident:
        primary = incident.events[0]
        incident.asset_context = self.systems.lookup_asset(primary.user, primary.host)
        incident.record(self.name, "request_asset_context", context=incident.asset_context)

        unique_keys = {
            (event.user, event.host, event.event_type, event.source_ip)
            for event in incident.events
        }
        analysis = triage(incident, related, incident.asset_context)
        analysis["correlated_events"] = len(unique_keys)
        analysis["duplicates_removed"] = len(incident.events) - len(unique_keys)
        analysis["triaged_at"] = utc_now()
        incident.risk_analysis = analysis
        incident.record(
            self.name,
            "correlate_and_deduplicate",
            correlations=len(analysis["correlations"]),
            duplicates_removed=analysis["duplicates_removed"],
        )
        incident.record(
            self.name,
            "analyze_risk_impact",
            verdict=analysis["verdict"],
            priority=analysis["priority"],
            risk_score=analysis["risk_score"],
        )
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
        # A classified malware family brings the ATT&CK tactics its samples typically show.
        tactics = incident.events[0].metadata.get("attack_tactics")
        if tactics:
            path = list(tactics)
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


_AUTO = object()


class OrchestratorAgent:
    """Evaluate response actions with a trained model and start the approved ones.

    ``response_model`` (orchestrator_model.py) scores every response action. The
    PolicyEngine checks each step when it is proposed and again before it runs,
    and the human verification gate approves or rejects the plan. Every human
    decision is also a training example: approved plans are reinforced, rejected
    actions are suppressed, and a rejected incident goes back for re-triage.
    """

    name = "orchestrator"
    OK_STATUSES = {"simulated", "success", "succeeded", "completed", "isolated", "disabled", "blocked", "quarantined"}

    def __init__(
        self,
        systems: ExternalSystems,
        require_approval: bool = True,
        policy: Optional[PolicyEngine] = None,
        response_model: Any = _AUTO,
        learn_from_decisions: bool = True,
        prognostic_observer: Any = None,
    ):
        self.systems = systems
        self.require_approval = require_approval
        self.policy = policy or PolicyEngine()
        self.model: Optional[ResponseModel] = ResponseModel.load() if response_model is _AUTO else response_model
        self.learn_from_decisions = learn_from_decisions
        self.prognostic_observer = prognostic_observer

    def _notify_prognostic_observer(self, incident: Incident) -> None:
        try:
            observer = self.prognostic_observer
            if observer is None:
                return
            if incident.risk_analysis.get("verdict") == "benign":
                observer.skip_benign(incident.incident_id)
                return
            # No Incident, systems, repository or plan reference crosses the
            # boundary. The observer only receives this detached JSON snapshot.
            observer.submit(deepcopy(incident_to_dict(incident)))
        except Exception:
            try:
                self.prognostic_observer.record_failure("observer_submission_failed")
            except Exception:
                pass  # Observer diagnostics cannot replace a legacy result.

    def create_risk_report(self, incident: Incident) -> Incident:
        ticket_id = incident.alert.get("ticket_id") or self.systems.create_ticket(incident)
        incident.alert["ticket_id"] = ticket_id
        incident.record(self.name, "send_risk_report", ticket_id=ticket_id)
        return incident

    def evaluate_and_respond(
        self, incident: Incident, approved: bool = False
    ) -> Incident:
        scores = features = None
        if self.model is not None:
            try:
                features = self.model.features(incident)
                scores = self.model.score(incident)
            except Exception:  # never leave an incident without a plan
                logging.getLogger(__name__).exception("Orchestrator model failed; using rule thresholds")
                scores = features = None
        plan = build_plan(
            incident, self.policy, scores,
            self.model.thresholds if scores is not None else None,
            self.model.info if scores is not None else None,
        )
        if features is not None:
            plan["features"] = features
        incident.response_options = plan.pop("options")
        incident.response_plan = plan
        incident.selected_playbook = plan["playbook"]
        incident.record(
            self.name,
            "evaluate_response_options",
            decided_by=plan["decided_by"],
            selected_playbook=incident.selected_playbook,
            scores={option["action"]: option["probability"] for option in incident.response_options},
            steps=[step["action"] for step in plan["steps"]],
            dropped_steps=[{"action": s["action"], "reason": s["policy"]["reason"]} for s in plan["dropped_steps"]],
        )

        if self.require_approval and not approved:
            incident.action_result = {
                "status": "approval_required",
                "playbook": incident.selected_playbook,
            }
            incident.record(self.name, "pause_for_approval")
            self._notify_prognostic_observer(incident)
            return incident

        result = self._execute_plan(incident)
        self._notify_prognostic_observer(result)
        return result

    def review_response(
        self, incident: Incident, decision: str, reviewer: str, reason: str
    ) -> Incident:
        """Human verification gate: run the stored plan, or reject it for re-triage."""
        if incident.action_result.get("status") != "approval_required":
            raise ValueError("This incident is no longer awaiting approval")
        if decision not in {"approve", "deny"}:
            raise ValueError("decision must be approve or deny")
        if not reviewer.strip() or not reason.strip():
            raise ValueError("reviewer and reason are required")
        approval = {
            "decision": decision,
            "reviewer": reviewer.strip(),
            "reason": reason.strip(),
            "decided_at": utc_now(),
        }
        incident.record("human", "response_decision", **approval, playbook=incident.selected_playbook)
        if decision == "deny":
            incident.action_result = {
                "status": "denied", "actions": [], "playbook": incident.selected_playbook,
                "feedback": "returned_for_retriage",
            }
            incident.record(self.name, "feedback_for_retriage", reason=approval["reason"])
        else:
            self._execute_plan(incident, approver=approval["reviewer"])
        incident.action_result["approval"] = approval
        self._learn(incident, approval)
        return incident

    def _learn(self, incident: Incident, approval: Dict[str, Any]) -> None:
        """Approve: the plan was right for every action. Deny: the proposed actions were wrong."""
        plan = incident.response_plan or {}
        features = plan.get("features")
        if not features:
            return
        proposed = set(steps_to_actions(plan.get("steps", [])))
        if approval["decision"] == "approve":
            labels = {action: int(action in proposed) for action in ACTIONS}
        elif proposed:
            labels = {action: 0 for action in proposed}
        else:
            return  # a rejected "monitor only" plan says more was needed, not which action
        record_feedback(features, labels, {**approval, "incident_id": incident.incident_id, "playbook": incident.selected_playbook})
        if self.model is not None and self.learn_from_decisions:
            try:
                self.model.learn(features, labels)
            except Exception:
                logging.getLogger(__name__).exception("Orchestrator online update failed")
                return
        incident.record(self.name, "learn_from_decision", labels=labels)

    def _execute_plan(self, incident: Incident, approver: Optional[str] = None) -> Incident:
        """Run exactly the reviewed steps, re-checking policy, then validate each result."""
        if incident.selected_playbook not in KNOWN_PLAYBOOKS:
            raise ValueError("Unknown response playbook")
        plan = incident.response_plan or self._legacy_plan(incident)
        named = {name: set(actions) for actions, (name, _) in NAMED_PLAYBOOKS.items()}
        planned = set(steps_to_actions(plan.get("steps", [])))
        if incident.selected_playbook in named and planned != named[incident.selected_playbook]:
            raise ValueError("The stored plan does not match its playbook; re-run the Orchestrator")
        risk = float(plan.get("risk_score", 0))
        actions = []
        for step in plan.get("steps", []):
            if step["action"] not in RESPONSE_ACTIONS:
                continue
            try:
                request = ActionRequest(
                    action=step["action"], incident_id=incident.incident_id, target=step["target"],
                    risk_score=min(100.0, risk), confidence=min(100.0, float(step.get("probability") or 1.0) * 100),
                    approved_by=approver,
                )
                decision = self.policy.approve(request, approver) if approver else self.policy.evaluate(request)
                blocked = not decision.allowed or (decision.requires_approval and self.require_approval)
                reason = decision.reason
            except ModelValidationError as exc:
                blocked, reason = True, str(exc)
            if blocked:
                actions.append({"action": step["action"], "target": step["target"], "status": "blocked_by_policy", "reason": reason, "validated": False})
                continue
            result = self._run(step, incident)
            result["validated"] = self._validate(step, result)
            actions.append(result)

        if not actions or all(a["validated"] for a in actions):
            status = "executed"
        elif all(a["status"] == "blocked_by_policy" for a in actions):
            status = "blocked_by_policy"
        else:
            status = "action_failed"
        incident.action_result = {"status": status, "actions": actions, "playbook": incident.selected_playbook, "executed_at": utc_now()}
        incident.record(self.name, "initiate_response", actions=actions)
        incident.record(
            self.name, "confirm_action", status=status,
            failed=[a["action"] for a in actions if not a["validated"]],
        )
        return incident

    def _run(self, step: Dict[str, Any], incident: Incident) -> Dict[str, Any]:
        action, target = step["action"], step["target"]
        calls = {
            "isolate_endpoint": lambda: self.systems.isolate_endpoint(target),
            "disable_user": lambda: self.systems.disable_user(target),
            "block_ip": lambda: self.systems.block_ip(target),
            "quarantine_file": lambda: self.systems.quarantine_file(incident.events[0].host, target),
        }
        try:
            return dict(calls[action]())
        except AttributeError:
            return {"action": action, "target": target, "status": "unsupported"}
        except Exception as exc:  # report a failed integration instead of losing the other steps
            return {"action": action, "target": target, "status": "failed", "error": str(exc)}

    def _validate(self, step: Dict[str, Any], result: Dict[str, Any]) -> bool:
        return str(result.get("status", "")).lower() in self.OK_STATUSES and str(result.get("target")) == str(step["target"])

    @staticmethod
    def _legacy_plan(incident: Incident) -> Dict[str, Any]:
        """Incidents stored before the trained Orchestrator only carry a playbook name."""
        targets = targets_for(incident)
        actions = {
            "contain_endpoint": ["isolate_endpoint"],
            "contain_and_disable_user": ["isolate_endpoint", "disable_user"],
        }.get(incident.selected_playbook, [])
        return {
            "risk_score": incident_risk(incident),
            "steps": [
                {"action": action, "target": targets[RESPONSE_ACTIONS[action].target] or "unknown", "probability": 1.0}
                for action in actions
            ],
        }


class SecurityOperationsPipeline:
    """Run the complete diagram workflow from events to a response decision."""

    def __init__(
        self,
        systems: Optional[ExternalSystems] = None,
        require_approval: bool = True,
        response_model: Any = _AUTO,
    ):
        systems = systems or DemoExternalSystems()
        self.sentinel = SentinelAgent()
        self.analyst = AnalystAgent(systems)
        self.prognostic = PrognosticAgent(systems)
        self.bi = BIAgent()
        self.orchestrator = OrchestratorAgent(systems, require_approval=require_approval, response_model=response_model)

    def run(
        self,
        events: Iterable[SecurityEvent],
        approved: bool = False,
        continues: Optional[Dict[str, Any]] = None,
        related: Iterable[RelatedEvent] = (),
        occurrences: Optional[int] = None,
    ) -> Incident:
        """Run the workflow; ``continues`` is a stored incident to re-assess in place.

        ``related`` is other activity on the host that the Analyst correlates with.
        ``occurrences`` is the exact repeat count when ``events`` is capped evidence.
        """
        incident = self.sentinel.detect_anomaly(events)
        if occurrences:
            incident.alert["occurrence_count"] = occurrences
        if continues:
            incident.incident_id = continues["incident_id"]
            incident.detected_at = continues["detected_at"]
            incident.alert["fingerprint"] = continues["incident_id"]
            incident.alert["ticket_id"] = continues.get("alert", {}).get("ticket_id")
            incident.audit_log = continues.get("audit_log", []) + incident.audit_log
        self.analyst.analyze(incident, related)
        return self.reassess(incident, approved=approved)

    def reassess(self, incident: Incident, approved: bool = False) -> Incident:
        """Run the agents after the Analyst, e.g. after a Claude review changed the triage."""
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


def incident_from_dict(data: Dict[str, Any]) -> Incident:
    """Rebuild an Incident from ``incident_to_dict`` output (e.g. a stored payload)."""
    names = {item.name for item in fields(Incident)}
    events = [SecurityEvent(**{**event, "severity": Severity(event["severity"])}) for event in data["events"]]
    return Incident(**{**{key: value for key, value in data.items() if key in names}, "events": events})


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

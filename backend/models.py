"""Validated data models shared by the cybersecurity agent services.

The existing ``agents.py`` module contains runtime workflow objects.  This
module provides boundary models for APIs, queues, databases, and policy
decisions without adding a third-party dependency.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional


class ModelValidationError(ValueError):
    """Raised when untrusted data does not satisfy a model's constraints."""


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionType(str, Enum):
    MONITOR = "monitor"
    CREATE_TICKET = "create_ticket"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    DISABLE_USER = "disable_user"
    BLOCK_IP = "block_ip"
    DELETE_DATA = "delete_data"


def _required(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ModelValidationError(f"{field_name} must be a non-empty string")
    return value.strip()


def _score(value: Any, field_name: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ModelValidationError(f"{field_name} must be numeric") from exc
    if not 0 <= number <= 100:
        raise ModelValidationError(f"{field_name} must be between 0 and 100")
    return round(number, 2)


def _timestamp(value: Any) -> str:
    value = _required(value, "timestamp")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ModelValidationError("timestamp must be ISO-8601 formatted") from exc
    return value


@dataclass
class EventModel:
    """Normalized security event accepted at the ingestion boundary."""

    event_id: str
    timestamp: str
    source: str
    event_type: str
    severity: Severity = Severity.LOW
    user: Optional[str] = None
    host: Optional[str] = None
    source_ip: Optional[str] = None
    message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.event_id = _required(self.event_id, "event_id")
        self.timestamp = _timestamp(self.timestamp)
        self.source = _required(self.source, "source")
        self.event_type = _required(self.event_type, "event_type")
        if isinstance(self.severity, str):
            try:
                self.severity = Severity(self.severity.lower())
            except ValueError as exc:
                raise ModelValidationError("invalid severity") from exc
        if not isinstance(self.severity, Severity):
            raise ModelValidationError("severity must be a Severity value")
        if not isinstance(self.metadata, dict):
            raise ModelValidationError("metadata must be a dictionary")

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["severity"] = self.severity.value
        return result


@dataclass
class IncidentModel:
    """Portable incident summary used by storage and evaluation code."""

    incident_id: str
    detected_at: str
    events: List[EventModel] = field(default_factory=list)
    anomaly_score: float = 0.0
    risk_score: float = 0.0
    confidence: float = 0.0
    status: str = "open"
    mitre_techniques: List[str] = field(default_factory=list)
    explanation: str = ""

    def __post_init__(self) -> None:
        self.incident_id = _required(self.incident_id, "incident_id")
        self.detected_at = _timestamp(self.detected_at)
        self.anomaly_score = _score(self.anomaly_score, "anomaly_score")
        self.risk_score = _score(self.risk_score, "risk_score")
        self.confidence = _score(self.confidence, "confidence")
        if self.status not in {"open", "triaged", "contained", "resolved", "closed"}:
            raise ModelValidationError("invalid incident status")
        if not self.events:
            raise ModelValidationError("incident must contain at least one event")

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["events"] = [event.to_dict() for event in self.events]
        return result


@dataclass
class ActionRequest:
    """A proposed action before it reaches an external system."""

    action: ActionType
    incident_id: str
    target: str
    risk_score: float
    confidence: float
    requested_by: str = "orchestrator"
    approved_by: Optional[str] = None
    reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.action, str):
            try:
                self.action = ActionType(self.action.lower())
            except ValueError as exc:
                raise ModelValidationError("invalid action") from exc
        if not isinstance(self.action, ActionType):
            raise ModelValidationError("action must be an ActionType value")
        self.incident_id = _required(self.incident_id, "incident_id")
        self.target = _required(self.target, "target")
        self.requested_by = _required(self.requested_by, "requested_by")
        self.risk_score = _score(self.risk_score, "risk_score")
        self.confidence = _score(self.confidence, "confidence")


@dataclass(frozen=True)
class PolicyDecision:
    """Auditable result of evaluating an action request."""

    allowed: bool
    requires_approval: bool
    reason: str
    policy_id: str
    action: str
    incident_id: str

    @property
    def executable(self) -> bool:
        return self.allowed and not self.requires_approval


def model_from_mapping(data: Mapping[str, Any]) -> EventModel:
    """Construct an ``EventModel`` from a JSON-like mapping."""
    return EventModel(**dict(data))

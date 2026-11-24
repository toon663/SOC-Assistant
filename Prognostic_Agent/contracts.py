"""Validated JSON contracts and canonical input identity.

The canonical form sorts unordered collections and object keys, normalizes UTC
timestamps and numeric fields, and excludes the transport-only request_id.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import re
from typing import Any

TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
ENTITY_TYPES = {"user", "host", "service"}


def utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timezone_required")
    return parsed.astimezone(timezone.utc)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def content_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class RequestValidationError(ValueError):
    def __init__(self, errors):
        super().__init__("Invalid Analyst alert")
        self.errors = errors


def validation_error(payload, errors, *, metadata=None):
    from .provenance import provenance
    payload = payload if isinstance(payload, dict) else {}
    return {
        **(metadata or provenance()), "response_type": "validation_error",
        "request_id": payload.get("request_id") if isinstance(payload.get("request_id"), str) else None,
        "alert_id": payload.get("alert_id") if isinstance(payload.get("alert_id"), str) else None,
        "errors": errors,
    }


@dataclass(frozen=True)
class AnalystAlert:
    data: dict
    input_fingerprint: str

    @classmethod
    def from_dict(cls, payload):
        errors = []

        def issue(field, code, message):
            errors.append({"field": field, "code": code, "message": message})

        if not isinstance(payload, dict):
            raise RequestValidationError([{"field": "$", "code": "object_required", "message": "Provide a JSON object."}])
        # Round trip validates that metadata is finite, portable JSON too.
        try:
            data = json.loads(canonical_json(payload))
        except (ValueError, TypeError):
            raise RequestValidationError([{"field": "$", "code": "invalid_json_value", "message": "Only finite JSON values are accepted."}]) from None

        def text(obj, key, prefix="", required=True):
            value = obj.get(key)
            if value is None and not required:
                obj[key] = None
                return
            if not isinstance(value, str) or not value.strip():
                issue(prefix + key, "string_required", "Provide a nonempty string.")
            else:
                obj[key] = value.strip()

        def stamp(obj, key, prefix=""):
            value = obj.get(key)
            try:
                obj[key] = utc_text(parse_time(value))
            except (AttributeError, TypeError, ValueError) as exc:
                code = "timezone_required" if str(exc) == "timezone_required" else "invalid_timestamp"
                issue(prefix + key, code, "Provide a timezone-aware ISO-8601 timestamp.")

        def number(key, upper):
            value = data.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= upper or not math.isfinite(value):
                issue(key, "invalid_score", f"Provide a finite number in [0, {upper}].")
            else:
                data[key] = float(value)

        def array(obj, key, prefix="", required=False):
            if required and key not in obj:
                issue(prefix + key, "field_required", "This array is required (it may be empty).")
            value = obj.get(key, [])
            if not isinstance(value, list):
                issue(prefix + key, "array_required", "Provide an array.")
                value = []
            obj[key] = value
            return value

        if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
            issue("schema_version", "unsupported_version", "schema_version must be 1.")
        text(data, "alert_id")
        text(data, "request_id", required=False)
        text(data, "analyst_revision")
        stamp(data, "timestamp")
        for key in ("user_id", "host_id", "source_ip"):
            text(data, key, required=False)
        number("anomaly_score", 100)
        if data.get("triage_score", "missing") is not None:
            number("triage_score", 100)
        source = data.setdefault("behavioral_score_source", "supplied" if data.get("triage_score") is not None else "unknown")
        if source not in ("unknown", "supplied") or (source == "supplied" and data.get("triage_score") is None) or (source == "unknown" and data.get("triage_score") is not None):
            issue("behavioral_score_source", "invalid_score_source", "Use supplied with an asset-independent score, or unknown with a null score.")
        number("analyst_confidence", 1)
        if data.get("verdict") not in ("benign", "suspicious", "malicious"):
            issue("verdict", "invalid_verdict", "Use benign, suspicious, or malicious.")
        ids = set()
        entities = array(data, "entities", required=True)
        for index, entity in enumerate(entities):
            prefix = f"entities[{index}]."
            if not isinstance(entity, dict):
                issue(prefix[:-1], "object_required", "Provide an entity object.")
                continue
            text(entity, "entity_id", prefix)
            if not isinstance(entity.get("entity_type"), str) or entity["entity_type"] not in ENTITY_TYPES:
                issue(prefix + "entity_type", "invalid_entity_type", "Use user, host, or service.")
            identity = entity.get("entity_id")
            if isinstance(identity, str):
                if identity in ids:
                    issue(prefix + "entity_id", "duplicate_identity", "Entity IDs must be unique.")
                ids.add(identity)
        for key, entity_type in (("user_id", "user"), ("host_id", "host")):
            value = data.get(key)
            if isinstance(value, str) and not any(isinstance(e, dict) and e.get("entity_id") == value and e.get("entity_type") == entity_type for e in entities):
                issue(key, "unresolved_reference", "Primary entity must appear in entities with the correct type.")
        event_ids = set()
        events = array(data, "normalized_events", required=True)
        for index, event in enumerate(events):
            prefix = f"normalized_events[{index}]."
            if not isinstance(event, dict):
                issue(prefix[:-1], "object_required", "Provide an event object.")
                continue
            text(event, "event_id", prefix)
            text(event, "event_type", prefix)
            stamp(event, "timestamp", prefix)
            identity = event.get("event_id")
            if isinstance(identity, str):
                if identity in event_ids:
                    issue(prefix + "event_id", "duplicate_identity", "Event IDs must be unique; the Analyst owns deduplication.")
                event_ids.add(identity)
            refs = array(event, "entity_ids", prefix)
            if any(not isinstance(ref, str) or ref not in ids for ref in refs):
                issue(prefix + "entity_ids", "unresolved_reference", "Reference supplied entities only.")
            elif len(refs) != len(set(refs)):
                issue(prefix + "entity_ids", "duplicate_reference", "Entity references must be unique.")
        techniques = array(data, "observed_techniques", required=True)
        technique_ids = set()
        for index, technique in enumerate(techniques):
            prefix = f"observed_techniques[{index}]."
            if not isinstance(technique, dict):
                issue(prefix[:-1], "object_required", "Provide a technique object.")
                continue
            identity = technique.get("technique_id")
            if not isinstance(identity, str) or not TECHNIQUE.fullmatch(identity):
                issue(prefix + "technique_id", "invalid_technique_id", "Use an ATT&CK ID such as T1059.001.")
            elif identity in technique_ids:
                issue(prefix + "technique_id", "duplicate_identity", "Starting technique IDs must be unique.")
            else:
                technique_ids.add(identity)
            refs = array(technique, "evidence_refs", prefix)
            attribution = technique.setdefault("attribution", "exact")
            if attribution not in ("exact", "coarse"):
                issue(prefix + "attribution", "invalid_attribution", "Use exact or coarse.")
            if attribution == "coarse" and refs:
                issue(prefix + "evidence_refs", "coarse_attribution_has_refs", "Coarse attribution cannot assert event-level evidence.")
            if any(not isinstance(ref, str) or ref not in event_ids for ref in refs):
                issue(prefix + "evidence_refs", "unresolved_reference", "Reference supplied event IDs only.")
            elif len(refs) != len(set(refs)):
                issue(prefix + "evidence_refs", "duplicate_reference", "Evidence references must be unique.")
        correlated = array(data, "correlated_alert_ids")
        if any(not isinstance(ref, str) or not ref.strip() for ref in correlated):
            issue("correlated_alert_ids", "invalid_reference", "Use nonempty alert IDs.")
        elif len(correlated) != len(set(correlated)):
            issue("correlated_alert_ids", "duplicate_reference", "Alert references must be unique.")
        findings = array(data, "findings")
        if any(not isinstance(item, str) for item in findings):
            issue("findings", "string_required", "Findings must be strings.")
        adapter_issues = array(data, "adapter_issues")
        if any(not isinstance(item, dict) or not isinstance(item.get("code"), str) for item in adapter_issues):
            issue("adapter_issues", "invalid_issue", "Each adapter issue needs a string code.")
        if errors:
            raise RequestValidationError(errors)
        if "guard_context" in data:
            from .guard_context import normalize_guard_context
            try:
                data["guard_context"] = normalize_guard_context(data["guard_context"], data)
            except ValueError as exc:
                raise RequestValidationError([{"field": "guard_context", "code": "invalid_guard_context", "message": str(exc)}]) from None
        # Normalize only collections defined as unordered by this contract.
        data["entities"] = sorted(entities, key=lambda e: e["entity_id"])
        data["normalized_events"] = sorted(events, key=lambda e: e["event_id"])
        for event in events:
            event["entity_ids"].sort()
        data["observed_techniques"] = sorted(techniques, key=lambda t: t["technique_id"])
        for technique in techniques:
            technique["evidence_refs"].sort()
        data["correlated_alert_ids"].sort()
        data["findings"].sort()
        identity = {key: value for key, value in data.items() if key != "request_id"}
        return cls(data, content_hash(identity))


def validate_response(response):
    """Check response invariants at both the CLI and library boundary."""
    if response["response_type"] == "validation_error":
        if not response["errors"] or "status" in response:
            raise ValueError("Invalid validation-error envelope")
        return response
    for key, choices in {
        "response_type": {"risk_forecast"},
        "status": {"complete", "partial", "abstained"},
        "numeric_assessment_status": {"complete", "partial", "unavailable"},
        "explanation_status": {"deterministic", "llm_selected", "unavailable"},
    }.items():
        if response.get(key) not in choices:
            raise ValueError("Invalid response " + key)
    if not response["reason"] or not response["reason_detail"]:
        raise ValueError("Response reason is required")
    if response["status"] == "abstained" and (response["predicted_path"] is not None or response["likelihood"] is not None):
        raise ValueError("Abstained forecasts cannot have a selected path or likelihood")
    if response["risk_score"] is not None and not 0 <= response["risk_score"] <= 100:
        raise ValueError("Risk score out of range")
    canonical_json(response)
    return response

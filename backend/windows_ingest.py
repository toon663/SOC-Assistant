"""Bridge Event_Gatherer and Sentinel_Agent into the multi-agent pipeline.

Flow: Windows Event Viewer -> gatherer -> Random Forest -> SecurityEvent ->
incident grouping -> Sentinel/Analyst/Prognostic/BI/Orchestrator -> SQLite.

The gatherer and detector stay importable as standalone CLIs, so they are loaded
from their sibling folders. The ML imports are lazy because the rest of the
backend runs on the standard library alone.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import sys
import threading
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

from agents import SecurityEvent, SecurityOperationsPipeline, Severity, utc_now
from database import IncidentRepository
from file_scan import MALWARE_LOG_NAME, FileScanService, result_to_event


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_THRESHOLD = 0.55
# Newest events kept as evidence per incident; the dashboard loads every stored
# event, so noisy sources must not grow without bound. Counts stay exact.
MAX_STORED_EVENTS = 50

# Appended, not prepended, so backend modules such as models.py keep priority.
for _folder in ("Event_Gatherer", "Sentinel_Agent"):
    _path = str(REPO_ROOT / _folder)
    if _path not in sys.path:
        sys.path.append(_path)

from threat_intel import SEED_SUSPICIOUS_EVENT_IDS, load_catalog  # noqa: E402 - needs the path above; stdlib only


WINDOWS_EVENT_TYPES = {
    104: "event_log_cleared",
    1102: "audit_log_cleared",
    4616: "system_time_changed",
    4625: "failed_logon",
    4648: "explicit_credential_logon",
    4672: "special_privileges_assigned",
    4688: "process_creation",
    4697: "service_installed",
    4698: "scheduled_task_created",
    4720: "user_account_created",
    4722: "user_account_enabled",
    4728: "group_member_added",
    4732: "group_member_added",
    4756: "group_member_added",
    4768: "kerberos_tgt_requested",
    4769: "kerberos_service_ticket_requested",
    4771: "kerberos_preauth_failed",
    4776: "ntlm_credential_validation",
    7045: "service_installed",
}

LOG_CLEARED_EVENT_IDS = {104, 1102}
# Logon and privilege events that Windows emits constantly for service identities.
ROUTINE_FOR_SERVICE_ACCOUNTS = {4624, 4672}

# Service identities are never valid targets for a disable-user playbook.
NON_HUMAN_ACCOUNTS = {
    "S-1-5-18", "S-1-5-19", "S-1-5-20",
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON",
}

ACCOUNT_NAME_RE = re.compile(r"Account Name:\s*(\S[^\r\n]*)")
SOURCE_IP_RE = re.compile(
    r"(?:Source Network Address|Source Address|Client Address):\s*(?:::ffff:)?([0-9A-Fa-f:.]+)"
)


class IngestUnavailable(RuntimeError):
    """The host cannot run collection or detection (wrong OS or missing packages)."""


def _is_human_account(name: str) -> bool:
    return bool(name) and name != "-" and not name.endswith("$") and name.upper() not in NON_HUMAN_ACCOUNTS


def extract_user(event: dict[str, Any]) -> Optional[str]:
    """Prefer the named account in the message; Security events often have no userId."""
    names = [name.strip() for name in ACCOUNT_NAME_RE.findall(str(event.get("message") or ""))]
    # In Windows messages the last block names the target account (4625, 4624, ...).
    for name in reversed(names):
        if _is_human_account(name):
            return name
    if names:
        return None
    user_id = event.get("userId")
    return user_id if user_id and _is_human_account(str(user_id)) else None


def extract_source_ip(message: str) -> Optional[str]:
    match = SOURCE_IP_RE.search(message or "")
    if not match:
        return None
    try:
        address = ipaddress.ip_address(match.group(1))
    except ValueError:
        return None
    return None if address.is_loopback or address.is_unspecified else str(address)


def severity_for(anomaly: dict[str, Any]) -> Severity:
    """Derive severity from Windows and threat-intel evidence, not the model score."""
    event = anomaly["event"]
    event_id = event.get("eventId")
    level = event.get("level")
    has_cve = any(match.get("type") == "cve" for match in anomaly.get("cisaMatches") or [])
    has_mitre = bool(anomaly.get("mitreTechniques"))

    if level == 1 or has_cve or event_id in LOG_CLEARED_EVENT_IDS:
        return Severity.CRITICAL
    if event_id in ROUTINE_FOR_SERVICE_ACCOUNTS and extract_user(event) is None:
        return Severity.LOW
    # Uses the curated seed IDs, not the catalog-derived list: low catalog IDs such
    # as 1 are Sysmon codes that collide with unrelated System/Application events.
    if event_id in SEED_SUSPICIOUS_EVENT_IDS or (has_mitre and event.get("logName") == "Security"):
        return Severity.HIGH
    if level == 2 or has_mitre or anomaly.get("cisaMatches"):
        return Severity.MEDIUM
    return Severity.LOW


def anomaly_to_event(anomaly: dict[str, Any]) -> SecurityEvent:
    """Convert a Sentinel_Agent anomaly into the backend's SecurityEvent."""
    event = anomaly["event"]
    host = anomaly.get("computerName")
    log_name = event.get("logName") or "unknown"
    windows_event_id = event.get("eventId")
    message = event.get("message") or ""
    timestamp = event.get("timeCreatedUtc") or anomaly.get("detectedAtUtc") or utc_now()
    return SecurityEvent(
        # The timestamp guards against record IDs restarting after a log reset.
        event_id=f"{host}:{log_name}:{event.get('recordId')}:{timestamp}",
        timestamp=timestamp,
        source=f"windows-eventlog:{log_name}",
        event_type=WINDOWS_EVENT_TYPES.get(windows_event_id, f"windows_event_{windows_event_id}"),
        user=extract_user(event),
        host=host,
        source_ip=extract_source_ip(message),
        destination=event.get("provider") or None,
        message=message,
        severity=severity_for(anomaly),
        detector_score=anomaly.get("modelScore"),
        metadata={
            "windows_event_id": windows_event_id,
            "record_id": event.get("recordId"),
            "log_name": log_name,
            "level_name": event.get("levelName"),
            "mitre_techniques": list(anomaly.get("mitreTechniques") or []),
            "cisa_matches": list(anomaly.get("cisaMatches") or []),
            "reasons": list(anomaly.get("reasons") or []),
            "detector": anomaly.get("model"),
        },
    )


def group_key(event: SecurityEvent) -> str:
    """Identify repeats of one event per host, channel, event ID, and user.

    User stays in the key because the Orchestrator acts on the first event's user,
    so one incident must not mix accounts. Malware detections group per host and file.
    """
    if event.metadata.get("sha256"):
        return f"{event.host}|{MALWARE_LOG_NAME}|{event.metadata['sha256']}"
    return "|".join(
        str(part)
        for part in (event.host, event.metadata.get("log_name"), event.metadata.get("windows_event_id"), event.user)
    )


def group_events(events: Iterable[SecurityEvent]) -> list[list[SecurityEvent]]:
    groups: dict[str, list[SecurityEvent]] = {}
    for event in events:
        groups.setdefault(group_key(event), []).append(event)
    return list(groups.values())


def _restore_event(stored: dict[str, Any]) -> SecurityEvent:
    return SecurityEvent(**{**stored, "severity": Severity(stored["severity"])})


def _load_detector() -> Any:
    try:
        import anomaly_agent
    except ImportError as error:
        raise IngestUnavailable(
            f"Detector dependency missing ({error}). Run: pip install -r requirements.txt"
        ) from error
    return anomaly_agent


class WindowsIngestService:
    """Run collection and detection, then feed new anomalies through the agents."""

    def __init__(
        self,
        pipeline: SecurityOperationsPipeline,
        repository: IncidentRepository,
        file_scan: Optional[FileScanService] = None,
    ):
        self.pipeline = pipeline
        self.repository = repository
        # Scans executables from process-creation events; models load on first use.
        self.file_scan = file_scan or FileScanService()
        # Serializes ingests so concurrent requests cannot both process one event.
        self._lock = threading.Lock()

    def collect_and_ingest(
        self,
        *,
        logs: Optional[Sequence[str]] = None,
        hours: int = 24,
        max_events_per_log: int = 500,
        threshold: float = DEFAULT_THRESHOLD,
    ) -> dict[str, Any]:
        if platform.system() != "Windows":
            raise IngestUnavailable("Live collection needs Windows Event Viewer; use /ingest/document instead.")
        import gatherer

        document = gatherer.collect_document(
            logs or gatherer.DEFAULT_LOGS,
            hours=hours,
            max_events_per_log=max_events_per_log,
        )
        return self.ingest_document(document, threshold=threshold, source="live-collection")

    def ingest_document(
        self,
        document: dict[str, Any],
        *,
        threshold: float = DEFAULT_THRESHOLD,
        source: str = "uploaded-document",
    ) -> dict[str, Any]:
        raw_events = document.get("events")
        if not isinstance(raw_events, list) or not all(isinstance(item, dict) for item in raw_events):
            raise ValueError("document must contain an events list of objects")

        summary: dict[str, Any] = {
            "source": source,
            "events_scanned": len(raw_events),
            "anomalies_detected": 0,
            "malware_detected": 0,
            "duplicates_skipped": 0,
            "threat_intel_loaded": False,
            "incidents": [],
            "errors": document.get("errors") or [],
        }
        if not raw_events:
            return summary

        anomaly_agent = _load_detector()
        # Never downloads during a request: without a cache, the seed heuristics apply.
        catalog = load_catalog()
        summary["threat_intel_loaded"] = catalog is not None

        with self._lock:
            anomalies = anomaly_agent.detect_anomalies(
                raw_events,
                source_path=Path(source),
                computer_name=document.get("computerName"),
                catalog=catalog,
                threshold=threshold,
            )
            events = {event.event_id: event for event in map(anomaly_to_event, anomalies)}
            malware_events, summary["malware_scan"] = self.file_scan.scan_process_events(
                raw_events, host=document.get("computerName"), user_for=extract_user
            )
            summary["malware_detected"] = len(malware_events)
            for event in malware_events:
                events.setdefault(event.event_id, event)
            new_events = [
                event for event_id, event in events.items()
                if not self.repository.is_event_ingested(event_id)
            ]
            summary["anomalies_detected"] = len(anomalies)
            summary["duplicates_skipped"] = len(events) - len(new_events)

            for group in group_events(new_events):
                summary["incidents"].append(self._record_group(group))
        return summary

    def ingest_scan_result(
        self,
        result: dict[str, Any],
        *,
        host: Optional[str],
        origin: str = "on-demand",
    ) -> dict[str, Any]:
        """Open an incident for an on-demand scan; clean files and repeats open none."""
        event = result_to_event(result, host=host, origin=origin)
        response: dict[str, Any] = {"scan": result, "incident": None, "already_reported": False}
        if event is None:
            return response
        with self._lock:
            if self.repository.is_event_ingested(event.event_id):
                response["already_reported"] = True
                prior = self.repository.find_open_incident(group_key(event))
                response["incident_id"] = prior["incident_id"] if prior else None
                return response
            response["incident"] = self._record_group([event])
        return response

    def _record_group(self, group: list[SecurityEvent]) -> dict[str, Any]:
        """Open an incident for a group, or add its events to the group's open incident."""
        key = group_key(group[0])
        prior = self.repository.find_open_incident(key)
        prior_events = [_restore_event(item) for item in prior["events"]] if prior else []
        prior_alert = prior["alert"] if prior else {}

        # Newest first: the agents treat the first event as the primary one.
        evidence = sorted(prior_events + group, key=lambda event: event.timestamp, reverse=True)
        incident = self.pipeline.run(evidence[:MAX_STORED_EVENTS], approved=False, continues=prior)

        timestamps = [event.timestamp for event in group]
        occurrences = len(group) + prior_alert.get("occurrence_count", len(prior_events))
        incident.alert.update(
            occurrence_count=occurrences,
            first_seen=min(timestamps + [prior_alert.get("first_seen", min(timestamps))]),
            last_seen=max(timestamps + [prior_alert.get("last_seen", max(timestamps))]),
        )
        self.repository.save_incident(
            incident,
            ingested_event_ids=[event.event_id for event in group],
            group_key=key,
        )
        return {
            "incident_id": incident.incident_id,
            "title": incident.alert.get("title"),
            "severity": incident.events[0].severity.value,
            "new_events": len(group),
            "occurrence_count": occurrences,
            "merged": prior is not None,
            "risk_score": incident.forecast.get("forecast_score"),
            "playbook": incident.selected_playbook,
            "status": incident.action_result.get("status"),
        }

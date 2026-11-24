"""Build the Orchestrator's training set from Mordor recordings and MITRE D3FEND.

Each Windows recording from download_mordor.py is converted to the gatherer's
document format and replayed through the real backend pipeline (Sentinel ->
Analyst -> Prognostic -> BI), so every training example is an incident exactly
as the Orchestrator would see it live.

Labels come from the recording's ATT&CK techniques: MITRE D3FEND lists the
countermeasures for each technique, and D3FEND_ACTIONS maps those onto our
response actions. An incident gets an action as a positive label only when:
  - the action counters the recording's technique,
  - the incident's own ATT&CK evidence shares a tactic with the recording
    (Mordor labels whole recordings, so this filters background noise),
  - the Analyst rates the incident actionable (suspicious or malicious, triage
    score >= ACTIONABLE_SCORE), and
  - the incident names a target for the action (host, human account, remote IP, file).
Everything else is a "monitor only" example, which teaches the model restraint.

Usage (from the repository root):
    python Orchestrator_Agent/build_dataset.py
    python Orchestrator_Agent/build_dataset.py --channels Security System --max-events 5000
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Optional

AGENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = AGENT_DIR.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from agents import DemoExternalSystems, SecurityOperationsPipeline, incident_from_dict  # noqa: E402
from database import IncidentRepository  # noqa: E402
from orchestrator_model import incident_features  # noqa: E402
from playbooks import ACTIONS, RESPONSE_ACTIONS, targets_for  # noqa: E402
from windows_ingest import WindowsIngestService  # noqa: E402

DATA_DIR = AGENT_DIR / "data"
MORDOR_DIR = DATA_DIR / "mordor"
D3FEND_DIR = DATA_DIR / "d3fend"
ATTACK_STIX = REPO_ROOT / "Sentinel_Agent" / "intel_cache" / "enterprise-attack.json"
DATASET_PATH = DATA_DIR / "orchestrator_dataset.jsonl"
TACTIC_MAP_PATH = DATA_DIR / "tactic_map.json"

DEFAULT_CHANNELS = (
    "Security", "System", "Application",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
)
ACTIONABLE_SCORE = 40.0
LEVELS = {"CRITICAL": (1, "Critical"), "ERROR": (2, "Error"), "WARNING": (3, "Warning"), "INFO": (4, "Information")}

# D3FEND defensive techniques that correspond to one of our response actions.
# Detect/Harden/Model/Deceive/Restore techniques have no incident-time action here.
D3FEND_ACTIONS = {
    "Account Locking": "disable_user",
    "Credential Revocation": "disable_user",
    "Authentication Cache Invalidation": "disable_user",
    "Session Termination": "disable_user",
    "User Account Permissions": "disable_user",
    "Network Isolation": "isolate_endpoint",
    "Network Resource Access Mediation": "isolate_endpoint",
    "Remote File Access Mediation": "isolate_endpoint",
    "Process Termination": "isolate_endpoint",
    "Process Suspension": "isolate_endpoint",
    "Kernel-based Process Isolation": "isolate_endpoint",
    "Hardware-based Process Isolation": "isolate_endpoint",
    "Application-based Process Isolation": "isolate_endpoint",
    "Host Shutdown": "isolate_endpoint",
    "Network Traffic Filtering": "block_ip",
    "Inbound Traffic Filtering": "block_ip",
    "Outbound Traffic Filtering": "block_ip",
    "File Eviction": "quarantine_file",
    "Content Quarantine": "quarantine_file",
    "Executable Denylisting": "quarantine_file",
}


class NoFileScan:
    """Replays must not scan executables on this machine that a log happens to name."""

    def scan_process_events(self, raw_events: Any, host: Any = None, user_for: Any = None) -> tuple[list, dict]:
        return [], {"skipped": "training replay"}


def build_tactic_map(path: Path = ATTACK_STIX) -> dict[str, list[str]]:
    bundle = json.loads(path.read_text(encoding="utf-8"))
    tactics: dict[str, list[str]] = {}
    for item in bundle.get("objects", []):
        if item.get("type") != "attack-pattern" or item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        ids = [ref["external_id"] for ref in item.get("external_references", []) if ref.get("source_name") == "mitre-attack" and ref.get("external_id")]
        phases = sorted({phase["phase_name"] for phase in item.get("kill_chain_phases", []) if phase.get("kill_chain_name") == "mitre-attack"})
        for technique in ids:
            tactics[technique] = phases
    return tactics


def d3fend_actions(technique: str) -> dict[str, list[str]]:
    """Our actions that D3FEND lists against a technique, with the countermeasures behind each."""
    found: dict[str, set[str]] = {}
    for candidate in dict.fromkeys([technique, technique.split(".")[0]]):
        path = D3FEND_DIR / f"{candidate}.json"
        if not path.exists():
            continue
        bindings = json.loads(path.read_text(encoding="utf-8")).get("off_to_def", {}).get("results", {}).get("bindings", [])
        for binding in bindings:
            label = binding.get("def_tech_label", {}).get("value")
            action = D3FEND_ACTIONS.get(label)
            if action:
                found.setdefault(action, set()).add(label)
    return {action: sorted(labels) for action, labels in found.items()}


def to_gatherer_event(raw: dict[str, Any]) -> dict[str, Any]:
    level, level_name = LEVELS.get(str(raw.get("Severity", "INFO")).upper(), (4, "Information"))
    event_type = str(raw.get("EventType", "")).upper()
    keywords = ["Audit Failure"] if event_type == "AUDIT_FAILURE" else ["Audit Success"] if event_type == "AUDIT_SUCCESS" else []
    envelope = {
        "@version", "@timestamp", "tags", "host", "port", "EventTime", "EventReceivedTime", "SourceModuleName",
        "SourceModuleType", "Message", "Channel", "SourceName", "Hostname", "EventID", "RecordNumber",
        "Severity", "SeverityValue", "Keywords", "EventType", "ThreadID", "ExecutionProcessID", "Task",
        "Category", "Opcode", "OpcodeValue", "Version", "ProviderGuid", "UserID", "AccountName", "AccountType", "Domain",
    }
    return {
        "recordId": raw.get("RecordNumber"),
        "timeCreatedUtc": raw.get("@timestamp"),
        "eventId": raw.get("EventID"),
        "provider": raw.get("SourceName") or "",
        "level": level,
        "levelName": level_name,
        "keywords": keywords,
        "logName": raw.get("Channel") or "",
        "machineName": raw.get("Hostname"),
        "userId": raw.get("UserID"),
        "processId": raw.get("ExecutionProcessID"),
        "threadId": raw.get("ThreadID"),
        "task": raw.get("Category") or "",
        "opcode": raw.get("Opcode") or "",
        "activityId": raw.get("ActivityID"),
        "message": raw.get("Message") or "",
        "eventData": [str(value) for key, value in raw.items() if key not in envelope],
    }


def read_recording(path: Path, channels: set[str], max_events: int) -> Iterable[dict[str, Any]]:
    count = 0
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if not name.endswith(".json"):
                continue
            with archive.open(name) as handle:
                for line in handle:
                    try:
                        raw = json.loads(line.decode("utf-8", "replace"))
                    except ValueError:
                        continue
                    if not isinstance(raw, dict):
                        continue
                    if raw.get("Channel") in channels and raw.get("EventID") is not None:
                        yield to_gatherer_event(raw)
                        count += 1
                        if max_events and count >= max_events:
                            return


def build_tactic_names(path: Path = ATTACK_STIX) -> dict[str, str]:
    """ATT&CK tactic IDs (TA0006) to the phase names techniques use (credential-access)."""
    bundle = json.loads(path.read_text(encoding="utf-8"))
    names = {}
    for item in bundle.get("objects", []):
        if item.get("type") == "x-mitre-tactic":
            for ref in item.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    names[ref["external_id"]] = item["x_mitre_shortname"]
    return names


def labels_for(incident: Any, recording_actions: set[str], recording_tactics: set[str], features: dict[str, float]) -> tuple[dict[str, int], bool, bool]:
    """Mordor has no per-event attack labels, so an incident counts as part of the
    recorded attack only when its own ATT&CK evidence shares a tactic with it."""
    analysis = incident.risk_analysis or {}
    actionable = analysis.get("verdict") in {"suspicious", "malicious"} and float(analysis.get("risk_score", 0)) >= ACTIONABLE_SCORE
    incident_tactics = {key.split("=", 1)[1] for key in features if key.startswith("tactic=")}
    relevant = bool(incident_tactics & recording_tactics)
    targets = targets_for(incident)
    labels = {
        action: int(actionable and relevant and action in recording_actions and bool(targets[RESPONSE_ACTIONS[action].target]))
        for action in ACTIONS
    }
    return labels, actionable, relevant


def replay(events: list[dict[str, Any]], source: str) -> list[Any]:
    repository = IncidentRepository(":memory:")
    try:
        pipeline = SecurityOperationsPipeline(systems=DemoExternalSystems(), require_approval=True, response_model=None)
        service = WindowsIngestService(pipeline, repository, file_scan=NoFileScan())
        service.ingest_document({"computerName": None, "events": events}, source=source)
        return [incident_from_dict(item) for item in repository.list_incidents(100000)]
    finally:
        repository.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--channels", nargs="+", default=list(DEFAULT_CHANNELS), help="event log channels to replay")
    parser.add_argument("--max-events", type=int, default=20000, help="cap per recording (0 = no cap)")
    args = parser.parse_args()

    index = json.loads((MORDOR_DIR / "index.json").read_text(encoding="utf-8"))
    tactic_map = build_tactic_map()
    tactic_names = build_tactic_names()
    TACTIC_MAP_PATH.write_text(json.dumps(tactic_map))
    channels = set(args.channels)

    rows, skipped, label_counts = [], [], Counter()
    started = time.time()
    for number, item in enumerate(index, 1):
        if not item["archives"] or not item["techniques"]:
            continue
        recording_actions: dict[str, list[str]] = {}
        for technique in item["techniques"]:
            for action, countermeasures in d3fend_actions(technique).items():
                recording_actions.setdefault(action, [])
                recording_actions[action] = sorted(set(recording_actions[action]) | set(countermeasures))
        events = []
        for archive in item["archives"]:
            try:
                events.extend(read_recording(MORDOR_DIR / "host" / archive, channels, args.max_events))
            except (OSError, zipfile.BadZipFile) as error:
                skipped.append(f"{archive}: {error}")
        if not events:
            continue
        try:
            incidents = replay(events, f"mordor:{item['id']}")
        except Exception as error:  # one bad recording must not lose the rest
            skipped.append(f"{item['id']}: replay failed: {error!r}")
            continue
        recording_tactics = {tactic_names[t] for t in item["tactics"] if t in tactic_names}
        for incident in incidents:
            features = incident_features(incident, tactic_map)
            labels, actionable, relevant = labels_for(incident, set(recording_actions), recording_tactics, features)
            label_counts.update(action for action, value in labels.items() if value)
            label_counts["monitor_only"] += int(not any(labels.values()))
            analysis = incident.risk_analysis or {}
            rows.append({
                "recording": item["id"],
                "title": item["title"],
                "techniques": item["techniques"],
                "incident_title": incident.alert.get("title"),
                "verdict": analysis.get("verdict"),
                "triage_score": analysis.get("risk_score"),
                "actionable": actionable,
                "relevant": relevant,
                "targets": {key: bool(value) for key, value in targets_for(incident).items()},
                "d3fend": recording_actions,
                "features": features,
                "labels": labels,
            })
        print(f"[{number}/{len(index)}] {item['id']} {len(events)} events -> {len(incidents)} incidents", flush=True)

    with DATASET_PATH.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    print(f"\n{len(rows)} incidents from {len({r['recording'] for r in rows})} recordings in {time.time() - started:.0f}s -> {DATASET_PATH}")
    print("Positive labels:", dict(label_counts))
    for line in skipped:
        print("Skipped", line)


if __name__ == "__main__":
    main()

"""Build restraint examples for the Orchestrator from WitFoo Precinct6 Windows traffic.

Mordor teaches the model which responses fit an attack, but almost every Mordor
example comes from an attack recording. WitFoo Precinct6 is live production SOC
data, so it shows what the Sentinel and Analyst raise on ordinary activity.

The Windows Security rows (WinLogBeat JSON and raw event XML) are converted to the
gatherer's document format, grouped per organization, host and day, and replayed
through the backend pipeline. Each incident becomes a "no containment" example,
because WitFoo's correlation engine (Precinct) saw nothing there worth an incident.

Incidents built from rows that Precinct marked malicious are left out entirely:
their ATT&CK labels describe the parent incident's profile, not the event, so they
cannot be trusted as either a positive or a negative.

Output rows match build_dataset.py, with "source": "witfoo".

Usage (from the repository root, after download_witfoo.py):
    python Orchestrator_Agent/build_witfoo_dataset.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Optional
from xml.etree import ElementTree

import pandas as pd

from build_dataset import DATA_DIR, TACTIC_MAP_PATH, build_tactic_map, replay
from orchestrator_model import incident_features
from playbooks import ACTIONS, targets_for

WITFOO_DIR = DATA_DIR / "witfoo"
OUTPUT_PATH = DATA_DIR / "witfoo_dataset.jsonl"
WINDOWS_STREAMS = ("microsoft-windows-security-auditing", "windows_security_audit")
WINLOGBEAT_PREFIX = re.compile(r"^[^{]*:::\s*")
XML_NS = re.compile(r"\sxmlns='[^']*'")
LEVELS = {"critical": 1, "error": 2, "warning": 3, "information": 4, "info": 4}


def _keywords(outcome: str) -> list[str]:
    outcome = (outcome or "").lower()
    if "fail" in outcome:
        return ["Audit Failure"]
    if "success" in outcome:
        return ["Audit Success"]
    return []


def from_winlogbeat(text: str) -> Optional[dict[str, Any]]:
    try:
        doc = json.loads(WINLOGBEAT_PREFIX.sub("", text, count=1))
    except ValueError:
        return None
    event = doc.get("event") or {}
    winlog = doc.get("winlog") or {}
    level = str((doc.get("log") or {}).get("level") or "information").lower()
    try:
        event_id = int(event.get("code") or winlog.get("event_id"))
    except (TypeError, ValueError):
        return None
    return {
        "recordId": winlog.get("record_id"),
        "timeCreatedUtc": doc.get("@timestamp"),
        "eventId": event_id,
        "provider": event.get("provider") or winlog.get("provider_name") or "",
        "level": LEVELS.get(level, 4),
        "levelName": level.capitalize(),
        "keywords": _keywords(event.get("outcome", "")),
        "logName": winlog.get("channel") or "Security",
        "machineName": (doc.get("host") or {}).get("name") or winlog.get("computer_name"),
        "userId": None,
        "processId": (winlog.get("process") or {}).get("pid"),
        "threadId": ((winlog.get("process") or {}).get("thread") or {}).get("id"),
        "task": event.get("action") or "",
        "opcode": winlog.get("opcode") or "",
        "activityId": None,
        "message": doc.get("message") or "",
        "eventData": [str(v) for v in (winlog.get("event_data") or {}).values()],
    }


def from_event_xml(text: str) -> Optional[dict[str, Any]]:
    try:
        root = ElementTree.fromstring(XML_NS.sub("", text, count=1))
    except ElementTree.ParseError:
        return None
    system = root.find("System")
    rendering = root.find("RenderingInfo")
    if system is None:
        return None

    def text_of(parent, path: str) -> str:
        node = parent.find(path) if parent is not None else None
        return (node.text or "").strip() if node is not None and node.text else ""

    try:
        event_id = int(text_of(system, "EventID"))
    except ValueError:
        return None
    provider = system.find("Provider")
    created = system.find("TimeCreated")
    execution = system.find("Execution")
    keywords = [k.text for k in rendering.iter("Keyword") if k.text] if rendering is not None else []
    level_name = text_of(rendering, "Level") or "Information"
    return {
        "recordId": text_of(system, "EventRecordID") or None,
        "timeCreatedUtc": created.get("SystemTime") if created is not None else None,
        "eventId": event_id,
        "provider": provider.get("Name", "") if provider is not None else "",
        "level": LEVELS.get(level_name.lower(), 4),
        "levelName": level_name,
        "keywords": keywords,
        "logName": text_of(system, "Channel") or "Security",
        "machineName": text_of(system, "Computer"),
        "userId": None,
        "processId": execution.get("ProcessID") if execution is not None else None,
        "threadId": execution.get("ThreadID") if execution is not None else None,
        "task": text_of(rendering, "Task"),
        "opcode": text_of(rendering, "Opcode"),
        "activityId": None,
        "message": text_of(rendering, "Message"),
        "eventData": [d.text or "" for d in root.iter("Data")],
    }


def to_gatherer_event(row: Any) -> Optional[dict[str, Any]]:
    text = row.message_sanitized or ""
    event = from_event_xml(text) if text.lstrip().startswith("<") else from_winlogbeat(text)
    if event is None or not event["machineName"]:
        return None
    if not event["recordId"]:
        event["recordId"] = int(hashlib.sha1(row.artifact_id.encode()).hexdigest()[:12], 16)
    return event


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--max-events", type=int, default=20000, help="events per replayed document")
    args = parser.parse_args()

    columns = ["artifact_id", "org_id", "stream_name", "label_binary", "message_sanitized"]
    signals = pd.read_parquet(WITFOO_DIR / "signals" / "signals.parquet", columns=columns)
    signals = signals[signals.stream_name.isin(WINDOWS_STREAMS)]
    print(f"{len(signals)} WitFoo Windows Security events")

    documents: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    malicious_records: set[tuple[str, str]] = set()
    unreadable = 0
    for row in signals.itertuples(index=False):
        event = to_gatherer_event(row)
        if event is None:
            unreadable += 1
            continue
        day = str(event["timeCreatedUtc"] or "")[:10]
        documents[(row.org_id, event["machineName"], day)].append(event)
        if row.label_binary == "malicious":
            malicious_records.add((event["machineName"], str(event["recordId"])))
    print(f"{len(documents)} host-days, {unreadable} unreadable rows, {len(malicious_records)} malicious rows excluded")

    tactic_map = json.loads(TACTIC_MAP_PATH.read_text()) if TACTIC_MAP_PATH.exists() else build_tactic_map()
    rows, excluded, verdicts = [], 0, Counter()
    started = time.time()
    for number, ((org, host, day), events) in enumerate(sorted(documents.items()), 1):
        events.sort(key=lambda e: str(e["timeCreatedUtc"]))
        for start in range(0, len(events), args.max_events):
            chunk = events[start:start + args.max_events]
            group = f"witfoo:{org}:{host}:{day}"
            try:
                incidents = replay(chunk, group)
            except Exception as error:  # one bad document must not lose the rest
                print(f"  {group}: replay failed: {error!r}")
                continue
            for incident in incidents:
                records = {(e.host, str(e.metadata.get("record_id"))) for e in incident.events}
                if records & malicious_records:
                    excluded += 1
                    continue
                analysis = incident.risk_analysis or {}
                verdicts[analysis.get("verdict")] += 1
                rows.append({
                    "source": "witfoo",
                    "recording": group,
                    "title": f"WitFoo production traffic, {org}",
                    "techniques": [],
                    "incident_title": incident.alert.get("title"),
                    "verdict": analysis.get("verdict"),
                    "triage_score": analysis.get("risk_score"),
                    "actionable": analysis.get("verdict") in {"suspicious", "malicious"},
                    "relevant": False,
                    "targets": {key: bool(value) for key, value in targets_for(incident).items()},
                    "d3fend": {},
                    "features": incident_features(incident, tactic_map),
                    "labels": {action: 0 for action in ACTIONS},
                })
        if number % 25 == 0:
            print(f"[{number}/{len(documents)}] {len(rows)} incidents so far", flush=True)

    with OUTPUT_PATH.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    print(f"\n{len(rows)} restraint incidents from {len(documents)} host-days in {time.time() - started:.0f}s -> {OUTPUT_PATH}")
    print(f"Analyst verdicts: {dict(verdicts)}; excluded (malicious rows): {excluded}")


if __name__ == "__main__":
    main()

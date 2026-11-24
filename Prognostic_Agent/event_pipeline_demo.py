"""Synthetic Windows records through the existing detector, Sentinel and Analyst.

Run with python -B -m Prognostic_Agent.event_pipeline_demo. Command lines are
strings only. Existing model/catalog are read, never trained or refreshed.
The normal service wrapper is bypassed to avoid persistence and response actions.
No behavioral-score or technique-attribution overrides are supplied to the adapter.
"""

import argparse
import base64
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid
import warnings

from .analyst_adapter import adapt_analyst_incident
from .asset_context import LocalJSONAssetProvider
from .config import AGENT_DIR, ForecastConfig
from .contracts import parse_time, utc_text
from .prognostic_agent import build_risk_forecast

REPO_ROOT = AGENT_DIR.parent


def confine_writes():
    """Enforce this demo's write boundary, including imported code, in the CLI."""
    sys.dont_write_bytecode = True

    def check(path):
        if isinstance(path, (str, bytes, os.PathLike)):
            resolved = Path(os.fsdecode(path)).resolve()
            if not resolved.is_relative_to(AGENT_DIR.resolve()):
                raise PermissionError(f"Event pipeline demo writes are confined to {AGENT_DIR}")

    def audit(event, args):
        if event == "open":
            path, mode, flags = args
            if (mode and any(char in mode for char in "wax+")) or flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                check(path)
        elif event in {"os.mkdir", "os.remove", "os.rmdir", "os.chmod", "os.utime"}:
            check(args[0])
        elif event in {"os.rename", "os.link", "os.symlink"}:
            check(args[0])
            check(args[1])
        elif event in {"sqlite3.connect", "socket.connect"}:
            raise PermissionError("This fixture uses neither databases nor network connections")

    sys.addaudithook(audit)


def make_event_document(as_of, *, host="fixture-workstation", user="fixture-admin"):
    """Gatherer-shaped records; the encoded command only prints a test marker."""
    def event(record, code, minutes, message):
        return {"recordId": record, "timeCreatedUtc": utc_text(as_of - timedelta(minutes=minutes)),
                "eventId": code, "provider": "Microsoft-Windows-Security-Auditing", "level": 0,
                "levelName": "Information", "keywords": ["Audit Failure" if code == 4625 else "Audit Success"],
                "logName": "Security", "machineName": host, "userId": user,
                "processId": 4, "threadId": 1, "task": "Logon" if code != 4688 else "Process Creation",
                "opcode": "Info", "eventData": {}, "message": message}

    failures = [event(9100 + number, 4625, 11 - number,
                      "An account failed to log on.\nAccount For Which Logon Failed:\n"
                      f"  Account Name: {user}\nLogon Type: 3\nFailure Reason: Unknown user name or bad password.\n"
                      "Source Network Address: 203.0.113.42") for number in range(5)]
    success = event(9200, 4624, 5,
                    "An account was successfully logged on.\nNew Logon:\n"
                    f"  Account Name: {user}\nLogon Type: 3\nSource Network Address: 203.0.113.42")
    encoded = base64.b64encode("Write-Output 'synthetic-only'".encode("utf-16-le")).decode("ascii")
    process = event(9300, 4688, 2,
                    "A new process has been created.\nSubject:\n"
                    f"  Account Name: {user}\n"
                    "New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
                    "Creator Process Name: C:\\Windows\\System32\\cmd.exe\n"
                    f"Process Command Line: powershell -enc {encoded} -w hidden -ep bypass")
    return {"schemaVersion": 1, "collectedAtUtc": utc_text(as_of), "computerName": host,
            "lookbackHours": 1, "maxEventsPerLog": 7, "logs": ["Security"], "format": "json",
            "eventCount": 7, "synthetic": True, "events": failures + [success, process]}


class InventorySystems:
    """Only the local asset-lookup method used by AnalystAgent is provided."""

    def __init__(self, inventory):
        self.records = {item["entity_id"]: item for item in inventory["entities"]}

    def lookup_asset(self, user, host):
        record = self.records.get("host:" + host.casefold(), {})
        return {"user": user, "host": host, "asset_owner": record.get("asset_owner"),
                "criticality": record.get("asset_criticality", "normal"), "department": "Synthetic Test"}


def _write(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")


def run_pipeline(output_dir, *, inventory_document=None, rules_path=None,
                 event_document_as_of=None, causal_replay=False, prepare_adapter=None, event_document=None):
    # Backend uses sibling imports. Only these existing pure functions/classes
    # are called; do not instantiate WindowsIngestService or a repository.
    sys.path.insert(0, str(REPO_ROOT / "backend"))
    sys.path.insert(1, str(REPO_ROOT / "Sentinel_Agent"))
    import anomaly_agent
    import agents
    from analyst import RelatedEvent
    from threat_intel import CATALOG_PATH, load_catalog
    from windows_ingest import anomaly_to_event, group_events, is_routine_process_launch

    model_path = REPO_ROOT / "Sentinel_Agent" / "models" / "random_forest_anomaly.joblib"
    artifacts = [*sorted((REPO_ROOT / "backend").glob("*.py")),
                 *sorted((REPO_ROOT / "Sentinel_Agent").glob("*.py")), model_path, CATALOG_PATH]

    def fingerprints():
        return {str(path.relative_to(REPO_ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in artifacts}

    before = fingerprints()
    output_dir = Path(output_dir).resolve()
    if not output_dir.is_relative_to(AGENT_DIR.resolve()):
        raise ValueError("Outputs must stay inside Prognostic_Agent")
    output_dir.mkdir(parents=True, exist_ok=False)
    as_of = parse_time(event_document_as_of) if event_document_as_of else datetime.now(timezone.utc)
    document = deepcopy(event_document) if event_document is not None else make_event_document(as_of)
    raw_path = output_dir / "input_events.json"
    _write(raw_path, document)
    inventory = deepcopy(inventory_document) if inventory_document is not None else json.loads(
        (AGENT_DIR / "examples" / "synthetic_powershell" / "inventory.json").read_text(encoding="utf-8"))
    if inventory_document is None:
        for record in inventory["entities"]:
            record["as_of"] = utc_text(as_of - timedelta(minutes=20))
    inventory_path = output_dir / "inventory.json"
    _write(inventory_path, inventory)
    catalog = load_catalog(CATALOG_PATH)
    if catalog is None:
        raise FileNotFoundError("Existing cached catalog required; this demo never downloads one")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        anomalies = anomaly_agent.detect_anomalies(
            document["events"], source_path=raw_path, computer_name=document["computerName"],
            catalog=catalog, threshold=.55, model_path=model_path, load_existing_model=True)
    # Preserve warnings in the exported evidence, not just the terminal transcript.
    detector_warnings = list({(item.category.__name__, str(item.message)): None for item in caught})
    filtered = [item for item in anomalies if is_routine_process_launch(item)]
    events = [anomaly_to_event(item) for item in anomalies if not is_routine_process_launch(item)]
    groups = group_events(events)
    if causal_replay:
        groups.sort(key=lambda group: max(parse_time(event.timestamp) for event in group))
    sentinel = agents.SentinelAgent()
    incidents = [sentinel.detect_anomaly(group) for group in groups]
    sentinel_outputs = [agents.incident_to_dict(item) for item in incidents]
    analyst = agents.AnalystAgent(InventorySystems(inventory))
    cutoffs = {}
    for incident in incidents:
        cutoff = (max(parse_time(event.timestamp) for event in incident.events) + timedelta(seconds=1)
                  if causal_replay else datetime.now(timezone.utc))
        cutoffs[incident.incident_id] = utc_text(cutoff)
        related = [RelatedEvent(event, incident_id=other.incident_id, title=other.alert["title"])
                   for other in incidents if other is not incident for event in other.events
                   if not causal_replay or parse_time(event.timestamp) <= cutoff]
        analyst.analyze(incident, related)
    results = []
    config = ForecastConfig(environment="test", max_candidates=5,
                            rules_path=Path(rules_path) if rules_path is not None else ForecastConfig().rules_path)
    for incident, sentinel_output in zip(incidents, sentinel_outputs):
        serialized = agents.incident_to_dict(incident)
        cutoff = cutoffs[incident.incident_id] if causal_replay else agents.utc_now()
        adapter_payload, guard_context = prepare_adapter(serialized, cutoff) if prepare_adapter else (serialized, None)
        request = adapt_analyst_incident(adapter_payload, guard_context=guard_context)
        forecast = build_risk_forecast(request, config=config, forecast_as_of=cutoff,
                                       asset_provider=LocalJSONAssetProvider(inventory_path))
        results.append({"event_type": incident.events[0].event_type,
                        "sentinel_incident": sentinel_output, "analyst_incident": serialized,
                        "adapter_input_incident": adapter_payload,
                        "analyst_technique_ids": incident.risk_analysis["mitre_techniques"],
                        "adapter_request": request, "adapter_issues": request["adapter_issues"],
                        "forecast": forecast})
    after = fingerprints()
    if before != after:
        raise RuntimeError("A protected source, model or catalog changed during the demo")
    report = {"schema_version": 1, "environment": "test", "generated_at": agents.utc_now(),
              "pipeline": ["synthetic gatherer-shaped events", "Sentinel_Agent existing Random Forest",
                           "backend SentinelAgent", "backend AnalystAgent", "Prognostic adapter", "standalone Prognostic"],
              "execution": {"model_path": str(model_path), "model_loaded_existing": True,
                            "catalog_path": str(CATALOG_PATH), "catalog_refreshed": False,
                            "threshold": .55, "behavioral_score_override": None, "technique_evidence_override": None,
                            "asset_inventory": "caller-supplied inventory; source timestamps retained" if inventory_document is not None else "hand-built fixture with refreshed synthetic snapshot timestamps",
                            "causal_replay": causal_replay, "guard_assertion_overlay": prepare_adapter is not None,
                            "backend_database_used": False, "history_written": False, "llm_used": False,
                            "scope": "detector and agent calls only; no live collection, executable scanning, service persistence or response actions",
                            "protected_artifacts_unchanged": before == after,
                            "protected_artifact_sha256": after},
              "input_document": document, "inventory": inventory,
              "detector_warnings": [{"category": category, "message": message} for category, message in detector_warnings],
              "sentinel_anomalies": anomalies, "routine_process_launches_filtered": filtered,
              "normalized_events": [{**asdict(event), "severity": event.severity.value} for event in events],
              "incident_count": len(results), "results": results}
    _write(output_dir / "pipeline_output.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    confine_writes()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    directory = args.output_dir or AGENT_DIR / "private" / "event-pipeline" / (stamp + "_" + uuid.uuid4().hex)
    report = run_pipeline(directory)
    print("| Event group | Analyst verdict | Analyst risk | Behavioral score | Analyst technique IDs | Adapter issue codes | Forecast status | Reason |")
    print("|---|---|---:|---:|---|---|---|---|")
    for result in report["results"]:
        analysis, forecast = result["analyst_incident"]["risk_analysis"], result["forecast"]
        codes = list(dict.fromkeys(issue["code"] for issue in result["adapter_issues"]))
        print(f"| {result['event_type']} | {analysis['verdict']} | {analysis['risk_score']} | {analysis.get('behavioral_score')} | {', '.join(result['analyst_technique_ids'])} | {', '.join(codes)} | {forecast.get('status', forecast['response_type'])} | {forecast.get('reason', forecast.get('code'))} |")
    print("Full pipeline output: " + str(directory / "pipeline_output.json"))
    for warning in report["detector_warnings"]:
        print(warning["category"] + ": " + warning["message"], file=sys.stderr)
    return 0 if report["incident_count"] and all(r["forecast"]["response_type"] == "risk_forecast" for r in report["results"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())

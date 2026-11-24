"""Isolated retained-evidence re-triage, never a claim of new event ingestion.

All copied events are RF-probed and re-triaged, including evidence the current
admission filter would suppress. Original static malware findings are replayed
as recorded evidence: files are never opened, executed or rescanned.
"""

import argparse
from collections import Counter, defaultdict
from contextlib import closing
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import csv
import json
from pathlib import Path
import re
import sqlite3
import sys
from tempfile import TemporaryDirectory
import uuid
import warnings

from .analyst_adapter import adapt_analyst_incident
from .asset_context import LocalJSONAssetProvider
from .config import AGENT_DIR, ForecastConfig
from .contracts import content_hash, parse_time, utc_text
from .importers.core import import_inventory
from .operator_overlay import apply_overlay
from .private_paths import PRIVATE_DIR, confine_private_runtime, private_path, write_private
from .provenance import operational_error, provenance
from .service import ForecastService
from .shadow_source import sha256_file, snapshot_source, source_manifest
from .storage import ForecastHistory

SOURCE = "retriage_replay"
ROOT = AGENT_DIR.parent
LEVELS = {"critical": 1, "error": 2, "warning": 3, "information": 4, "verbose": 5}


def load_components():
    # Only the detector and two agents are invoked, never SecurityOperationsPipeline
    # or WindowsIngestService (which can scan executables and run response actions).
    for index, folder in enumerate(("backend", "Sentinel_Agent")):
        path = str(ROOT / folder)
        if path not in sys.path:
            sys.path.insert(index, path)
    import agents
    import anomaly_agent
    import windows_ingest
    from analyst import RelatedEvent
    from threat_intel import CATALOG_PATH, load_catalog
    catalog = load_catalog(CATALOG_PATH)
    if catalog is None:
        raise ValueError("An existing Sentinel catalog is required; replay never downloads one")
    return agents, anomaly_agent, windows_ingest, RelatedEvent, catalog, CATALOG_PATH


def protected_hashes(model_path, catalog_path):
    paths = [path for folder in ("backend", "Sentinel_Agent", "Event_Gatherer")
             for path in (ROOT / folder).glob("*.py")]
    paths += [model_path, catalog_path, ForecastConfig.rules_path, ForecastConfig.weights_path,
              ROOT / "run_backend_admin.bat", ROOT / "run_backend_dev.bat"]
    return {str(path.relative_to(ROOT)): sha256_file(path) for path in sorted(paths)}


def project_event(event):
    """Known normalized fields only; missing raw fields are explicitly reported."""
    metadata = event.get("metadata") or {}
    raw = {"recordId": metadata.get("record_id"), "timeCreatedUtc": event["timestamp"],
           "eventId": metadata.get("windows_event_id"), "provider": event.get("destination"),
           "logName": metadata.get("log_name"), "levelName": metadata.get("level_name"),
           "level": LEVELS.get(str(metadata.get("level_name") or "").casefold()),
           "machineName": event.get("host"), "userId": event.get("user"), "message": event.get("message", ""),
           "task": None, "processId": None, "threadId": None, "eventData": None, "keywords": None}
    return raw, sorted(name for name, value in raw.items() if value is None)


def event_order_key(timestamp):
    """UTC lexical key preserving Windows' seventh fractional-second digit."""
    parsed = parse_time(timestamp)
    match = re.search(r"\d{2}:\d{2}:\d{2}\.(\d+)", timestamp)
    fraction = match.group(1) if match else ""
    if len(fraction) > 12:
        raise ValueError("Timestamp precision exceeds the replay ordering contract")
    return parsed.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%S") + "." + fraction.ljust(12, "0")


def copy_incidents(snapshot_path, database_path):
    """Versioned disposable evidence DB; source opened immutable/read-only."""
    with closing(sqlite3.connect(Path(snapshot_path).as_uri() + "?mode=ro&immutable=1", uri=True)) as source:
        source.execute("PRAGMA query_only=ON")
        rows = source.execute("SELECT incident_id,payload FROM incidents ORDER BY detected_at,incident_id").fetchall()
    with closing(sqlite3.connect(database_path)) as target:
        target.execute("PRAGMA journal_mode=WAL")
        target.execute("PRAGMA busy_timeout=5000")
        target.execute("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,source TEXT NOT NULL,environment TEXT NOT NULL)")
        target.execute("INSERT INTO schema_migrations VALUES(1,?,'test')", (SOURCE,))
        target.execute("CREATE TABLE source_incidents(original_triage_id TEXT PRIMARY KEY,source TEXT NOT NULL,environment TEXT NOT NULL,payload_json TEXT NOT NULL,payload_sha256 TEXT NOT NULL)")
        target.execute("CREATE TABLE replay_events(original_triage_id TEXT NOT NULL,ordinal INTEGER NOT NULL,source TEXT NOT NULL,environment TEXT NOT NULL,event_order TEXT NOT NULL,event_json TEXT NOT NULL,PRIMARY KEY(original_triage_id,ordinal))")
        target.execute("CREATE TABLE analyst_revisions(original_triage_id TEXT NOT NULL,ordinal INTEGER NOT NULL,source TEXT NOT NULL,environment TEXT NOT NULL,triaged_at TEXT NOT NULL,behavioral_score REAL,techniques_json TEXT NOT NULL,PRIMARY KEY(original_triage_id,ordinal))")
        for identity, raw in rows:
            incident = json.loads(raw)
            if not isinstance(incident, dict) or not isinstance(incident.get("events"), list) or not incident["events"]:
                raise ValueError("Source incident has no usable event array: " + identity)
            target.execute("INSERT INTO source_incidents VALUES(?,?,'test',?,?)", (identity, SOURCE, raw, content_hash(incident)))
            for ordinal, event in enumerate(incident["events"]):
                target.execute("INSERT INTO replay_events VALUES(?,?,?,'test',?,?)",
                    (identity, ordinal, SOURCE, event_order_key(event["timestamp"]), json.dumps(event, allow_nan=False)))
        target.commit()
    return len(rows)


class ReplaySystems:
    def __init__(self, inventory):
        self.records = {record["entity_id"]: record for record in inventory["entities"]}

    def lookup_asset(self, user, host):
        record = self.records.get("host:" + (host or "").casefold(), {})
        return {"user": user, "host": host, "criticality": record.get("asset_criticality"),
                "asset_owner": record.get("asset_owner"), "source": SOURCE}


def score_copied_events(rows, detector, catalog, model_path, source_path):
    projections, missing = [], []
    for row in rows:
        projection, absent = project_event(row["event"])
        projections.append(projection)
        missing.append(absent)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        anomalies = detector.detect_anomalies(projections, source_path=source_path, computer_name=None,
            catalog=catalog, threshold=.55, model_path=model_path, load_existing_model=True)
    # Current detector contract: rf-<recordId>-<input index>. This index survives
    # its output score ordering and disambiguates missing/duplicate record IDs.
    by_index = {}
    for anomaly in anomalies:
        index = int(anomaly["anomalyId"].rsplit("-", 1)[1])
        if index not in range(len(rows)) or index in by_index:
            raise ValueError("Detector returned an ambiguous input index")
        by_index[index] = anomaly
    warnings_output = [{"category": item.category.__name__, "message": str(item.message)} for item in caught]
    return projections, missing, by_index, warnings_output


def normalize_replay_event(stored, projection, anomaly, agents, ingest):
    metadata = stored.get("metadata") or {}
    static = bool(metadata.get("sha256"))
    windows = type(metadata.get("windows_event_id")) is int
    if windows and not static:
        probe = anomaly or {"event": projection, "computerName": stored.get("host"), "modelScore": None,
                            "mitreTechniques": [], "cisaMatches": [], "reasons": [], "model": "RandomForestClassifier"}
        event = ingest.anomaly_to_event(probe)
        event.event_id, event.timestamp = stored["event_id"], stored["timestamp"]
        score_source = "current_sentinel_rf" if anomaly else "current_rf_not_emitted_no_score"
    else:
        # A Windows-event RF does not replace a PE scanner score or fabricate
        # Windows semantics for an API event. Preserve recorded non-Windows facts.
        event = agents.SecurityEvent(**{**deepcopy(stored), "severity": agents.Severity(stored["severity"])})
        score_source = "recorded_static_scan_not_rerun" if static else "recorded_non_windows_event"
    event.metadata["retriage_replay"] = {"source": SOURCE, "score_source": score_source,
                                        "rf_probe_emitted": anomaly is not None}
    return event, score_source


def render_reports(directory, report):
    fields = ["original_triage_id", "original_verdict", "analyst_verdict", "retained_events", "original_occurrences",
              "status", "reason", "risk_score", "path", "technique_ids", "issues"]
    with (directory / "results.csv").open("x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["source", "environment"] + fields)
        writer.writeheader()
        for row in report["comparison"]:
            writer.writerow({"source": SOURCE, "environment": "test", **{key: json.dumps(row[key]) if isinstance(row[key], (list, dict)) else row[key] for key in fields}})
    lines = ["# Retained-evidence re-triage replay", "", "Source: retriage_replay; environment: test. Not live ingestion.", "",
             "| Original triage ID | Old verdict | New verdict | Events | Outcome | Reason | Risk | Techniques |",
             "|---|---|---|---:|---|---|---:|---|"]
    for row in report["comparison"]:
        lines.append("| " + " | ".join(str(value) for value in (row["original_triage_id"], row["original_verdict"], row["analyst_verdict"],
                     row["retained_events"], row["status"], row["reason"], row["risk_score"], ", ".join(row["technique_ids"]))) + " |")
    (directory / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_private(directory / "retriage_replay.json", report)


def run_retriage_replay(source_db, raw_export, operator_overlay, *, output_dir, store_full_evidence=False):
    directory = private_path(output_dir)
    directory.mkdir(parents=True, exist_ok=False)
    source_db = Path(source_db).resolve()
    original_manifest = source_manifest(source_db)
    imported = import_inventory(raw_export, environment="test", output_root=directory / "imports")
    effective = apply_overlay(imported["inventory_path"], operator_overlay, directory / "effective-inventory")
    inventory_path = Path(effective["inventory_path"])
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    agents, detector, ingest, RelatedEvent, catalog, catalog_path = load_components()
    model_path = ROOT / "Sentinel_Agent" / "models" / "random_forest_anomaly.joblib"
    protected_before = protected_hashes(model_path, catalog_path)
    run_id = directory.name
    config = ForecastConfig(environment="test", store_full_evidence=store_full_evidence)
    results, detector_warnings = [], []
    missing_counts = Counter()
    cutoff = datetime.now(timezone.utc)
    history_path = directory / "forecast_history.db"
    with TemporaryDirectory(prefix="temporary-evidence-", dir=directory) as working:
        work = Path(working)
        snapshot = snapshot_source(source_db, work / "snapshot")
        incident_count = copy_incidents(snapshot["snapshot_path"], work / "events.db")
        with closing(sqlite3.connect(work / "events.db")) as connection:
            connection.row_factory = sqlite3.Row
            source_incidents = {row["original_triage_id"]: json.loads(row["payload_json"])
                                for row in connection.execute("SELECT * FROM source_incidents")}
            rows = [{"original_triage_id": row["original_triage_id"], "ordinal": row["ordinal"], "event": json.loads(row["event_json"])}
                    for row in connection.execute("SELECT * FROM replay_events ORDER BY event_order,original_triage_id,ordinal")]
            projections, missing, probes, detector_warnings = score_copied_events(rows, detector, catalog, model_path, work / "events.db")
            own, seen, final = defaultdict(list), [], {}
            sentinel, analyst = agents.SentinelAgent(), agents.AnalystAgent(ReplaySystems(inventory))
            probe_stats = defaultdict(lambda: Counter())
            for index, row in enumerate(rows):
                original_id = row["original_triage_id"]
                stored, anomaly = row["event"], probes.get(index)
                event, score_source = normalize_replay_event(stored, projections[index], anomaly, agents, ingest)
                event.metadata["retriage_replay"]["original_triage_id"] = original_id
                missing_counts.update(missing[index])
                own[original_id].append(event)
                evidence = sorted(own[original_id], key=lambda item: (event_order_key(item.timestamp), item.event_id), reverse=True)
                incident = sentinel.detect_anomaly(evidence)
                incident.incident_id = SOURCE + ":" + run_id + ":" + original_id
                incident.alert["fingerprint"] = incident.incident_id
                incident.alert["occurrence_count"] = len(evidence)
                related = [RelatedEvent(other, incident_id=SOURCE + ":" + run_id + ":" + owner)
                           for owner, other in seen if owner != original_id and other.host == event.host]
                analyst.analyze(incident, related)
                connection.execute("INSERT INTO analyst_revisions VALUES(?,?,?,'test',?,?,?)", (original_id, row["ordinal"], SOURCE,
                    incident.risk_analysis["triaged_at"], incident.risk_analysis["behavioral_score"], json.dumps(incident.risk_analysis["mitre_techniques"])))
                seen.append((original_id, event))
                available = {item.event_id: item for _, item in seen}
                referenced = {ref for refs in incident.risk_analysis["technique_evidence"].values() for ref in refs}
                support = [available[ref] for ref in sorted(referenced) if ref in available and ref not in {item.event_id for item in evidence}]
                serialized = agents.incident_to_dict(incident)
                adapter_input = deepcopy(serialized)
                adapter_input["events"].extend({**asdict(item), "severity": item.severity.value} for item in support)
                final[original_id] = (serialized, adapter_input)
                stats = probe_stats[original_id]
                stats["rf_emitted"] += anomaly is not None
                stats["rf_not_emitted"] += anomaly is None
                stats["production_routine_filter_would_skip"] += bool(anomaly and ingest.is_routine_process_launch(anomaly))
                stats[score_source] += 1
            connection.commit()
            with ForecastHistory(history_path, environment="test", store_full_evidence=store_full_evidence) as history:
                service = ForecastService(history, config=config)
                for original_id, (serialized, adapter_input) in final.items():
                    original = source_incidents[original_id]
                    context = {"schema_version": 1, "environment": "test", "source": SOURCE, "original_triage_id": original_id,
                               "original_triaged_at": (original.get("risk_analysis") or {}).get("triaged_at"),
                               "analyst_verdict": serialized["risk_analysis"]["verdict"], "inventory_sha256": effective["inventory_file_sha256"],
                               "evaluation_id": SOURCE + ":" + run_id + ":" + original_id}
                    request = adapt_analyst_incident(adapter_input)
                    request["adapter_metadata"]["replay"] = context
                    response = service.assess(request, asset_provider=LocalJSONAssetProvider(inventory_path), forecast_as_of=cutoff,
                                              evaluation_id=context["evaluation_id"], shadow_context=context)
                    results.append({"source": SOURCE, "environment": "test", "original_triage_id": original_id,
                        "original_triaged_at": context["original_triaged_at"], "original_verdict": (original.get("risk_analysis") or {}).get("verdict"),
                        "retained_events": len(original["events"]), "original_occurrences": original.get("alert", {}).get("occurrence_count", len(original["events"])),
                        "detector": dict(probe_stats[original_id]), "analyst_incident_id": serialized["incident_id"],
                        "analyst": serialized["risk_analysis"],
                        "sentinel_alert": serialized["alert"] if store_full_evidence else {
                            **{key: value for key, value in serialized["alert"].items() if key != "summary"},
                            "summary_sha256": content_hash(serialized["alert"].get("summary"))},
                        "adapter": {"issues": request["adapter_issues"], "observed_techniques": request["observed_techniques"],
                                    "supporting_related_event_count": len(adapter_input["events"]) - len(serialized["events"])},
                        "evidence_references": [{"event_id": event["event_id"], "sha256": content_hash(event), "timestamp": event["timestamp"]} for event in original["events"]],
                        **({"original_events": original["events"], "retriaged_events": adapter_input["events"]} if store_full_evidence else {}),
                        "forecast": response})
            temporary_revisions = connection.execute("SELECT COUNT(*) FROM analyst_revisions").fetchone()[0]
    source_after = source_manifest(source_db)
    protected_after = protected_hashes(model_path, catalog_path)
    comparison = []
    for item in results:
        response, analysis = item["forecast"], item["analyst"]
        path = response.get("predicted_path")
        comparison.append({"source": SOURCE, "environment": "test", "original_triage_id": item["original_triage_id"], "original_verdict": item["original_verdict"],
            "analyst_verdict": analysis["verdict"], "retained_events": item["retained_events"], "original_occurrences": item["original_occurrences"],
            "status": response.get("status") or response["response_type"], "reason": response.get("reason") or response["response_type"],
            "risk_score": response.get("risk_score"), "path": [path["starting_technique"]] + [step["technique_id"] for step in path["steps"]] if path else None,
            "technique_ids": analysis["mitre_techniques"], "issues": response.get("issues", []) + response.get("errors", [])})
    report = {"schema_version": 1, "source": SOURCE, "environment": "test", "forecast_as_of": utc_text(cutoff),
        "source_database": str(source_db), "source_hashes_before": original_manifest, "source_hashes_after": source_after,
        "backend_database_unchanged": original_manifest == source_after,
        "protected_artifacts_unchanged": protected_before == protected_after, "protected_artifact_sha256": protected_after,
        "inventory": effective, "import": imported, "incident_count": incident_count, "event_count": len(rows),
        "declared_occurrences": sum(row["original_occurrences"] for row in comparison), "analyst_revision_count": temporary_revisions,
        "temporary_event_database_removed": not work.exists(), "history_database": str(history_path),
        "status_counts": dict(sorted(Counter(row["status"] for row in comparison).items())),
        "reason_counts": dict(sorted(Counter(row["reason"] for row in comparison).items())),
        "analyst_verdict_counts": dict(sorted(Counter(row["analyst_verdict"] for row in comparison).items())),
        "incidents_with_techniques": [row for row in comparison if row["technique_ids"]],
        "old_suspicious_incidents": [row for row in comparison if row["original_verdict"] == "suspicious"],
        "detector_warnings": detector_warnings, "missing_projection_fields": dict(sorted(missing_counts.items())),
        "execution": {"source": SOURCE, "environment": "test", "model_loaded_existing": True, "threshold": .55,
            "ordering": "Global event timestamp, original triage ID and source ordinal; related events only from already replayed evidence",
            "admission_policy": "All retained incident evidence is re-triaged, including RF/routine-filter suppressions, which are reported separately",
            "evidence_clock": "Original timestamps retained; forecast cutoff is current replay time; no synthetic freshness",
            "inventory_clock": "Fresh local export with host-specific normal overlay; no cross-host inventory remapping",
            "missing_raw_features": "Projection from normalized records, not a faithful raw Event Viewer export; omitted fields retain detector defaults",
            "static_malware": "Recorded static evidence only; no executable opened or rescanned; no malware model loaded",
            "side_effects": "No backend pipeline/orchestrator, LLM, threat-intel download, watcher, live ingest or external write"},
        "comparison": comparison, "results": results}
    render_reports(directory, report)
    if not report["backend_database_unchanged"] or not report["protected_artifacts_unchanged"]:
        raise RuntimeError("Source or protected artifacts changed during replay; inspect private report")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-db", type=Path, default=ROOT / "backend" / "soc_agents.db")
    parser.add_argument("--raw-export", required=True)
    parser.add_argument("--operator-overlay", default=PRIVATE_DIR / "operator_overlay.json")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--store-full-evidence", action="store_true")
    parser.add_argument("--environment", choices=["test"], required=True)
    args = parser.parse_args(argv)
    confine_private_runtime()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    directory = args.output_dir or PRIVATE_DIR / "retriage-replay" / (stamp + "_" + uuid.uuid4().hex[:8])
    try:
        report = run_retriage_replay(args.backend_db, args.raw_export, args.operator_overlay,
                                    output_dir=directory, store_full_evidence=args.store_full_evidence)
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        error = {**operational_error("retriage_replay_error", str(exc), metadata=provenance(ForecastConfig(environment="test"))),
                 "source": SOURCE, "original_triage_id": None}
        write_private(private_path(directory) / ("run_error_" + uuid.uuid4().hex[:8] + ".json"), error)
        print(json.dumps(error, indent=2))
        return 1
    from .weekly_report import build_weekly_report
    from zoneinfo import ZoneInfo
    local_date = datetime.now(timezone.utc).astimezone(ZoneInfo("America/Los_Angeles")).date()
    from datetime import timedelta
    monday = local_date - timedelta(days=local_date.weekday())
    weekly = build_weekly_report(report["history_database"], week_start=monday)
    write_private(directory / "weekly_replay_only.json", weekly)
    print(json.dumps({key: report[key] for key in ("source", "environment", "incident_count", "event_count", "status_counts", "reason_counts", "analyst_verdict_counts", "backend_database_unchanged", "temporary_event_database_removed")} |
                     {"report_file": str(directory / "retriage_replay.json"), "all_results_csv": str(directory / "results.csv")}, indent=2))
    return 1 if report["status_counts"].get("operational_error") else 0


if __name__ == "__main__":
    raise SystemExit(main())

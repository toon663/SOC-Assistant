"""Report-only activity provenance; never changes Analyst verdicts or scores."""
import json
from .contracts import parse_time
from .private_paths import PRIVATE_DIR

TAGS = ("possible_self_generated", "test_data", "controlled_test")

def classify_activity(incident, windows=None):
    tags, matched = set(), []
    events = incident.get("events", []) if isinstance(incident, dict) else []
    if any(e.get("event_id") == "debug-003" or str(e.get("event_id", "")).startswith("manual-") for e in events):
        tags.add("test_data")
    if windows is None:
        windows = []
        for path in (PRIVATE_DIR / "activity-windows").glob("*.json"):
            try:
                windows.append(json.loads(path.read_text(encoding="utf-8-sig")))
            except (OSError, ValueError):
                continue
    for window in windows:
        if window.get("environment") != "test" or not window.get("ended_at"):
            continue
        try:
            start, end = parse_time(window["started_at"]), parse_time(window["ended_at"])
            times = [parse_time(e["timestamp"]) for e in events if str(e.get("host", "")).casefold() == str(window.get("host", "")).casefold()]
            overlap = bool(times) and min(times) <= end and max(times) >= start
        except (TypeError, ValueError, KeyError):
            continue
        if overlap:
            tags.add("controlled_test" if window.get("kind") == "controlled_test" else "possible_self_generated")
            matched.append(window.get("window_id"))
    return {"tags": sorted(tags), "window_ids": sorted(set(filter(None, matched))),
            "basis": "Report-only event-span/host overlap, not proof of process ancestry or causation"}


def refresh_tags(source_db, history_path):
    from contextlib import closing
    from pathlib import Path
    import sqlite3
    from tempfile import TemporaryDirectory
    from .private_paths import private_path
    from .shadow_source import snapshot_source
    root = PRIVATE_DIR / "activity-audit"
    root.mkdir(exist_ok=True)
    with TemporaryDirectory(dir=root) as work:
        snapshot = snapshot_source(source_db, Path(work) / "source")
        with closing(sqlite3.connect(Path(snapshot["snapshot_path"]).as_uri() + "?mode=ro&immutable=1", uri=True)) as source:
            by_id = {identity: classify_activity(json.loads(raw)) for identity, raw in source.execute("SELECT incident_id,payload FROM incidents")}
    history_path = private_path(history_path)
    if not history_path.is_file():
        raise ValueError("Existing agent-owned history is required")
    with closing(sqlite3.connect(history_path)) as history:
        tables = {row[0] for row in history.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"schema_migrations", "forecasts", "attempts"} <= tables:
            raise ValueError("Not an agent-owned forecast history")
        history.execute("PRAGMA busy_timeout=5000")
        history.execute("CREATE TABLE IF NOT EXISTS shadow_report_tags(environment TEXT NOT NULL,assessment_key TEXT NOT NULL,tags_json TEXT NOT NULL,PRIMARY KEY(environment,assessment_key))")
        keys = {}
        for table, field in (("forecasts", "response_json"), ("attempts", "metrics_json")):
            for raw, in history.execute(f"SELECT {field} FROM {table} WHERE environment='test'"):
                response = json.loads(raw)
                context = response.get("shadow_context") or {}
                if context.get("assessment_key") and context.get("source_incident_id") in by_id:
                    keys[context["assessment_key"]] = by_id[context["source_incident_id"]]
        history.executemany("INSERT INTO shadow_report_tags VALUES('test',?,?) ON CONFLICT(environment,assessment_key) DO UPDATE SET tags_json=excluded.tags_json", [(key, json.dumps(value)) for key, value in keys.items()])
        history.commit()
    return {"refreshed_assessment_keys": len(keys), "environment": "test", "report_only": True}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend-db", required=True)
    parser.add_argument("--history-db", required=True)
    args = parser.parse_args()
    print(json.dumps(refresh_tags(args.backend_db, args.history_db)))

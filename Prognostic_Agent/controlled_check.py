"""Read-only check for the exact encoded controlled-test payload in saved incidents."""
import argparse
import json
from pathlib import Path
import sqlite3
import subprocess
from contextlib import closing
from tempfile import TemporaryDirectory

from .private_paths import PRIVATE_DIR, private_path, write_private
from .shadow_source import snapshot_source
from .contracts import parse_time


def preflight(window_path=None):
    """Read OS state through a fixed, read-only Windows probe; redact failures."""
    command = ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
               str(Path(__file__).with_name("controlled_probe.ps1"))]
    if window_path:
        command += ["-WindowPath", str(private_path(window_path))]
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=45, check=True)
        return json.loads(process.stdout.lstrip("\ufeff"))
    except subprocess.CalledProcessError as error:
        blocked = "malicious content" in (error.stderr or "").lower() or "scriptcontainedmaliciouscontent" in (error.stderr or "").lower()
        return {"elevated": None, "both_settings_on": None, "matching_4688_count": None,
                "errors": ["windows_security_blocked_probe" if blocked else "preflight_probe_failed"]}
    except (OSError, subprocess.SubprocessError, ValueError):
        return {"elevated": None, "both_settings_on": None, "matching_4688_count": None,
                "errors": ["preflight_unavailable_run_from_elevated_windows_powershell"]}


def diagnose_capture(results, observation):
    """Do not turn denied log access or a missing assessment into capture failure."""
    if results:
        if any(not row["T1059_001_present"] for row in results):
            return "incident_with_no_technique"
        return None
    count = observation.get("matching_4688_count")
    if count == 0:
        return "no_4688_in_security_log"
    if count is not None and count > 0:
        return "no_incident_ingested"
    return None


def check(source_db, window_path, daily_summary=None, observation=None):
    window = json.loads(private_path(window_path).read_text(encoding="utf-8-sig"))
    if window.get("kind") != "controlled_test" or not window.get("ended_at"):
        raise ValueError("A completed controlled test window is required")
    observation = preflight(window_path) if observation is None else observation
    start, end = parse_time(window["started_at"]), parse_time(window["ended_at"])
    matches = []
    root = PRIVATE_DIR / "controlled-checks"
    root.mkdir(exist_ok=True)
    with TemporaryDirectory(dir=root) as work:
        snapshot = snapshot_source(source_db, Path(work) / "source")
        with closing(sqlite3.connect(Path(snapshot["snapshot_path"]).as_uri() + "?mode=ro&immutable=1", uri=True)) as source:
            for identity, raw in source.execute("SELECT incident_id,payload FROM incidents"):
                incident = json.loads(raw)
                if any(str(e.get("host", "")).casefold() == window["host"].casefold() and start <= parse_time(e["timestamp"]) <= end and window["encoded_command"] in e.get("message", "") for e in incident.get("events", [])):
                    matches.append((identity, incident))
    saved = {}
    if daily_summary:
        summary = json.loads(private_path(daily_summary).read_text(encoding="utf-8-sig"))
        batch = json.loads(private_path(summary["batch"]["results_file"]).read_text(encoding="utf-8-sig"))
        saved = {row["source_incident_id"]: row["result"] for row in batch["results"]}
        with closing(sqlite3.connect(private_path(summary["batch"]["history_database"]).as_uri() + "?mode=ro", uri=True)) as history:
            for raw, in history.execute("SELECT response_json FROM forecasts WHERE environment='test' ORDER BY created_at DESC"):
                response = json.loads(raw)
                saved.setdefault(response.get("alert_id"), response)
    results = []
    for index, (identity, incident) in enumerate(matches, 1):
        analysis = incident.get("risk_analysis") or {}
        forecast = saved.get(identity)
        results.append({"incident": "controlled_incident_" + str(index),
            "behavioral_score_present": "behavioral_score" in analysis, "technique_evidence_present": "technique_evidence" in analysis,
            "T1059_001_present": "T1059.001" in analysis.get("mitre_techniques", []),
            "status": forecast.get("status", forecast.get("response_type")) if forecast else "not_in_this_batch",
            "reason": forecast.get("reason") if forecast else None, "path": ([forecast["predicted_path"]["starting_technique"]] + [s["technique_id"] for s in forecast["predicted_path"]["steps"]]) if forecast and forecast.get("predicted_path") else None,
            "risk_score": forecast.get("risk_score") if forecast else None,
            "unresolved_guards": sorted({g["type"] for row in (forecast or {}).get("diagnostics", {}).get("rejected_transitions", []) for g in row.get("guard_evaluations", []) if g["status"] == "unresolved"}),
            "unresolved_prerequisites": sorted({reason for row in (forecast or {}).get("diagnostics", {}).get("rejected_transitions", []) for reason in row.get("reasons", []) if "unresolved" in reason}),
            "issue_codes": sorted({i["code"] for i in (forecast or {}).get("issues", [])})})
    diagnosis = diagnose_capture(results, observation)
    return {"environment": "test", "preflight": observation,
            "diagnosis": diagnosis,
            "diagnosis_inconclusive": not results and diagnosis is None,
            "matching_incidents": len(results), "results": results,
            "note": "No match means capture/ingestion has not been demonstrated. Presence of additive fields alone does not prove which running source revision was loaded."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-db", default=PRIVATE_DIR.parent.parent / "backend" / "soc_agents.db")
    parser.add_argument("--window")
    parser.add_argument("--preflight", action="store_true", help="Only inspect current OS settings/log/listener; no window required")
    parser.add_argument("--daily-summary")
    args = parser.parse_args()
    if args.preflight:
        print(json.dumps(preflight(), indent=2))
    elif not args.window:
        parser.error("--window is required unless --preflight is used")
    else:
        print(json.dumps(check(args.backend_db, args.window, args.daily_summary), indent=2))

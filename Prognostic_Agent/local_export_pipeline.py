"""Replay synthetic events bound to an actually exported local host/account.

Only inventory facts are real. No security action or command in an event is run.
No lab reachability, criticality, exposure, policy state or privileges are added.
"""

import argparse
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import uuid

from .config import AGENT_DIR
from .contracts import parse_time, utc_text
from .event_pipeline_demo import _write, confine_writes, make_event_document, run_pipeline
from .importers.core import import_inventory
from .lab_pipeline_demo import LAB_RULES


def select_subject(inventory):
    host = next((record for record in inventory["entities"] if record["entity_type"] == "host"), None)
    users = {record["canonical_id"]: record for record in inventory["entities"]
             if record["entity_type"] == "user" and record.get("source_attributes", {}).get("is_local_account")
             and record.get("account_controls", {}).get("enabled") is True}
    if host is None or not users:
        raise ValueError("A collected host and an enabled exported local account are required; no identity was fabricated")
    ordered = sorted(users.values(), key=lambda record: (record.get("privilege_level") != "admin", record["canonical_id"]))
    user = ordered[0]
    hostname = host["source_attributes"]["hostname"]
    return host, user, hostname, hostname + "\\" + user["source_attributes"]["name"]


def run_local_export_pipeline(raw_path, directory):
    directory = Path(directory).resolve()
    if not directory.is_relative_to(AGENT_DIR.resolve()):
        raise ValueError("Local-export replay outputs must stay inside Prognostic_Agent")
    directory.mkdir(parents=True, exist_ok=False)
    imported = import_inventory(raw_path, environment="test", output_root=directory / "imports")
    if not imported["publishable"]:
        raise ValueError("Raw export was quarantined; inspect " + imported["issues_path"])
    inventory = json.loads(Path(imported["inventory_path"]).read_text(encoding="utf-8"))
    host_record, user_record, hostname, username = select_subject(inventory)
    collected = parse_time(inventory["source"]["collected_at"])
    document = make_event_document(collected + timedelta(seconds=20), host=hostname, user=username)
    # Place synthetic records after the inventory snapshot, without refreshing
    # inventory timestamps or waiting in real time. The causal cutoffs are explicit.
    for event, offset in zip(document["events"], (2, 4, 6, 8, 10, 14, 18)):
        event["timeCreatedUtc"] = utc_text(collected + timedelta(seconds=offset))
    document["provenance"] = "Synthetic replay events; only the bound host/account inventory comes from a real export."

    def prepare(serialized, cutoff):
        payload = deepcopy(serialized)
        snapshot_id = "local-export:" + imported["source_sha256"][:16]
        controls = user_record["account_controls"]
        payload["events"].append({"event_id": snapshot_id, "timestamp": utc_text(collected),
            "source": "local_export", "event_type": "inventory_snapshot", "host": hostname, "user": username,
            "metadata": {"environment": "test", "source_sha256": imported["source_sha256"],
                         "enabled": controls["enabled"], "locked": controls["locked"], "blocked": None,
                         "privilege_scope_host_ids": user_record.get("privilege_scope_host_ids")}})
        analysis = payload["risk_analysis"]
        technique = "T1110.001"
        if technique not in analysis["mitre_techniques"]:
            return payload, None
        refs = analysis["technique_evidence"].get(technique, [])
        events = {event["event_id"]: event for event in serialized["events"]}
        if not refs or any(ref not in events for ref in refs):
            return payload, None
        times = [parse_time(events[ref]["timestamp"]) for ref in refs]
        bindings = [{"technique_id": technique, "seed_event_id": ref,
            "user_id": "user:" + username.casefold(), "host_id": host_record["entity_id"],
            "source_ip": events[ref]["source_ip"], "endpoint_id": "auth:" + hostname.casefold() + ":network-logon",
            "analyst_correlation": {"source": "analyst", "as_of": utc_text(max(times)), "evidence_refs": list(refs),
                "activity": "online_authentication_failures", "event_count": len(refs),
                "window_start": utc_text(min(times)), "window_end": utc_text(max(times))},
            "account_authentication": {"source": "local_export", "as_of": utc_text(collected), "evidence_refs": [snapshot_id],
                "enabled": controls["enabled"], "locked": controls["locked"], "blocked": None}}
            for ref in refs]
        # No authentication_reachability assertion: local listeners do not prove
        # reachability from the synthetic remote source. blocked remains unknown.
        return payload, {"schema_version": 1, "bindings": bindings}

    pipeline = run_pipeline(directory / "pipeline", inventory_document=inventory, rules_path=LAB_RULES,
                            event_document=document, causal_replay=True, prepare_adapter=prepare)
    comparison = []
    for item in pipeline["results"]:
        response = item["forecast"]
        rejected = response.get("diagnostics", {}).get("rejected_transitions", [])
        path = response.get("predicted_path")
        unresolved = sorted({evaluation["type"] for row in rejected for evaluation in row.get("guard_evaluations", [])
                             if evaluation["status"] == "unresolved"})
        comparison.append({"incident": item["event_type"], "environment": response["environment"],
            "status": response.get("status", response["response_type"]), "reason": response.get("reason"),
            "path": [path["starting_technique"]] + [step["technique_id"] for step in path["steps"]] if path else None,
            "risk_score": response.get("risk_score"), "unresolved_guards": unresolved,
            "unresolved_prerequisites": sorted({reason for row in rejected for reason in row["reasons"] if "unresolved" in reason}),
            "issues": response.get("issues", []),
            "guard_sources_not_evaluated": [technique["technique_id"] for technique in item["adapter_request"]["observed_techniques"]
                                           if technique["technique_id"].startswith("T1110") and not technique["evidence_refs"]]})
    report = {"schema_version": 1, "environment": "test", "import": imported,
              "provenance": "Real local-export inventory; synthetic attack events. No reachability or policy-blocking facts invented.",
              "selected_subject": {"host_id": host_record["entity_id"], "user_id": "user:" + username.casefold(),
                                   "selection": "Enabled exported local account, preferring SID-verified host-local admin membership"},
              "issues": json.loads(Path(imported["issues_path"]).read_text(encoding="utf-8")),
              "comparison": comparison, "pipeline": pipeline}
    _write(directory / "local_export_pipeline.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-export", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--environment", choices=["test"], default="test")
    args = parser.parse_args(argv)
    confine_writes()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    directory = args.output_dir or AGENT_DIR / "private" / "local-pipeline" / (stamp + "_" + uuid.uuid4().hex[:8])
    report = run_local_export_pipeline(args.raw_export, directory)
    print(json.dumps({"environment": "test", "comparison": report["comparison"],
                      "quarantine": report["issues"]["quarantine"], "import": report["import"],
                      "full_report": str(directory / "local_export_pipeline.json")}, indent=2))
    return 0 if all(row["status"] in {"complete", "partial", "abstained"} for row in report["comparison"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())

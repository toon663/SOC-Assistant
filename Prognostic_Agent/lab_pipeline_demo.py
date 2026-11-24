"""Causal event-time lab replay, explicit guards and one-fact removal controls.

All assertions are hand-authored lab ground truth, not new backend capabilities.
No behavioral score or technique-attribution overrides, network, DB or LLM calls.
"""

import argparse
import ast
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import uuid

from .analyst_adapter import adapt_analyst_incident
from .asset_context import LocalJSONAssetProvider
from .config import AGENT_DIR, ForecastConfig
from .contracts import parse_time
from .event_pipeline_demo import InventorySystems, REPO_ROOT, _write, confine_writes, run_pipeline
from .prognostic_agent import build_risk_forecast

LAB_DIR = AGENT_DIR / "examples" / "auth_lab"
LAB_RULES = AGENT_DIR / "rules" / "attack_transitions_guarded_auth.json"


def _read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def verify_expected_failure_scope():
    snapshot = _read(LAB_DIR / "expected_failure_scope.json")
    expected = set(snapshot["methods"])
    historical = AGENT_DIR / snapshot["source_report"]
    if historical.exists():
        assert expected == set(_read(historical)["classification"]["unbuilt_or_unwired_approval_layer"]["tests"])
    path = REPO_ROOT / "backend" / "tests" / "test_approvals.py"
    source = path.read_text(encoding="utf-8")
    actual = set()
    available = set()
    for cls in ast.parse(source).body:
        if not isinstance(cls, ast.ClassDef):
            continue
        for method in cls.body:
            if isinstance(method, ast.FunctionDef):
                available.add("test_approvals." + cls.name + "." + method.name)
            if isinstance(method, ast.FunctionDef) and any(isinstance(item, ast.Name) and item.id == "expected_unbuilt_approval" for item in method.decorator_list):
                actual.add("test_approvals." + cls.name + "." + method.name)
    return {"exact_match": expected == actual, "count": len(actual), "methods": sorted(actual),
            "historical_methods_count": len(expected), "all_original_methods_present": expected <= available,
            "decorators_match_historical_snapshot": expected == actual,
            "missing": sorted(expected - actual), "extra": sorted(actual - expected),
            "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "historical_scope_checked": historical.exists(), "scope_snapshot": str(LAB_DIR / "expected_failure_scope.json")}


def adapter_preparer(inventory, plan):
    records = {item["entity_id"]: item for item in inventory["entities"]}
    subject = plan["subject"]
    endpoint = records[subject["host_id"]]["authentication_endpoint"]
    controls = records[subject["user_id"]]["account_controls"]
    if endpoint["endpoint_id"] != subject["endpoint_id"] or controls["endpoint_id"] != subject["endpoint_id"]:
        raise ValueError("Lab endpoint identities disagree")
    if endpoint["source_ip"] != subject["source_ip"] or endpoint["reachable"] != plan["authentication_reachability"]["reachable"]:
        raise ValueError("Lab reachability facts disagree")
    if any(controls[key] != plan["account_authentication"][key] for key in ("enabled", "locked", "blocked")):
        raise ValueError("Lab account-control facts disagree")

    def prepare(serialized, cutoff):
        payload = deepcopy(serialized)
        snapshot = deepcopy(plan["inventory_evidence"])
        if parse_time(snapshot["timestamp"]) > parse_time(cutoff):
            raise ValueError("Lab inventory proof is future-dated")
        payload["events"].append(snapshot)
        analysis = payload["risk_analysis"]
        technique = plan["source_technique"]
        if technique not in analysis["mitre_techniques"]:
            return payload, None
        source_events = {item["metadata"].get("record_id"): item for item in serialized["events"]}
        cohort = plan["analyst_correlation"]["record_ids"]
        if any(identity not in source_events for identity in cohort):
            raise ValueError("The lab cohort is not fully supplied by this incident")
        refs = [source_events[identity]["event_id"] for identity in cohort]
        if set(refs) != set(analysis["technique_evidence"].get(technique, [])):
            raise ValueError("Hand-authored cohort does not match actual Analyst attribution")
        correlation = {key: deepcopy(value) for key, value in plan["analyst_correlation"].items() if key != "record_ids"}
        correlation["evidence_refs"] = refs
        bindings = [{**deepcopy(subject), "technique_id": technique,
                     "seed_event_id": source_events[identity]["event_id"],
                     "analyst_correlation": deepcopy(correlation),
                     "authentication_reachability": deepcopy(plan["authentication_reachability"]),
                     "account_authentication": deepcopy(plan["account_authentication"])}
                    for identity in plan["seed_record_ids"]]
        return payload, {"schema_version": 1, "bindings": bindings}

    return prepare


def summarize(kind, variant, forecast):
    path = forecast.get("predicted_path")
    radius = forecast.get("blast_radius", {})
    coverage = sorted({issue["code"] for issue in forecast.get("issues", [])} |
                      {"unsupported:" + item["technique_id"] for item in forecast.get("unsupported_starting_techniques", [])} |
                      {reason for item in forecast.get("diagnostics", {}).get("rejected_transitions", []) for reason in item["reasons"]})
    return {"incident": kind, "variant": variant, "environment": forecast["environment"],
            "status": forecast.get("status", forecast["response_type"]), "reason": forecast.get("reason"),
            "path": [path["starting_technique"]] + [step["technique_id"] for step in path["steps"]] if path else None,
            "risk_score": forecast.get("risk_score"), "risk_score_basis": forecast.get("risk_score_basis"),
            "likelihood_index": (forecast.get("likelihood") or {}).get("index"),
            "blast_radius": {key: radius.get(key) for key in ("observed_count", "potential_count", "potential_entities", "unknown_relationship_entities")},
            "issues": forecast.get("issues", []), "coverage_findings": coverage,
            "unsupported_starting_techniques": forecast.get("unsupported_starting_techniques", []),
            "rejected_transitions": forecast.get("diagnostics", {}).get("rejected_transitions", [])}


def run_lab(directory):
    directory = Path(directory).resolve()
    if not directory.is_relative_to(AGENT_DIR.resolve()):
        raise ValueError("Lab outputs must stay inside Prognostic_Agent")
    directory.mkdir(parents=True, exist_ok=False)
    inventory, plan = _read(LAB_DIR / "inventory.json"), _read(LAB_DIR / "guard_assertions.json")
    if inventory["environment"] != "test" or plan["environment"] != "test":
        raise ValueError("Lab artifacts must be environment=test")
    scope = verify_expected_failure_scope()
    _write(directory / "expected_failure_scope.json", scope)
    prepare = adapter_preparer(inventory, plan)
    pipeline = run_pipeline(directory / "pipeline", inventory_document=inventory, rules_path=LAB_RULES,
                            event_document_as_of=plan["event_document_as_of"], causal_replay=True,
                            prepare_adapter=prepare)
    config = ForecastConfig(environment="test", rules_path=LAB_RULES, max_candidates=5)
    results, comparison = [], []
    for item in pipeline["results"]:
        kind, baseline = item["event_type"], item["forecast"]
        request, changed_inventory = deepcopy(item["adapter_request"]), deepcopy(inventory)
        records = {record["entity_id"]: record for record in changed_inventory["entities"]}
        if kind == "failed_logon":
            variant, changed_fact = "auth_reachability_unknown", "host:fixture-workstation.authentication_endpoint.reachable"
            records[plan["subject"]["host_id"]]["authentication_endpoint"].pop("reachable")
            for binding in request["guard_context"]["bindings"]:
                binding["authentication_reachability"].pop("reachable")
            for event in request["normalized_events"]:
                if event["event_id"] == plan["inventory_evidence"]["event_id"]:
                    event["metadata"].pop("reachable")
        elif kind == "successful_logon":
            variant, changed_fact = "account_privilege_unknown", "user:fixture-admin.privilege_level"
            records[plan["subject"]["user_id"]].pop("privilege_level")
        else:
            variant, changed_fact = "topology_unknown", "host:fixture-workstation.related_assets"
            records[plan["subject"]["host_id"]].pop("related_assets")
        variant_dir = directory / kind / variant
        variant_dir.mkdir(parents=True)
        _write(variant_dir / "inventory.json", changed_inventory)
        _write(variant_dir / "request.json", request)
        degraded = build_risk_forecast(request, config=config, forecast_as_of=baseline["forecast_as_of"],
                                       asset_provider=LocalJSONAssetProvider(variant_dir / "inventory.json"))
        _write(variant_dir / "forecast.json", degraded)
        results.append({"incident": kind, "baseline": item, "variant": variant,
                        "changed_fact": changed_fact, "variant_request": request,
                        "variant_inventory": changed_inventory, "variant_forecast": degraded})
        comparison.extend([summarize(kind, "baseline", baseline), summarize(kind, variant, degraded)])

    # Preserve the old batch semantics as a control: Analyst has already seen
    # the success, so T1078 must not be forecast again from the failure group.
    import agents
    from analyst import RelatedEvent
    failed = next(item for item in pipeline["results"] if item["event_type"] == "failed_logon")
    incident = agents.incident_from_dict(failed["sentinel_incident"])
    related = [RelatedEvent(event, incident_id=other.incident_id, title=other.alert["title"])
               for item in pipeline["results"] if item["event_type"] != "failed_logon"
               for other in [agents.incident_from_dict(item["sentinel_incident"])] for event in other.events]
    agents.AnalystAgent(InventorySystems(inventory)).analyze(incident, related)
    serialized = agents.incident_to_dict(incident)
    payload, guards = prepare(serialized, plan["event_document_as_of"])
    batch_request = adapt_analyst_incident(payload, guard_context=guards)
    batch_forecast = build_risk_forecast(batch_request, config=config, forecast_as_of=plan["event_document_as_of"],
                                        asset_provider=LocalJSONAssetProvider(directory / "pipeline" / "inventory.json"))
    after = {name: hashlib.sha256((REPO_ROOT / name).read_bytes()).hexdigest()
             for name in pipeline["execution"]["protected_artifact_sha256"]}
    if after != pipeline["execution"]["protected_artifact_sha256"]:
        raise RuntimeError("Protected pipeline artifacts changed")
    report = {"schema_version": 1, "environment": "test", "rules_path": str(LAB_RULES),
              "inventory_path": str(LAB_DIR / "inventory.json"), "guard_assertions_path": str(LAB_DIR / "guard_assertions.json"),
              "provenance": plan["provenance"], "scope_check": scope,
              "replay_policy": "Forecast at each incident's final event plus one second; Analyst receives no future related events. triaged_at remains processing-time provenance.",
              "protected_artifacts_unchanged": True, "pipeline": pipeline,
              "comparison": comparison, "results": results,
              "batch_control": {"analyst_incident": serialized, "adapter_request": batch_request,
                                "forecast": batch_forecast, "summary": summarize("failed_logon", "batch_control", batch_forecast)}}
    _write(directory / "lab_results.json", report)
    return report


def comparison_table(rows):
    lines = ["| Incident / variant | Status | Reason | Path | Risk | Blast observed / potential | Issues / coverage findings |",
             "|---|---|---|---|---:|---:|---|"]
    for row in rows:
        radius = row["blast_radius"]
        path = " -> ".join(row["path"]) if row["path"] else "null"
        notes = ", ".join(row["coverage_findings"]) or "none"
        lines.append(f"| {row['incident']} / {row['variant']} | {row['status']} | {row['reason']} | {path} | {row['risk_score']} | {radius['observed_count']} / {radius['potential_count']} | {notes} |")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    confine_writes()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    directory = args.output_dir or AGENT_DIR / "private" / "lab-pipeline" / (stamp + "_" + uuid.uuid4().hex)
    report = run_lab(directory)
    print(comparison_table(report["comparison"]))
    print("Scope match: " + str(report["scope_check"]["exact_match"]))
    print("Batch control: " + json.dumps({key: report["batch_control"]["summary"][key]
                                         for key in ("status", "reason", "path", "risk_score")}))
    print("Full lab output: " + str(directory / "lab_results.json"))
    return 0 if all(row["status"] in {"complete", "partial", "abstained"} for row in report["comparison"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Private per-decision shadow records and summaries. Never executes actions."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import uuid

from .contracts import content_hash, utc_text, parse_time
from .migrations import validate_environment
from .orchestrator_advisory import MAPPING_HASH, MAPPING_VERSION, prioritize_response_options
from .orchestrator_contract import ContractError, empty_record, validate_contract
from .private_paths import PRIVATE_DIR, private_path, write_private

DEFAULT_LOG_DIRECTORY = PRIVATE_DIR / "orchestrator-shadow"
KNOWN_ACTIONS = {"isolate_endpoint", "disable_user", "block_ip", "quarantine_file", "monitor", "create_ticket"}


def _option_view(option, index):
    # Logs contain hashes rather than raw target identities or caller option IDs.
    return {"option_ref": content_hash(option.get("option_id", {"action":option.get("action"), "target":option.get("target_entity_id"), "slot":index})),
            "action": option.get("action") if option.get("action") in KNOWN_ACTIONS else "other",
            "target_ref": content_hash(option["target_entity_id"]) if isinstance(option.get("target_entity_id"), str) else None,
            "eligible": option.get("eligible") if type(option.get("eligible")) is bool else None,
            "approval_required": option.get("approval_required") if type(option.get("approval_required")) is bool else None}


class ShadowDecisionLog:
    def __init__(self, directory=DEFAULT_LOG_DIRECTORY, *, environment="test"):
        validate_environment(environment)
        self.directory = private_path(directory)
        self.environment = environment

    def record(self, forecast, baseline_options, *, now=None):
        now = now or datetime.now(timezone.utc)
        try:
            validate_contract(forecast, expected_environment=self.environment, now=now)
        except (ContractError, ValueError, TypeError, KeyError) as error:
            identity = forecast.get("alert_id") if isinstance(forecast,dict) and isinstance(forecast.get("alert_id"),str) else None
            reason = error.code if isinstance(error,ContractError) else "contract_validation_failed"
            forecast = empty_record("validation_error", reason, environment=self.environment, alert_id=identity)
            forecast["issues"] = [{"code":reason, "detail":"Invalid handoff is no forecast, never low risk."}]
        advisory = prioritize_response_options(baseline_options, forecast, now=now)
        before = [_option_view(o, i) for i, o in enumerate(baseline_options)]
        # Use the original option views so even anonymous options retain stable
        # references when moved. Advisory never adds/removes/edits dictionaries.
        ordered = []
        remaining = list(enumerate(baseline_options))
        for option in advisory["prioritized_options"]:
            match = next((j for j, (_, original) in enumerate(remaining) if original == option), None)
            if match is None:
                raise ValueError("Advisory is not a permutation")
            original_index, _ = remaining.pop(match)
            ordered.append(before[original_index])
        identity = forecast.get("alert_id")
        correlation = forecast.get("request_id") or uuid.uuid4().hex
        record = {"schema_version":1, "response_type":"orchestrator_shadow_decision", "decision_id":uuid.uuid4().hex,
                  "created_at":utc_text(now), "environment":self.environment,
                  "incident_ref":content_hash(identity) if identity is not None else None,
                  "correlation_ref":content_hash(correlation),
                  "analyst_revision_ref":content_hash(forecast["analyst_revision"]) if forecast.get("analyst_revision") else None,
                  "forecast_id":forecast["forecast_id"], "forecast_revision":forecast["forecast_revision"],
                  "forecast_response_type":forecast["response_type"], "forecast_status":forecast["status"], "forecast_reason":forecast["reason"],
                  "numeric_assessment_status":forecast["numeric_assessment_status"],
                  "mapping_version":MAPPING_VERSION, "mapping_hash":MAPPING_HASH,
                  "options_without_forecast":before, "options_with_forecast":ordered,
                  "order_changed":advisory["order_changed"], "advisory_reason":advisory["reason"],
                  "issue_codes":sorted({i["code"] for i in forecast["issues"]}), "dry_run":True, "executed_actions":[]}
        path = self.directory / (record["decision_id"] + ".json")
        write_private(path, record)
        return record

    def summary(self):
        return summarize_shadow_log(self.directory, environment=self.environment)


def summarize_shadow_log(directory=DEFAULT_LOG_DIRECTORY, *, environment="test", start=None, end=None, queue_status=None):
    validate_environment(environment)
    start = parse_time(start) if start is not None else None
    end = parse_time(end) if end is not None else None
    if start is not None and end is not None and start >= end:
        raise ValueError("Start must precede end")
    statuses, reasons, advisory_reasons = Counter(), Counter(), Counter()
    skipped, errored, incidents, forecasts = set(), set(), set(), set()
    decision_count = changed = skip_count = error_count = invalid = unbound = 0
    mappings = Counter()
    for path in sorted(private_path(directory).glob("*.json")):
        try:
            row = json.loads(path.read_text(encoding="utf-8"))
            if row.get("response_type") != "orchestrator_shadow_decision" or row.get("schema_version") != 1 or row.get("dry_run") is not True or row.get("executed_actions") != []:
                raise ValueError()
            if not isinstance(row.get("mapping_version"), str) or not isinstance(row.get("mapping_hash"), str) or len(row["mapping_hash"]) != 64:
                raise ValueError()
            if row["environment"] != environment:
                continue
            if start is not None or end is not None:
                created = parse_time(row["created_at"])
                if (start is not None and created < start) or (end is not None and created >= end):
                    continue
            kind = row["forecast_response_type"]
            if (kind not in {"risk_forecast","skipped_benign","validation_error","operational_error"} or
                type(row["order_changed"]) is not bool or (row["incident_ref"] is not None and not isinstance(row["incident_ref"],str)) or
                not isinstance(row["forecast_reason"],str) or not isinstance(row["advisory_reason"],str) or
                (kind=="risk_forecast" and (row["forecast_status"] not in {"complete","partial","abstained"} or not isinstance(row["forecast_id"],str))) or
                (kind!="risk_forecast" and row["forecast_status"] is not None)):
                raise ValueError()
            decision_count += 1
            if row["incident_ref"] is None:
                unbound += 1
            else:
                incidents.add(row["incident_ref"])
            changed += row["order_changed"] is True
            reasons[row["forecast_reason"]] += 1
            advisory_reasons[row["advisory_reason"]] += 1
            mappings[(row["mapping_version"], row["mapping_hash"])] += 1
            if kind == "risk_forecast":
                statuses[row["forecast_status"]] += 1
                forecasts.add(row["forecast_id"])
            elif kind == "skipped_benign":
                if row["incident_ref"] is not None: skipped.add(row["incident_ref"])
                skip_count += 1
            elif kind in {"validation_error", "operational_error"}:
                if row["incident_ref"] is not None: errored.add(row["incident_ref"])
                error_count += 1
            else:
                raise ValueError()
        except (ValueError, KeyError, TypeError, OSError, AttributeError):
            invalid += 1
    queue = {"available":False, "scope":"process_lifetime_not_date_filtered", "reason":"No queue status snapshot supplied; historical queue counts are not persisted."}
    if queue_status is not None:
        status = queue_status.get("prognostic_observer") if isinstance(queue_status, dict) else None
        if isinstance(status, dict) and status.get("mode") == "shadow" and status.get("environment") == environment and isinstance(status.get("counts"), dict):
            allowed = {"accepted", "completed", "skipped_benign", "forecast_errors", "observer_queue_full", "observer_shutdown_dropped", "observer_closed", "observer_timeout", "observer_submission_failed", "observer_snapshot_too_large", "observer_failed", "observer_client_failed", "observer_package_missing", "observer_logging_failed", "observer_mapping_mismatch", "observer_contract_invalid", "observer_failure_log_failed", "observer_worker_loop_failed", "observer_shutdown_failed"}
            counts = status.get("counts") if isinstance(status.get("counts"), dict) else {}
            queue = {"available":True, "scope":"process_lifetime_not_date_filtered",
                     "counts":{k:v for k,v in counts.items() if k in allowed and type(v) is int and v >= 0},
                     "queued":status.get("queued") if type(status.get("queued")) is int else None,
                     "capacity":status.get("capacity") if type(status.get("capacity")) is int else None}
        else:
            queue["reason"] = "Observer disabled, unavailable or environment mismatch in supplied snapshot."
    return {"response_type":"orchestrator_shadow_summary", "environment":environment,
            "date_range":{"start_inclusive":utc_text(start) if start else None,"end_exclusive":utc_text(end) if end else None,"timezone":"UTC"},
            "queue_counters":queue,
            "counting_basis":"Status/reason/order counts are per decision; incident counts are distinct incident_ref values. Categories can overlap across revisions.",
            "decision_count":decision_count, "incident_count":len(incidents), "distinct_forecast_count":len(forecasts),
            "unbound_decision_count":unbound,
            "forecast_status_counts":dict(statuses), "reason_counts":dict(reasons), "advisory_reason_counts":dict(advisory_reasons),
            "order_changed_count":changed, "order_change_rate":changed/decision_count if decision_count else None,
            "skipped_decision_count":skip_count, "skipped_incident_count":len(skipped),
            "errored_decision_count":error_count, "errored_incident_count":len(errored), "invalid_log_file_count":invalid,
            "mapping_versions":[{"mapping_version":v,"mapping_hash":h,"decision_count":n} for (v,h),n in sorted(mappings.items())],
            "executed_action_count":0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=PRIVATE_DIR / "orchestrator-observer")
    parser.add_argument("--environment", choices=("test","demo","production"), default="test")
    parser.add_argument("--start", help="Inclusive UTC timestamp, e.g. 2026-11-23T00:00:00Z")
    parser.add_argument("--end", help="Exclusive UTC timestamp")
    parser.add_argument("--queue-status-file", type=Path, help="Private JSON snapshot of GET /orchestrator/status; process-lifetime counters, not date-filtered")
    args = parser.parse_args(argv)
    try:
        status = json.loads(private_path(args.queue_status_file).read_text(encoding="utf-8-sig")) if args.queue_status_file else None
        result = summarize_shadow_log(args.directory, environment=args.environment, start=args.start, end=args.end, queue_status=status)
    except (OSError, ValueError, TypeError):
        parser.error("Invalid date range, private status snapshot or summary input")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

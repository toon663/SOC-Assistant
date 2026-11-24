"""Monday-to-Monday shadow assessment report in America/Los_Angeles.

Counts stored forecast IDs once, never delivery attempts. Errors have separate
attempt-based sections and are excluded from the abstention-rate denominator.
"""

import argparse
from collections import Counter, defaultdict
from datetime import date, datetime, time, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import uuid
from zoneinfo import ZoneInfo

from .contracts import parse_time, utc_text
from .private_paths import PRIVATE_DIR, private_path, write_private
from .shadow_batch import SHADOW_HISTORY
from .payload_categories import LEGACY
from .storage import storage_time

TIMEZONE = "America/Los_Angeles"


def week_window(week_start=None, *, now=None):
    zone = ZoneInfo(TIMEZONE)
    now = now or datetime.now(timezone.utc)
    if now.utcoffset() is None:
        raise ValueError("Report clock must be timezone-aware")
    if week_start is None:
        local_day = now.astimezone(zone).date()
        start_day = local_day - timedelta(days=local_day.weekday() + 7)
    else:
        start_day = date.fromisoformat(week_start) if isinstance(week_start, str) else week_start
    if start_day.weekday() != 0:
        raise ValueError("week-start must be a Monday")
    start = datetime.combine(start_day, time.min, zone)
    end = datetime.combine(start_day + timedelta(days=7), time.min, zone)
    return {"timezone": TIMEZONE, "start_local": start.isoformat(), "end_local": end.isoformat(),
            "start_utc": storage_time(start), "end_utc": storage_time(end), "bounds": "start inclusive, end exclusive",
            "hours": (end.astimezone(timezone.utc) - start.astimezone(timezone.utc)).total_seconds() / 3600}


def outcome(response, *, identity, created_at, unit):
    context = response.get("shadow_context") or {}
    path = response.get("predicted_path")
    return {"unit": unit, "id": identity, "alert_id": response.get("alert_id") or context.get("source_incident_id"),
            "analyst_verdict": context.get("analyst_verdict") or response.get("analyst_verdict") or "unknown",
            "created_at": created_at, "response_type": response["response_type"], "status": response.get("status"),
            "reason": response.get("reason"), "risk_score": response.get("risk_score"),
            "issues": response.get("issues", []),
            "path": [path["starting_technique"]] + [step["technique_id"] for step in path["steps"]] if path else None,
            "evaluation_id": context.get("evaluation_id"), "inventory_sha256": context.get("inventory_sha256"),
            "source": response.get("source") or context.get("source"),
            "original_triage_id": response.get("original_triage_id") or context.get("original_triage_id"),
            "observed_security_outcome": None}


def build_weekly_report(history_path=SHADOW_HISTORY, *, week_start=None, now=None, include_legacy=False):
    path = private_path(history_path)
    if not path.is_file():
        raise ValueError("Shadow history does not exist; report never creates an empty database")
    window = week_window(week_start, now=now)
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("BEGIN")
        forecasts = connection.execute("SELECT forecast_id,created_at,response_json FROM forecasts WHERE environment='test' AND created_at>=? AND created_at<? ORDER BY created_at,forecast_id", (window["start_utc"], window["end_utc"])).fetchall()
        attempts = connection.execute("SELECT attempt_id,created_at,metrics_json FROM attempts WHERE environment='test' AND created_at>=? AND created_at<? ORDER BY created_at,attempt_id", (window["start_utc"], window["end_utc"])).fetchall()
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        categories = {row["assessment_key"]: json.loads(row["missing_fields_json"]) for row in connection.execute(
            "SELECT assessment_key,missing_fields_json FROM shadow_payload_categories WHERE environment='test' AND category=?", (LEGACY,))} if "shadow_payload_categories" in tables else {}
    finally:
        connection.close()
    statuses, reasons, abstention_reasons = Counter(), Counter(), Counter()
    unsupported = defaultdict(lambda: {"alerts": set(), "forecasts": set(), "reasons": defaultdict(set)})
    outcomes, errors = [], {"validation_error": [], "operational_error": []}
    replay_outcomes = []
    legacy = {}
    legacy_prior_forecasts = legacy_prior_validation = 0

    def collect_legacy(response, identity, created_at):
        context = response.get("shadow_context") or {}
        key = context.get("assessment_key", identity)
        if response["response_type"] != LEGACY and context.get("payload_category") != LEGACY and key not in categories:
            return False
        if key not in legacy:
            item = outcome(response, identity=identity, created_at=created_at, unit="legacy_assessment")
            item["original_assessment"] = {name: item[name] for name in ("response_type", "status", "reason", "path", "risk_score", "issues")}
            missing = context.get("missing_analyst_fields", categories.get(key, []))
            item.update(response_type=LEGACY, status=None, reason=LEGACY, path=None, risk_score=None,
                        missing_analyst_fields=missing, issues=[{"code": LEGACY, "missing_analyst_fields": missing}])
            legacy[key] = item
        return True

    forecast_count = 0
    for row in forecasts:
        response = json.loads(row["response_json"])
        if response["response_type"] != "risk_forecast":
            raise ValueError("Non-forecast found in forecasts table")
        if response.get("source") == "retriage_replay" or (response.get("shadow_context") or {}).get("source") == "retriage_replay":
            replay_outcomes.append(outcome(response, identity=row["forecast_id"], created_at=row["created_at"], unit="forecast"))
            continue
        if collect_legacy(response, row["forecast_id"], row["created_at"]):
            legacy_prior_forecasts += 1
            continue
        forecast_count += 1
        statuses[response["status"]] += 1
        reasons[response["reason"]] += 1
        if response["status"] == "abstained":
            abstention_reasons[response["reason"]] += 1
        outcomes.append(outcome(response, identity=row["forecast_id"], created_at=row["created_at"], unit="forecast"))
        for item in response.get("unsupported_starting_techniques", []):
            group = unsupported[item["technique_id"]]
            group["alerts"].add(response["alert_id"])
            group["forecasts"].add(row["forecast_id"])
            group["reasons"][item["reason"]].add(response["alert_id"])
    for row in attempts:
        metrics = json.loads(row["metrics_json"])
        kind = metrics["response_type"]
        if metrics.get("source") == "retriage_replay" or (metrics.get("shadow_context") or {}).get("source") == "retriage_replay":
            if kind in {"validation_error", "operational_error"}:
                replay_outcomes.append(outcome(metrics, identity=row["attempt_id"], created_at=row["created_at"], unit="error_attempt"))
            continue
        if kind == LEGACY or kind == "validation_error":
            if collect_legacy(metrics, row["attempt_id"], row["created_at"]):
                legacy_prior_validation += kind == "validation_error"
                continue
        if kind in errors:
            item = outcome(metrics, identity=row["attempt_id"], created_at=row["created_at"], unit="error_attempt")
            item["validation_errors"] = metrics.get("validation_errors", [])
            item["reason_detail"] = metrics.get("reason_detail")
            errors[kind].append(item)
            outcomes.append(item)
    all_outcomes = outcomes + (list(legacy.values()) if include_legacy else [])
    denominator = forecast_count
    numerator = statuses["abstained"]
    return {"schema_version": 1, "response_type": "weekly_shadow_report", "environment": "test", "window": window,
            "generated_at": utc_text(now or datetime.now(timezone.utc)), "history_database": str(path),
            "period_complete": parse_time(window["end_utc"]) <= (now or datetime.now(timezone.utc)),
            "counting_basis": "eligible non-legacy forecast_id, by first persisted created_at in [Monday 00:00,next Monday 00:00) local time; replay delivery attempts excluded; revisions count as separate forecasts; legacy payloads are a separate category",
            "forecast_count": denominator, "status_counts": dict(sorted(statuses.items())), "reason_counts": dict(sorted(reasons.items())),
            "legacy_payloads": {"category": LEGACY, "assessment_count": len(legacy), "included_in_view": include_legacy,
                                "prior_forecasts_reclassified": legacy_prior_forecasts,
                                "prior_validation_attempts_reclassified": legacy_prior_validation,
                                "items": list(legacy.values()) if include_legacy else [],
                                "basis": "Distinct assessment keys; source-contract classification overlays history without rewriting recorded forecasts or errors"},
            "assessment_category_counts": {"risk_forecast": denominator, "validation_error": len(errors["validation_error"]),
                                           "operational_error": len(errors["operational_error"]), **({LEGACY: len(legacy)} if include_legacy else {})},
            "reported_outcome_count": len(all_outcomes),
            "retriage_replay": {"source": "retriage_replay", "excluded_from_primary_counts": True,
                                "forecast_count": sum(item["unit"] == "forecast" for item in replay_outcomes),
                                "original_triage_count": len({item["original_triage_id"] for item in replay_outcomes if item["original_triage_id"]}),
                                "status_counts": dict(Counter(item["status"] or item["response_type"] for item in replay_outcomes)),
                                "reason_counts": dict(Counter(item["reason"] or item["response_type"] for item in replay_outcomes)),
                                "items": replay_outcomes},
            "distinct_alert_count": len({item["alert_id"] for item in outcomes if item["unit"] == "forecast"}),
            "abstention_rate": {"numerator": numerator, "denominator": denominator,
                                "rate": numerator / denominator if denominator else None,
                                "denominator_basis": "eligible non-legacy risk forecasts, including complete, partial and abstained; legacy payloads and validation/operational errors excluded",
                                "by_reason": [{"reason": key, "numerator": count, "denominator": denominator,
                                               "rate": count / denominator if denominator else None} for key, count in sorted(abstention_reasons.items())]},
            "unsupported_techniques": [{"technique_id": key, "distinct_alert_count": len(value["alerts"]),
                                         "forecast_count": len(value["forecasts"]),
                                         "reasons": [{"reason": reason, "distinct_alert_count": len(alerts)} for reason, alerts in sorted(value["reasons"].items())]}
                                        for key, value in sorted(unsupported.items(), key=lambda pair: (-len(pair[1]["alerts"]), pair[0]))],
            "validation_errors": {"attempt_count": len(errors["validation_error"]), "reason_counts": dict(Counter(item["reason"] or "validation_error" for item in errors["validation_error"])), "items": errors["validation_error"]},
            "operational_errors": {"attempt_count": len(errors["operational_error"]), "reason_counts": dict(Counter(item["reason"] or "operational_error" for item in errors["operational_error"])), "items": errors["operational_error"]},
            "non_benign_incidents": [item for item in all_outcomes if item["analyst_verdict"] in {"suspicious", "malicious"}],
            "unclassified_incidents": [item for item in all_outcomes if item["analyst_verdict"] not in {"benign", "suspicious", "malicious"}],
            "benign_with_predicted_path": [item for item in outcomes + list(legacy.values()) if item["analyst_verdict"] == "benign" and (item["path"] or item.get("original_assessment", {}).get("path"))],
            "outcome_note": "Outcomes are assessment/error results, not observed compromise. Subsequent security outcomes remain unknown.",
            "retention_note": "Uses retained history only (default 90 days). Export reports before purging their source period; durable unsupported aggregates are not substituted for weekly distinct-alert counts."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history-db", default=SHADOW_HISTORY)
    parser.add_argument("--week-start", help="Monday YYYY-MM-DD; default last completed local week")
    parser.add_argument("--output-dir", default=PRIVATE_DIR / "weekly")
    parser.add_argument("--environment", choices=["test"], required=True)
    parser.add_argument("--include-legacy", action="store_true", help="Show ineligible legacy payloads as a separate category, never validation errors")
    args = parser.parse_args(argv)
    report = build_weekly_report(args.history_db, week_start=args.week_start, include_legacy=args.include_legacy)
    start = report["window"]["start_local"][:10]
    path = private_path(args.output_dir) / ("weekly_" + start + ("_with_legacy_" if args.include_legacy else "_without_legacy_") + uuid.uuid4().hex[:8] + ".json")
    write_private(path, report)
    print(json.dumps({key: report[key] for key in ("environment", "window", "forecast_count", "status_counts", "reason_counts", "abstention_rate", "assessment_category_counts")} | {"legacy_assessment_count": report["legacy_payloads"]["assessment_count"], "report_file": str(path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

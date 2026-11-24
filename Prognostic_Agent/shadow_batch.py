"""Manual incremental shadow replay of persisted real incidents; test only.

No backend import, ingestion, network access, LLM, response action or scheduler.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import uuid

from .analyst_adapter import adapt_analyst_incident
from .asset_context import LocalJSONAssetProvider
from .batch_replay import DEFAULT_SOURCE_PATH, select_incidents
from .config import AGENT_DIR, ForecastConfig
from .contracts import AnalystAlert, RequestValidationError, content_hash, parse_time, utc_text, validation_error
from .private_paths import PRIVATE_DIR, private_path, write_private
from .provenance import operational_error, provenance
from .payload_categories import LEGACY, legacy_envelope, missing_analyst_fields
from .service import ForecastService, shadow_metrics
from .shadow_source import inspect_snapshot, snapshot_source
from .storage import ForecastHistory, storage_time

SHADOW_HISTORY = PRIVATE_DIR / "shadow" / "forecast_history.db"


class ShadowLedger:
    """Durable hash-only processed keys survive the 90-day forecast purge."""

    def __init__(self, history):
        self.history = history
        with history._transaction():
            history.connection.execute("CREATE TABLE IF NOT EXISTS shadow_schema_migrations(version INTEGER PRIMARY KEY,environment TEXT NOT NULL,applied_at TEXT NOT NULL)")
            version = history.connection.execute("SELECT MAX(version) FROM shadow_schema_migrations").fetchone()[0] or 0
            if version > 2:
                raise ValueError("Shadow ledger is newer than this runner")
            history.connection.execute("CREATE TABLE IF NOT EXISTS shadow_processed(environment TEXT NOT NULL,assessment_key TEXT NOT NULL,first_assessed_at TEXT NOT NULL,response_type TEXT NOT NULL,PRIMARY KEY(environment,assessment_key))")
            if version == 0:
                history.connection.execute("INSERT INTO shadow_schema_migrations VALUES(1,?,?)", (history.environment, storage_time(datetime.now(timezone.utc))))
            history.connection.execute("CREATE TABLE IF NOT EXISTS shadow_payload_categories(environment TEXT NOT NULL,assessment_key TEXT NOT NULL,category TEXT NOT NULL,missing_fields_json TEXT NOT NULL,PRIMARY KEY(environment,assessment_key))")
            if version < 2:
                history.connection.execute("INSERT INTO shadow_schema_migrations VALUES(2,?,?)", (history.environment, storage_time(datetime.now(timezone.utc))))
            # Recover the small gap after a committed service result and before
            # its ledger insert. Operational failures are deliberately retryable.
            for table, field in (("forecasts", "response_json"), ("attempts", "metrics_json")):
                for row in history.connection.execute(f"SELECT created_at,{field} FROM {table} WHERE environment=?", (history.environment,)).fetchall():
                    value = json.loads(row[field])
                    context = value.get("shadow_context") or {}
                    key = context.get("assessment_key")
                    if key and value.get("response_type") in {"risk_forecast", "validation_error", LEGACY}:
                        history.connection.execute("INSERT OR IGNORE INTO shadow_processed VALUES(?,?,?,?)",
                            (history.environment, key, row["created_at"], value["response_type"]))

    def keys(self):
        return {row[0] for row in self.history.connection.execute("SELECT assessment_key FROM shadow_processed WHERE environment=?", (self.history.environment,))}

    def complete(self, key, response):
        if response["response_type"] not in {"risk_forecast", "validation_error", LEGACY}:
            return
        if response["response_type"] == "risk_forecast" and not response.get("history", {}).get("persisted"):
            return
        with self.history._transaction():
            self.history.connection.execute("INSERT OR IGNORE INTO shadow_processed VALUES(?,?,?,?)",
                (self.history.environment, key, storage_time(datetime.now(timezone.utc)), response["response_type"]))

    def classify(self, categories):
        with self.history._transaction():
            self.history.connection.executemany("INSERT INTO shadow_payload_categories VALUES(?,?,?,?) ON CONFLICT(environment,assessment_key) DO UPDATE SET category=excluded.category,missing_fields_json=excluded.missing_fields_json",
                [(self.history.environment, key, LEGACY, json.dumps(missing)) for key, missing in categories.items()])


def assessment_key(source_identity, row):
    if "_shadow_input_key" not in row:
        try:
            fingerprint = AnalystAlert.from_dict(adapt_analyst_incident(row["incident"])).input_fingerprint
            kind = "canonical_normalized_input"
        except (RequestValidationError, ValueError, TypeError, KeyError, AttributeError):
            try:
                fingerprint = content_hash(row["incident"])
            except (TypeError, ValueError):
                fingerprint = row["source_payload_sha256"]
            kind = "invalid_source_payload"
        row["_shadow_input_key"] = {"kind": kind, "sha256": fingerprint}
    return content_hash({"environment": "test", "source": source_identity, "incident": row["source_incident_id"],
                         "input": row["_shadow_input_key"]})


def run_shadow_batch(source_db, inventory_path, *, output_dir, history_path=SHADOW_HISTORY, limit=10000,
                     now=None, evaluation_id=None, fresh_only=False):
    now = now or datetime.now(timezone.utc)
    if now.utcoffset() is None:
        raise ValueError("Shadow evaluation time must be timezone-aware")
    now = now.astimezone(timezone.utc)
    output_dir, history_path, inventory_path = map(private_path, (output_dir, history_path, inventory_path))
    if output_dir.exists():
        raise ValueError("Shadow output directory must be new")
    output_dir.mkdir(parents=True)
    inventory = json.loads(inventory_path.read_text(encoding="utf-8-sig"))
    if inventory.get("environment") != "test" or not inventory.get("publishable"):
        raise ValueError("Shadow run needs a publishable test inventory")
    # Hash the exact inventory used, including collection and overlay provenance.
    from .shadow_source import sha256_file
    inventory_hash = sha256_file(inventory_path)
    expected_evaluation = "shadow:" + now.date().isoformat() + ":inventory:" + inventory_hash
    if evaluation_id is not None and evaluation_id != expected_evaluation:
        raise ValueError("Evaluation ID must contain the UTC run date and exact inventory SHA-256: " + expected_evaluation)
    evaluation_id = expected_evaluation
    source = snapshot_source(source_db, output_dir / "source")
    inspection = inspect_snapshot(source, now=now)
    write_private(output_dir / "source_inspection.json", inspection)
    config = ForecastConfig(environment="test")
    results = []
    with ForecastHistory(history_path, environment="test") as history:
        ledger = ShadowLedger(history)
        done = ledger.keys()
        source_identity = source["source_identity"]
        categories, fresh_count, done_count = {}, 0, 0
        def eligible(row):
            nonlocal fresh_count, done_count
            key = assessment_key(source_identity, row)
            missing = missing_analyst_fields(row["incident"])
            if missing:
                categories[key] = missing
            try:
                triaged = parse_time(row["incident"]["risk_analysis"]["triaged_at"])
                fresh = 0 <= (now - triaged).total_seconds() <= 86400
            except (KeyError, TypeError, ValueError, AttributeError):
                fresh = False
            fresh_count += fresh
            done_count += key in done
            return key not in done and (not fresh_only or fresh)
        selected, selection = select_incidents(source["snapshot_path"], limit,
                                               eligible=eligible)
        ledger.classify(categories)
        service = ForecastService(history, config=config)
        provider = LocalJSONAssetProvider(inventory_path)
        for row in selected:
            context = {"schema_version": 1, "environment": "test", "assessment_key": assessment_key(source_identity, row),
                       "source_identity": source_identity, "source_payload_sha256": row["source_payload_sha256"],
                       "source_incident_id": row["source_incident_id"], "analyst_verdict": row["analyst_verdict"],
                       "evaluation_id": evaluation_id, "inventory_sha256": inventory_hash}
            missing = missing_analyst_fields(row["incident"])
            if missing:
                context.update(payload_category=LEGACY, missing_analyst_fields=missing)
                response = legacy_envelope(row["source_incident_id"], missing, provenance(config), context)
                history.record_attempt(shadow_metrics(response, {}, elapsed_ms=0))
            else:
                try:
                    request = adapt_analyst_incident(row["incident"])
                except (ValueError, TypeError, AttributeError, KeyError) as exc:
                    response = validation_error({"alert_id": row["source_incident_id"]},
                        [{"field": "$incident", "code": "invalid_analyst_incident", "message": type(exc).__name__}], metadata=provenance(config))
                    response["shadow_context"] = context
                    history.record_attempt(shadow_metrics(response, {}, elapsed_ms=0))
                else:
                    response = service.assess(request, asset_provider=provider, forecast_as_of=now,
                                              evaluation_id=evaluation_id, shadow_context=context)
            ledger.complete(context["assessment_key"], response)
            results.append({"source_incident_id": row["source_incident_id"], "analyst_verdict": row["analyst_verdict"], "result": response})
    summary = {"schema_version": 1, "response_type": "shadow_batch_result", "environment": "test",
               "evaluation_id": evaluation_id, "inventory_sha256": inventory_hash, "forecast_as_of": utc_text(now),
               "history_database": str(history_path), "processed_count": len(results),
               "remaining_count": max(0, selection["eligible_incident_count"] - len(selected)),
               "already_assessed_count": done_count,
               "fresh_only": fresh_only, "fresh_incident_count": fresh_count,
               "legacy_payload_unsupported_count": len(categories),
               "status_counts": dict(sorted(Counter(item["result"].get("status") or item["result"]["response_type"] for item in results).items())),
               "reason_counts": dict(sorted(Counter(item["result"].get("reason") or item["result"]["response_type"] for item in results).items())),
               "source": source, "source_inspection": inspection, "results": results,
               "selection": "Unseen (source,incident,canonical normalized input), suspicious first; changed input gets new assessments; operational errors retry",
               "clock": "Run-time UTC; existing evidence/asset freshness limits unchanged. Historical records are not made fresh."}
    summary["results_file"] = str(output_dir / "shadow_batch.json")
    write_private(summary["results_file"], summary)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-db", type=Path, default=DEFAULT_SOURCE_PATH)
    parser.add_argument("--asset-inventory")
    parser.add_argument("--history-db", default=SHADOW_HISTORY)
    parser.add_argument("--output-dir")
    parser.add_argument("--limit", type=int, default=10000)
    parser.add_argument("--evaluation-id")
    parser.add_argument("--record-run-error", help="Private JSON error from exporter/importer/report stage")
    parser.add_argument("--fresh-only", action="store_true", help="Only unseen incidents triaged within the last 24 hours")
    parser.add_argument("--as-of", help="Fixed UTC time supplied by the daily runner")
    parser.add_argument("--environment", choices=["test"], required=True)
    args = parser.parse_args(argv)
    if args.record_run_error:
        failure = json.loads(private_path(args.record_run_error).read_text(encoding="utf-8-sig"))
        response = operational_error("daily_" + failure["stage"] + "_error", failure["detail"], metadata=provenance(ForecastConfig(environment="test")))
        with ForecastHistory(private_path(args.history_db), environment="test") as history:
            history.record_attempt(shadow_metrics(response, {}, elapsed_ms=0))
        return 0
    if not args.output_dir or not args.asset_inventory or not args.evaluation_id:
        parser.error("shadow batch requires --output-dir, --asset-inventory and --evaluation-id")
    try:
        result = run_shadow_batch(args.backend_db, args.asset_inventory, output_dir=args.output_dir,
                                  history_path=args.history_db, limit=args.limit,
                                  now=parse_time(args.as_of) if args.as_of else None, evaluation_id=args.evaluation_id, fresh_only=args.fresh_only)
    except (OSError, ValueError, TypeError, sqlite3.Error) as exc:
        error = operational_error("shadow_batch_error", str(exc), metadata=provenance(ForecastConfig(environment="test")))
        # A source/copy failure has no incident/forecast. Keep it in the same
        # attempt stream so the weekly report does not silently lose run failures.
        destination = private_path(args.output_dir)
        destination.mkdir(parents=True, exist_ok=True)
        write_private(destination / ("operational_error_" + uuid.uuid4().hex + ".json"), error)
        with ForecastHistory(private_path(args.history_db), environment="test") as history:
            history.record_attempt(shadow_metrics(error, {}, elapsed_ms=0))
        print(json.dumps(error, indent=2))
        return 1
    print(json.dumps({key: value for key, value in result.items() if key != "results"}, indent=2))
    return 1 if result["status_counts"].get("operational_error") else 0


if __name__ == "__main__":
    raise SystemExit(main())

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import csv
import json
import sqlite3
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from Prognostic_Agent import ForecastConfig, build_risk_forecast
from Prognostic_Agent.contracts import AnalystAlert
from Prognostic_Agent.reporting import export_unsupported, shadow_summary
from Prognostic_Agent.service import ForecastService
from Prognostic_Agent.service import forecast_summary, shadow_metrics
from Prognostic_Agent.storage import ForecastHistory
from Prognostic_Agent.tests.test_contracts import ROOT, alert

AS_OF = "2026-11-23T12:00:00Z"


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory(prefix="test-history-", dir=ROOT)
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "history.db"

    def history(self, **kwargs):
        kwargs.setdefault("environment", "test")
        result = ForecastHistory(self.path, **kwargs)
        self.addCleanup(result.close)
        return result

    def test_migration_wal_timeout_and_privacy_defaults(self):
        history = self.history(busy_timeout_ms=1234)
        self.assertEqual(history.connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(history.connection.execute("PRAGMA busy_timeout").fetchone()[0], 1234)
        self.assertEqual(history.connection.execute("SELECT version FROM schema_migrations").fetchone()[0], 1)
        self.assertEqual(history.connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0], 2)
        request = alert()
        request["normalized_events"][0]["message"] = "RAW_EVIDENCE_MARKER"
        result = ForecastService(history).assess(request, forecast_as_of=AS_OF)
        self.assertTrue(result["history"]["persisted"])
        stored = history.connection.execute("SELECT input_json,response_json FROM forecasts").fetchone()
        self.assertNotIn("RAW_EVIDENCE_MARKER", "".join(stored))
        self.assertIn("sha256", stored[0])
        self.assertEqual(history.retention_days, 90)

    def test_full_evidence_is_explicit(self):
        history = self.history(store_full_evidence=True)
        config = ForecastConfig(store_full_evidence=True, environment="test")
        request = alert()
        request["normalized_events"][0]["message"] = "RAW_EVIDENCE_MARKER"
        ForecastService(history, config=config).assess(request, forecast_as_of=AS_OF)
        self.assertIn("RAW_EVIDENCE_MARKER", history.connection.execute("SELECT input_json FROM forecasts").fetchone()[0])

    def test_replay_is_not_recomputed_and_changed_input_creates_revision(self):
        history = self.history()
        service = ForecastService(history)
        request = alert()
        first = service.assess(request, forecast_as_of=AS_OF)
        request["request_id"] = "redelivery"
        with patch("Prognostic_Agent.service.build_risk_forecast", side_effect=AssertionError("Should use history")):
            replay = service.assess(request, forecast_as_of=AS_OF)
        self.assertEqual(first["history"]["forecast_id"], replay["history"]["forecast_id"])
        self.assertTrue(replay["history"]["idempotent_replay"])
        self.assertEqual(replay["request_id"], "redelivery")
        request["analyst_revision"] = "2"
        second = service.assess(request, forecast_as_of=AS_OF)
        self.assertEqual(second["history"]["revision"], 2)
        third = service.assess(request, forecast_as_of=AS_OF, evaluation_id="new-asset-snapshot")
        self.assertEqual(third["history"]["revision"], 3)
        self.assertEqual(shadow_summary(history)["attempt_count"], 4)

    def test_two_connections_cannot_create_duplicate_forecasts(self):
        first, second = self.history(), self.history()
        request = AnalystAlert.from_dict(alert())
        response = build_risk_forecast(request.data, forecast_as_of=AS_OF, config=ForecastConfig(environment="test"))
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(history.save, response, request.data, "same-key") for history in (first, second)]
            results = [future.result() for future in futures]
        self.assertEqual({result[0]["history"]["revision"] for result in results}, {1})
        self.assertEqual(sum(result[1] for result in results), 1)
        self.assertEqual(len(first.history(request.data["alert_id"])), 1)

    def test_retention_cascades_and_preserves_revision_counter(self):
        history = self.history()
        service = ForecastService(history)
        request = alert()
        request["observed_techniques"][0]["technique_id"] = "T1486"
        first = service.assess(request, forecast_as_of=AS_OF)
        result = history.purge(now=datetime.now(timezone.utc) + timedelta(days=91))
        self.assertEqual(result["forecasts_deleted"], 1)
        self.assertIsNone(history.get(first["history"]["forecast_id"]))
        aggregate = history.unsupported_report()["items"][0]
        self.assertEqual(aggregate["forecast_count"], 1)
        self.assertEqual(aggregate["retained_forecast_count"], 0)
        self.assertEqual(aggregate["alert_count"], 1)
        self.assertEqual(aggregate["evidence_refs"], [])
        self.assertEqual(aggregate["analyst_confidence_summary"], {"count": 1, "mean": .85})
        self.assertEqual(history.connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0], 0)
        self.assertEqual(service.assess(request, forecast_as_of=AS_OF)["history"]["revision"], 2)
        self.assertEqual(history.unsupported_report()["items"][0]["forecast_count"], 1)

    def test_read_only_database_failure_is_reported_without_claiming_persistence(self):
        history = self.history()
        # Real SQLite write rejection, independent of OS ACLs/root permissions.
        history.connection.execute("PRAGMA query_only=ON")
        result = ForecastService(history).assess(alert(), forecast_as_of=AS_OF)
        self.assertEqual(result["response_type"], "operational_error")
        self.assertIn("readonly", result["reason_detail"].lower())
        self.assertFalse(result.get("persisted", False))
        self.assertIn("attempt_log_unavailable", {item["code"] for item in result["provenance_issues"]})
        self.assertEqual(history.connection.execute("SELECT COUNT(*) FROM forecasts").fetchone()[0], 0)

    def test_reordered_keys_and_z_timestamps_replay_same_assessment(self):
        history = self.history()
        service = ForecastService(history)
        first_request = alert()
        first_request["timestamp"] = first_request["timestamp"].replace("Z", "+00:00")
        first_request["normalized_events"][0]["timestamp"] = first_request["normalized_events"][0]["timestamp"].replace("Z", "+00:00")
        first = service.assess(first_request, forecast_as_of=AS_OF)
        replay_request = json.loads(json.dumps(alert(), sort_keys=True))
        replay_request["request_id"] = "reordered-z-redelivery"
        with patch("Prognostic_Agent.service.build_risk_forecast", side_effect=AssertionError("Replay must not recompute")):
            replay = service.assess(replay_request, forecast_as_of="2026-11-23T12:00:00+00:00")
        self.assertEqual(first["input_fingerprint"], replay["input_fingerprint"])
        self.assertEqual(first["history"]["forecast_id"], replay["history"]["forecast_id"])
        self.assertEqual(replay["history"]["revision"], 1)
        self.assertTrue(replay["history"]["idempotent_replay"])
        self.assertEqual(history.connection.execute("SELECT COUNT(*) FROM forecasts").fetchone()[0], 1)

    def test_environments_isolate_replay_revision_reports_exports_and_purge(self):
        test_history, production = self.history(), self.history(environment="production")
        request = alert()
        request["observed_techniques"][0]["technique_id"] = "T1486"
        one = ForecastService(test_history).assess(request, forecast_as_of=AS_OF)
        two = ForecastService(production).assess(request, forecast_as_of=AS_OF)
        self.assertEqual((one["history"]["revision"], two["history"]["revision"]), (1, 1))
        self.assertNotEqual(one["history"]["forecast_id"], two["history"]["forecast_id"])
        self.assertEqual([item["environment"] for item in test_history.unsupported_report()["items"]], ["test"])
        self.assertEqual(len(test_history.unsupported_report(environment="all")["items"]), 2)
        self.assertEqual(shadow_summary(test_history)["attempt_count"], 1)
        self.assertEqual(shadow_summary(test_history, environment="all")["attempt_count"], 2)
        for format in ("json", "csv"):
            path = Path(self.directory.name) / ("production." + format)
            report = export_unsupported(test_history, path, format=format, environment="production")
            self.assertEqual([item["environment"] for item in report["items"]], ["production"])
            if format == "csv":
                with path.open(newline="") as stream:
                    self.assertEqual([row["environment"] for row in csv.DictReader(stream)], ["production"])
        test_history.purge(now=datetime.now(timezone.utc) + timedelta(days=91))
        self.assertIsNotNone(production.get(two["history"]["forecast_id"]))
        self.assertIsNone(test_history.get(one["history"]["forecast_id"]))
        self.assertEqual(test_history.unsupported_report()["items"][0]["forecast_count"], 1)
        for table in ("schema_migrations", "forecasts", "attempts", "unsupported", "alert_revisions", "unsupported_aggregates", "unsupported_alerts", "unsupported_assessment_keys"):
            self.assertIn("environment", {row["name"] for row in test_history.connection.execute(f"PRAGMA table_info({table})")})

    def test_v1_migration_preserves_legacy_history_and_backfills_demo_aggregates(self):
        request = alert()
        request["observed_techniques"][0]["technique_id"] = "T1486"
        response = build_risk_forecast(request, forecast_as_of=AS_OF)
        response.pop("environment")
        response["risk_score"] = 60
        with closing(sqlite3.connect(self.path)) as connection:
            for statement in (
                "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_at TEXT NOT NULL)",
                "CREATE TABLE alert_revisions(alert_id TEXT PRIMARY KEY,last_revision INTEGER NOT NULL)",
                "CREATE TABLE forecasts(forecast_id TEXT PRIMARY KEY,alert_id TEXT NOT NULL,revision INTEGER NOT NULL,idempotency_key TEXT NOT NULL UNIQUE,input_fingerprint TEXT NOT NULL,created_at TEXT NOT NULL,response_json TEXT NOT NULL,input_json TEXT NOT NULL,UNIQUE(alert_id,revision))",
                "CREATE TABLE attempts(attempt_id TEXT PRIMARY KEY,forecast_id TEXT REFERENCES forecasts(forecast_id) ON DELETE CASCADE,created_at TEXT NOT NULL,metrics_json TEXT NOT NULL)",
                "CREATE TABLE unsupported(forecast_id TEXT NOT NULL REFERENCES forecasts(forecast_id) ON DELETE CASCADE,technique_id TEXT NOT NULL,reason TEXT NOT NULL,details_json TEXT NOT NULL,PRIMARY KEY(forecast_id,technique_id,reason))",
            ):
                connection.execute(statement)
            connection.execute("INSERT INTO schema_migrations VALUES(1,?)", (AS_OF,))
            connection.execute("INSERT INTO alert_revisions VALUES(?,1)", (request["alert_id"],))
            connection.execute("INSERT INTO forecasts VALUES(?,?,?,?,?,?,?,?)", ("legacy", request["alert_id"], 1, "legacy-key", response["input_fingerprint"], AS_OF, json.dumps(response), "{}"))
            item = response["unsupported_starting_techniques"][0]
            connection.execute("INSERT INTO unsupported VALUES(?,?,?,?)", ("legacy", item["technique_id"], item["reason"], json.dumps(item)))
            connection.commit()
        history = self.history(environment="demo")
        self.assertEqual(history.get("legacy")["environment"], "demo")
        self.assertEqual(history.get("legacy")["behavioral_score_source"], "unknown")
        self.assertTrue(history.get("legacy")["risk_score_may_include_asset_impact"])
        self.assertEqual(history.unsupported_report()["items"][0]["forecast_count"], 1)
        self.assertEqual(history.connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0], 2)
        self.assertEqual(history.connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_reports_exports_and_validation_attempts(self):
        history = self.history()
        service = ForecastService(history)
        request = alert()
        request["observed_techniques"][0]["technique_id"] = "T1486"
        service.assess(request, forecast_as_of=AS_OF)
        service.assess(request, forecast_as_of=AS_OF)
        bad = deepcopy(request)
        bad["observed_techniques"][0]["technique_id"] = "invalid"
        response = service.assess(bad)
        self.assertEqual(response["response_type"], "validation_error")
        report = history.unsupported_report()["items"][0]
        self.assertEqual(report["forecast_count"], 1)
        self.assertEqual(report["alert_count"], 1)
        self.assertEqual(report["analyst_confidences"], [.85])
        for format in ("json", "csv"):
            path = Path(self.directory.name) / ("report." + format)
            export_unsupported(history, path, format=format)
            if format == "json":
                self.assertEqual(json.loads(path.read_text())["items"][0]["technique_id"], "T1486")
            else:
                with path.open(newline="") as stream:
                    self.assertEqual(next(csv.DictReader(stream))["forecast_count"], "1")
            with self.assertRaises(FileExistsError):
                export_unsupported(history, path, format=format)
        metrics = shadow_summary(history)
        self.assertEqual(metrics["attempt_count"], 3)
        self.assertEqual(metrics["invalid_technique_inputs"], 1)
        self.assertIsNone(metrics["outcome_metrics"])
        attempt = json.loads(history.connection.execute("SELECT metrics_json FROM attempts LIMIT 1").fetchone()[0])
        for key in ("versions", "stage_timings_ms", "observation_coverage", "interventions", "legacy_score_delta", "llm_enabled"):
            self.assertIn(key, attempt)

    def test_summary_writer_failure_keeps_persisted_result(self):
        history = self.history()
        def unavailable(summary):
            raise RuntimeError("Offline")
        result = ForecastService(history, summary_writer=unavailable).assess(alert(), forecast_as_of=AS_OF)
        self.assertEqual(result["delivery_issues"][0]["code"], "summary_writer_error")
        self.assertIsNotNone(history.get(result["history"]["forecast_id"]))

    def test_persistence_failure_explicitly_returns_unpersisted_computation(self):
        history = self.history()
        with patch.object(history, "save", side_effect=OSError("Disk unavailable")):
            response = ForecastService(history).assess(alert(), forecast_as_of=AS_OF)
        self.assertEqual(response["response_type"], "operational_error")
        self.assertFalse(response["persisted"])
        self.assertEqual(response["computed_result"]["response_type"], "risk_forecast")

    def test_other_application_databases_and_backend_filename_are_rejected(self):
        with self.assertRaises(ValueError):
            ForecastHistory(Path(self.directory.name) / "soc_agents.db")
        self.assertFalse((Path(self.directory.name) / "soc_agents.db").exists())
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("CREATE TABLE unrelated(value TEXT)")
        with self.assertRaises(ValueError):
            ForecastHistory(self.path)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall(), [("unrelated",)])


class ProvenanceTests(unittest.TestCase):
    def test_versions_in_all_engine_response_types_even_with_missing_artifacts(self):
        outputs = [build_risk_forecast({}), build_risk_forecast(alert(), forecast_as_of=AS_OF),
                   build_risk_forecast(alert(), config=ForecastConfig(weights_path=ROOT / "missing-weights.json"))]
        self.assertEqual({item["response_type"] for item in outputs}, {"validation_error", "risk_forecast", "operational_error"})
        for output in outputs:
            for key in ("schema_version", "agent_version", "config_version", "versions"):
                self.assertIn(key, output)
            self.assertTrue({"agent", "config", "rules", "weights"} <= set(output["versions"]))
        self.assertIsNone(outputs[2]["versions"]["weights"])
        self.assertTrue(outputs[2]["provenance_issues"])

    def test_risk_score_outputs_always_state_behavioral_source(self):
        response = build_risk_forecast(alert(), forecast_as_of=AS_OF)
        for output in (response, response["impact_assessment"], forecast_summary(response), shadow_metrics(response, alert(), elapsed_ms=0)):
            self.assertIn("risk_score", output)
            self.assertEqual(output["behavioral_score_source"], "supplied")
            self.assertIn("risk_score_may_include_asset_impact", output)

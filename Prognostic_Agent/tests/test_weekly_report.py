"""Synthetic weekly counts, DST boundaries, replay exclusion and error separation."""

from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from Prognostic_Agent.config import ForecastConfig
from Prognostic_Agent.contracts import AnalystAlert, validation_error
from Prognostic_Agent.private_paths import PRIVATE_DIR
from Prognostic_Agent.prognostic_agent import build_risk_forecast
from Prognostic_Agent.provenance import operational_error
from Prognostic_Agent.service import shadow_metrics
from Prognostic_Agent.storage import ForecastHistory
from Prognostic_Agent.tests.test_contracts import alert
from Prognostic_Agent.weekly_report import build_weekly_report, week_window
from Prognostic_Agent.shadow_batch import ShadowLedger
from Prognostic_Agent.payload_categories import LEGACY


class WeeklyWindowTests(unittest.TestCase):
    def test_dst_weeks_use_local_monday_midnight_not_fixed_168_hours(self):
        self.assertEqual(week_window("2026-03-02")["hours"], 167)
        self.assertEqual(week_window("2026-10-26")["hours"], 169)
        self.assertEqual(week_window("2026-11-23")["hours"], 168)
        with self.assertRaisesRegex(ValueError, "Monday"):
            week_window("2026-11-24")

    def test_default_is_last_completed_week_in_los_angeles(self):
        # UTC Monday before LA midnight is still Sunday locally.
        window = week_window(now=datetime(2026, 11, 23, 7, 30, tzinfo=timezone.utc))
        self.assertTrue(window["start_local"].startswith("2026-11-09"))
        window = week_window(now=datetime(2026, 11, 23, 8, tzinfo=timezone.utc))
        self.assertTrue(window["start_local"].startswith("2026-11-16"))


class WeeklyReportTests(unittest.TestCase):
    def setUp(self):
        PRIVATE_DIR.mkdir(exist_ok=True)
        self.temp = TemporaryDirectory(prefix="test-weekly-", dir=PRIVATE_DIR)
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "history.db"
        self.history = ForecastHistory(self.path, environment="test")
        self.addCleanup(self.history.close)
        self.config = ForecastConfig(environment="test")

    def save_forecast(self, key, *, status="abstained", verdict="suspicious", created="2026-11-24T00:00:00.000000Z", path=False):
        request = alert()
        request["verdict"] = verdict
        request["observed_techniques"] = [{"technique_id": "T1486", "evidence_refs": [request["normalized_events"][0]["event_id"]], "attribution": "exact"}]
        response = build_risk_forecast(request, config=self.config, forecast_as_of="2026-11-23T12:00:00Z")
        # Simulate a legacy benign/path inconsistency: reporting must surface it.
        response["status"] = status
        response["reason"] = "unsupported_transition" if status == "abstained" else "asset_context_incomplete"
        response["shadow_context"] = {"analyst_verdict": verdict, "evaluation_id": key, "assessment_key": key}
        if path:
            response["predicted_path"] = {"starting_technique": "T1078", "steps": [{"technique_id": "T1059.001"}]}
        response, replay = self.history.save(response, AnalystAlert.from_dict(request).data, key)
        self.assertFalse(replay)
        identity = response["history"]["forecast_id"]
        self.history.connection.execute("UPDATE forecasts SET created_at=? WHERE forecast_id=?", (created, identity))
        return response

    def test_counts_each_forecast_once_and_distinct_alerts_across_revisions(self):
        first = self.save_forecast("revision-1")
        self.save_forecast("revision-2")
        self.save_forecast("benign-path", status="partial", verdict="benign", path=True)
        self.save_forecast("before", created="2026-11-23T07:59:59.999999Z")
        self.save_forecast("end-exclusive", created="2026-11-30T08:00:00.000000Z")
        for _ in range(3):
            self.history.record_attempt(shadow_metrics(first, {"verdict": "suspicious"}, elapsed_ms=1, replay=True), first["history"]["forecast_id"])
        self.history.connection.execute("UPDATE attempts SET created_at='2026-11-24T00:00:00.000000Z'")
        report = build_weekly_report(self.path, week_start="2026-11-23")
        self.assertEqual(report["forecast_count"], 3)
        self.assertEqual(report["status_counts"], {"abstained": 2, "partial": 1})
        self.assertEqual(report["abstention_rate"]["numerator"], 2)
        self.assertEqual(report["abstention_rate"]["denominator"], 3)
        self.assertAlmostEqual(report["abstention_rate"]["rate"], 2 / 3)
        self.assertEqual(report["unsupported_techniques"][0]["distinct_alert_count"], 1)
        self.assertEqual(len(report["non_benign_incidents"]), 2)
        self.assertEqual(len(report["benign_with_predicted_path"]), 1)
        self.assertEqual(report["benign_with_predicted_path"][0]["path"], ["T1078", "T1059.001"])

    def test_validation_and_operational_errors_are_separate_from_forecast_denominator(self):
        self.save_forecast("one")
        error = validation_error({"alert_id": "invalid-fixture"}, [{"field": "timestamp", "code": "invalid_timestamp", "message": "Synthetic"}], metadata=None)
        error["environment"] = "test"
        error["shadow_context"] = {"analyst_verdict": "malicious"}
        self.history.record_attempt(shadow_metrics(error, {}, elapsed_ms=1))
        error = operational_error("synthetic_db_error", "Synthetic", config=self.config)
        self.history.record_attempt(shadow_metrics(error, {}, elapsed_ms=1))
        self.history.connection.execute("UPDATE attempts SET created_at='2026-11-24T00:00:00.000000Z'")
        report = build_weekly_report(self.path, week_start="2026-11-23")
        self.assertEqual(report["forecast_count"], 1)
        self.assertEqual(report["abstention_rate"]["denominator"], 1)
        self.assertEqual(report["validation_errors"]["attempt_count"], 1)
        self.assertEqual(report["operational_errors"]["attempt_count"], 1)
        self.assertEqual(len(report["non_benign_incidents"]), 2)

    def test_empty_week_has_null_rate_and_no_missing_database_is_created(self):
        report = build_weekly_report(self.path, week_start="2026-01-05")
        self.assertEqual(report["forecast_count"], 0)
        self.assertIsNone(report["abstention_rate"]["rate"])
        missing = self.path.parent / "missing.db"
        with self.assertRaises(ValueError):
            build_weekly_report(missing)
        self.assertFalse(missing.exists())

    def test_legacy_views_reclassify_old_history_without_rewriting_it(self):
        self.save_forecast("modern")
        old = self.save_forecast("legacy-forecast", verdict="benign", status="partial", path=True)
        stored_before = self.history.connection.execute("SELECT response_json FROM forecasts WHERE forecast_id=?", (old["history"]["forecast_id"],)).fetchone()[0]
        for key in ("legacy-error", "modern-error"):
            error = validation_error({"alert_id": key}, [{"field": "timestamp", "code": "invalid_timestamp", "message": "Synthetic"}])
            error["environment"] = "test"
            error["shadow_context"] = {"assessment_key": key, "analyst_verdict": "suspicious"}
            self.history.record_attempt(shadow_metrics(error, {}, elapsed_ms=0))
        self.history.connection.execute("UPDATE attempts SET created_at='2026-11-24T00:00:00.000000Z'")
        ledger = ShadowLedger(self.history)
        ledger.classify({key: ["behavioral_score", "technique_evidence"] for key in ("legacy-forecast", "legacy-error")})
        without = build_weekly_report(self.path, week_start="2026-11-23")
        with_legacy = build_weekly_report(self.path, week_start="2026-11-23", include_legacy=True)
        for report in (without, with_legacy):
            self.assertEqual(report["forecast_count"], 1)
            self.assertEqual(report["validation_errors"]["attempt_count"], 1)
            self.assertEqual(report["abstention_rate"]["denominator"], 1)
            self.assertEqual(report["legacy_payloads"]["assessment_count"], 2)
            self.assertEqual(len(report["benign_with_predicted_path"]), 1)
        self.assertNotIn(LEGACY, without["assessment_category_counts"])
        self.assertEqual(with_legacy["assessment_category_counts"][LEGACY], 2)
        self.assertEqual(with_legacy["reported_outcome_count"] - without["reported_outcome_count"], 2)
        self.assertEqual(stored_before, self.history.connection.execute("SELECT response_json FROM forecasts WHERE forecast_id=?", (old["history"]["forecast_id"],)).fetchone()[0])


if __name__ == "__main__":
    unittest.main()

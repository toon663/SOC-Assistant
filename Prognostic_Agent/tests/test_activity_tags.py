import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from Prognostic_Agent.activity_tags import classify_activity
from Prognostic_Agent.private_paths import PRIVATE_DIR
from Prognostic_Agent.storage import ForecastHistory
from Prognostic_Agent.weekly_report import build_weekly_report
from Prognostic_Agent.tests import test_weekly_report as weekly_fixture


class ActivityTagTests(unittest.TestCase):
    def test_test_data_markers_and_host_bound_windows(self):
        events = [{"event_id": "manual-example", "host": "example-host", "timestamp": "2026-11-23T12:00:01Z"}]
        window = {"environment": "test", "kind": "exporter", "window_id": "example-window", "host": "EXAMPLE-HOST", "started_at": "2026-11-23T12:00:00Z", "ended_at": "2026-11-23T12:00:02Z"}
        result = classify_activity({"events": events}, [window])
        self.assertEqual(result["tags"], ["possible_self_generated", "test_data"])
        window["kind"] = "controlled_test"
        self.assertIn("controlled_test", classify_activity({"events": events}, [window])["tags"])
        window["host"] = "different-host"
        self.assertEqual(classify_activity({"events": events}, [window])["tags"], ["test_data"])
        events[0]["event_id"] = "debug-003"
        self.assertEqual(classify_activity({"events": events}, [])["tags"], ["test_data"])

    def test_tagged_forecast_is_separate_from_rate_denominator(self):
        fixture = weekly_fixture.WeeklyReportTests(methodName="test_empty_week_has_null_rate_and_no_missing_database_is_created")
        fixture.setUp()
        try:
            fixture.save_forecast("tagged")
            fixture.save_forecast("ordinary")
            fixture.history.connection.execute("CREATE TABLE shadow_report_tags(environment TEXT,assessment_key TEXT,tags_json TEXT)")
            fixture.history.connection.execute("INSERT INTO shadow_report_tags VALUES('test','tagged',?)", (json.dumps({"tags": ["controlled_test"], "window_ids": ["synthetic"]}),))
            report = build_weekly_report(fixture.path, week_start="2026-11-23")
            self.assertEqual(report["forecast_count"], 1)
            self.assertEqual(report["abstention_rate"]["denominator"], 1)
            self.assertEqual(report["separated_activity"]["controlled_test"]["count"], 1)
        finally:
            fixture.doCleanups()

    def test_controlled_script_is_confirmation_gated_and_has_only_inert_payload(self):
        # Static inspection only: never invoke the PowerShell test script.
        text = (PRIVATE_DIR.parent / "controlled_powershell_test.ps1").read_text()
        self.assertIn('$payload = "Write-Output \'prognostic-controlled-test\'"', text)
        self.assertLess(text.index("Read-Host"), text.index("Start-Process"))
        for argument in ("-EncodedCommand", "-WindowStyle", "-ExecutionPolicy"):
            self.assertIn(argument, text)

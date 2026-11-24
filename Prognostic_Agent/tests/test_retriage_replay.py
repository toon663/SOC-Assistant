"""Synthetic retained-evidence replay; never reads the actual backend database."""

from contextlib import closing
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from Prognostic_Agent.contracts import utc_text
from Prognostic_Agent.private_paths import PRIVATE_DIR
from Prognostic_Agent.retriage_replay import copy_incidents, event_order_key, project_event, run_retriage_replay
from Prognostic_Agent.shadow_source import sha256_file
from Prognostic_Agent.tests.test_adapter import incident
from Prognostic_Agent.tests.test_import_inventory import raw_export
from Prognostic_Agent.weekly_report import build_weekly_report


class RetriageReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        PRIVATE_DIR.mkdir(exist_ok=True)
        cls.temp = TemporaryDirectory(prefix="test-retriage-", dir=PRIVATE_DIR)
        cls.root = Path(cls.temp.name)
        cls.source = cls.root / "source.db"
        cls.export = cls.root / "raw.json"
        cls.overlay = cls.root / "overlay.json"
        now = datetime.now(timezone.utc)
        raw = raw_export()
        raw["collected_at"] = utc_text(now - timedelta(minutes=5))
        export = cls.root / "raw.json"
        export.write_text(json.dumps(raw), encoding="utf-8")
        overlay = cls.root / "overlay.json"
        overlay.write_text(json.dumps({"schema_version": 1, "environment": "test", "approved_at": utc_text(now - timedelta(minutes=4)),
            "provenance": {"source": "operator"}, "hosts": [{"host_id": "host:lab-pc", "asset_criticality": "normal"}]}), encoding="utf-8")
        first = incident()
        first["incident_id"] = "original-process"
        first["events"][0].update(timestamp=utc_text(now - timedelta(minutes=3)), host="LAB-PC", user="LAB-PC\\alice",
            severity="high", source="windows-eventlog:Security", source_ip=None, destination="Microsoft-Windows-Security-Auditing",
            message="A new process has been created.\nNew Process Name: C:\\Windows\\powershell.exe\nProcess Command Line: powershell -enc TEST -ep bypass -w hidden",
            metadata={"windows_event_id": 4688, "record_id": 100, "log_name": "Security", "level_name": "Information"})
        second = deepcopy(first["events"][0])
        second.update(event_id="process-2", timestamp=utc_text(now - timedelta(minutes=1)))
        second["metadata"]["record_id"] = 101
        first["events"].append(second)
        first["alert"] = {"occurrence_count": 12}
        malware = incident()
        malware["incident_id"] = "original-malware"
        malware["events"][0].update(event_id="scan-1", timestamp=utc_text(now - timedelta(minutes=2)), host="LAB-PC",
            user="LAB-PC\\alice", severity="high", source="sentinel-malware-scanner", source_ip=None,
            event_type="malware_detected", detector_score=.7, message="SYNTHETIC_PRIVATE_EVIDENCE_MARKER",
            metadata={"sha256": "a" * 64, "log_name": "malware-scan", "windows_event_id": None, "verdict": "suspicious",
                      "file_name": "unopened-fixture.exe", "file_path": "Z:\\nonexistent\\unopened-fixture.exe", "mitre_techniques": []})
        invalid = incident()
        invalid["incident_id"] = "original-invalid"
        invalid["events"][0].update(event_id="invalid-api-1", timestamp=utc_text(now - timedelta(minutes=4)), host="LAB-PC",
            user="LAB-PC\\alice", severity="high", source="api-fixture", source_ip=42, event_type="api-fixture", metadata={})
        with closing(sqlite3.connect(cls.source)) as connection:
            connection.execute("CREATE TABLE incidents(incident_id TEXT PRIMARY KEY,detected_at TEXT,payload TEXT)")
            for item in (first, malware, invalid):
                connection.execute("INSERT INTO incidents VALUES(?,?,?)", (item["incident_id"], item["events"][0]["timestamp"], json.dumps(item)))
            connection.commit()
        cls.before = sha256_file(cls.source)
        cls.directory = cls.root / "replay"
        cls.report = run_retriage_replay(cls.source, export, overlay, output_dir=cls.directory)
        cls.results = {item["original_triage_id"]: item for item in cls.report["results"]}

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_every_source_has_one_result_and_each_event_was_retriaged_in_time_order(self):
        report = self.report
        self.assertEqual(report["incident_count"], 3)
        self.assertEqual(report["event_count"], 4)
        self.assertEqual(report["analyst_revision_count"], 4)
        self.assertEqual(len(report["comparison"]), 3)
        self.assertTrue(report["temporary_event_database_removed"])
        self.assertTrue(report["backend_database_unchanged"])
        self.assertEqual(self.before, sha256_file(self.source))
        self.assertTrue(report["protected_artifacts_unchanged"])
        self.assertEqual(self.results["original-process"]["original_occurrences"], 12)
        self.assertEqual(self.results["original-process"]["sentinel_alert"]["occurrence_count"], 2)

    def test_current_analyst_fields_attribution_and_replay_labels_are_persisted(self):
        for original_id, item in self.results.items():
            self.assertEqual(item["source"], "retriage_replay")
            self.assertEqual(item["environment"], "test")
            self.assertIn("behavioral_score", item["analyst"])
            self.assertIn("technique_evidence", item["analyst"])
            self.assertEqual(item["forecast"]["source"], "retriage_replay")
            self.assertEqual(item["forecast"]["original_triage_id"], original_id)
        process = self.results["original-process"]
        self.assertIn("T1059.001", process["analyst"]["mitre_techniques"])
        self.assertEqual(process["forecast"]["status"], "partial")
        self.assertIsNotNone(process["forecast"]["predicted_path"])

    def test_malware_reuses_recorded_static_findings_without_inventing_techniques(self):
        malware = self.results["original-malware"]
        self.assertEqual(malware["detector"]["recorded_static_scan_not_rerun"], 1)
        self.assertEqual(malware["analyst"]["verdict"], "suspicious")
        self.assertEqual(malware["analyst"]["behavioral_score"], 65)
        self.assertEqual(malware["analyst"]["mitre_techniques"], [])
        self.assertEqual(malware["forecast"]["status"], "abstained")
        self.assertIsNone(malware["forecast"]["predicted_path"])
        self.assertFalse("SYNTHETIC_PRIVATE_EVIDENCE_MARKER" in (self.directory / "retriage_replay.json").read_text(encoding="utf-8"),
                         "Raw evidence appeared despite store_full_evidence=False")

    def test_replay_forecasts_never_enter_primary_weekly_counts(self):
        from zoneinfo import ZoneInfo
        day = datetime.now(timezone.utc).astimezone(ZoneInfo("America/Los_Angeles")).date()
        report = build_weekly_report(self.report["history_database"], week_start=day - timedelta(days=day.weekday()))
        self.assertEqual(report["forecast_count"], 0)
        self.assertEqual(report["validation_errors"]["attempt_count"], 0)
        self.assertEqual(report["retriage_replay"]["forecast_count"], 2)
        self.assertEqual(report["retriage_replay"]["original_triage_count"], 3)
        self.assertEqual(report["retriage_replay"]["status_counts"]["validation_error"], 1)
        self.assertEqual(report["retriage_replay"]["reason_counts"]["validation_error"], 1)
        self.assertTrue(report["retriage_replay"]["excluded_from_primary_counts"])

    def test_raw_projection_marks_unavailable_features_unknown(self):
        raw, missing = project_event({"event_id": "api-fixture", "timestamp": "2026-11-23T00:00:00Z", "metadata": {}})
        self.assertIsNone(raw["eventId"])
        self.assertIn("keywords", missing)
        self.assertIn("eventData", missing)
        self.assertNotIn("mitre_techniques", raw)

    def test_a_validation_error_remains_a_separate_labeled_result(self):
        row = next(row for row in self.report["comparison"] if row["original_triage_id"] == "original-invalid")
        self.assertEqual((row["status"], row["reason"]), ("validation_error", "validation_error"))
        self.assertEqual(row["source"], "retriage_replay")

    def test_ordering_preserves_submicroseconds_and_normalizes_offsets(self):
        self.assertLess(event_order_key("2026-11-23T12:00:00.1234561Z"), event_order_key("2026-11-23T12:00:00.1234562Z"))
        self.assertEqual(event_order_key("2026-11-23T12:00:00.1234562Z"), event_order_key("2026-11-23T04:00:00.1234562-08:00"))

    def test_explicit_cohort_does_not_include_later_added_incidents(self):
        target = self.root / "cohort.db"
        self.assertEqual(copy_incidents(self.source, target, {"original-malware"}), 1)
        with closing(sqlite3.connect(target)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM replay_events").fetchone()[0], 1)
        with self.assertRaisesRegex(ValueError, "cohort IDs"):
            copy_incidents(self.source, self.root / "missing.db", {"not-present"})

    def test_causal_mode_uses_each_last_event_and_only_replay_asset_assumptions(self):
        report = run_retriage_replay(self.source, self.export, self.overlay, output_dir=self.root / "causal", causal=True)
        for item in report["results"]:
            expected = max(ref["timestamp"] for ref in item["evidence_references"])
            self.assertEqual(item["causal_cutoff"], expected)
            self.assertNotEqual(item["forecast"].get("reason"), "stale_evidence")
            self.assertEqual(item["forecast"]["shadow_context"]["asset_context_source"], "operator_replay")
        for path in (self.root / "causal" / "causal-inventories").glob("*.json"):
            inventory = json.loads(path.read_text())
            self.assertEqual(inventory["source"], "operator_replay")
            self.assertTrue(all(row["privilege_level"] is None for row in inventory["entities"] if row["entity_type"] == "host"))


if __name__ == "__main__":
    unittest.main()

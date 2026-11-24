"""Synthetic-only shadow source, overlay, ledger and privacy regressions."""

from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from Prognostic_Agent.config import AGENT_DIR, ForecastConfig
from Prognostic_Agent.contracts import content_hash
from Prognostic_Agent.importers.core import import_inventory
from Prognostic_Agent.operator_overlay import apply_overlay
from Prognostic_Agent.privacy_audit import audit_identities
from Prognostic_Agent.private_paths import PRIVATE_DIR, private_path
from Prognostic_Agent.provenance import operational_error
from Prognostic_Agent.payload_categories import LEGACY, missing_analyst_fields
from Prognostic_Agent.shadow_batch import run_shadow_batch
from Prognostic_Agent.shadow_source import sha256_file, snapshot_source
from Prognostic_Agent.storage import ForecastHistory
from Prognostic_Agent.tests.test_adapter import incident
from Prognostic_Agent.tests.test_import_inventory import raw_export

NOW = datetime(2026, 11, 23, 12, 2, tzinfo=timezone.utc)


class ShadowTests(unittest.TestCase):
    def setUp(self):
        PRIVATE_DIR.mkdir(exist_ok=True)
        self.temp = TemporaryDirectory(prefix="test-shadow-", dir=PRIVATE_DIR)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source.db"
        self.history = self.root / "history.db"
        self.raw = self.root / "raw.json"
        self.raw.write_text(json.dumps(raw_export()), encoding="utf-8")
        self.imported = import_inventory(self.raw, environment="test", output_root=self.root / "imports")
        self.overlay = self.root / "overlay.json"
        self.overlay.write_text(json.dumps({"schema_version": 1, "environment": "test", "approved_at": "2026-11-23T12:00:00Z",
            "provenance": {"source": "operator"}, "hosts": [{"host_id": "host:lab-pc", "asset_criticality": "normal"}]}), encoding="utf-8")
        self.effective = apply_overlay(self.imported["inventory_path"], self.overlay, self.root / "effective")

    @unittest.skipUnless(shutil.which("powershell.exe"), "Windows PowerShell launch check")
    def test_powershell_default_paths_resolve_at_launch_without_running_collection(self):
        result = subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                 "-File", str(AGENT_DIR / "daily_shadow.ps1"), "-PlanOnly"],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["environment"], "test")
        self.assertEqual(Path(plan["history_path"]).resolve(), PRIVATE_DIR / "shadow" / "forecast_history.db")
        self.assertFalse(plan["registers_scheduled_task"])

    def make_source(self, count=2, invalid=False):
        with closing(sqlite3.connect(self.source)) as connection:
            connection.execute("CREATE TABLE incidents(incident_id TEXT PRIMARY KEY,detected_at TEXT,payload TEXT)")
            for index in range(count):
                value = incident()
                value["incident_id"] = "shadow-fixture-" + str(index)
                value["risk_analysis"].update(behavioral_score=50, technique_evidence={"T1059.001": ["event-1"]})
                if invalid and index == count - 1:
                    value["risk_analysis"] = {}
                connection.execute("INSERT INTO incidents VALUES(?,?,?)", (value["incident_id"], "2026-11-23T12:00:00Z", json.dumps(value)))
            connection.commit()

    def run_batch(self, name, **kwargs):
        return run_shadow_batch(self.source, self.effective["inventory_path"], history_path=self.history,
                                output_dir=self.root / name, now=NOW, **kwargs)

    def test_overlay_only_changes_this_hosts_criticality_and_preserves_unknowns(self):
        inventory = json.loads(Path(self.effective["inventory_path"]).read_text(encoding="utf-8"))
        host = next(row for row in inventory["entities"] if row["entity_type"] == "host")
        self.assertEqual(host["asset_criticality"], "normal")
        self.assertEqual(host["as_of"], "2026-11-23T12:00:00Z")
        self.assertIsNone(host["last_updated"])
        self.assertIsNone(host["exposure"])
        self.assertNotIn("related_assets", host)
        self.assertTrue(all(row["asset_criticality"] is None for row in inventory["entities"] if row["entity_type"] == "user"))
        value = json.loads(self.overlay.read_text())
        value["hosts"][0]["host_id"] = "host:other"
        self.overlay.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "does not match"):
            apply_overlay(self.imported["inventory_path"], self.overlay, self.root / "wrong")

    def test_read_only_snapshot_includes_uncheckpointed_wal_without_touching_source(self):
        self.make_source(1)
        with closing(sqlite3.connect(self.source)) as writer:
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("INSERT INTO incidents SELECT 'new-in-wal',detected_at,payload FROM incidents")
            writer.commit()
            before = {suffix: sha256_file(str(self.source) + suffix) for suffix in ("", "-wal", "-shm")}
            snapshot = snapshot_source(self.source, self.root / "snapshot")
            self.assertEqual(before, {suffix: sha256_file(str(self.source) + suffix) for suffix in before})
            self.assertIn("wal", snapshot["source_hashes"])
            with closing(sqlite3.connect(snapshot["snapshot_path"])) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 2)
        Path(str(self.source) + "-journal").write_bytes(b"active journal")
        with self.assertRaisesRegex(ValueError, "rollback"):
            snapshot_source(self.source, self.root / "refused")

    def test_incremental_selection_does_not_starve_later_rows_and_skips_across_days(self):
        self.make_source(3, invalid=True)
        source_hash = sha256_file(self.source)
        first = self.run_batch("first", limit=1)
        self.assertEqual(first["processed_count"], 1)
        self.assertEqual(first["remaining_count"], 2)
        second = self.run_batch("second")
        self.assertEqual(second["processed_count"], 2)
        self.assertEqual(second["already_assessed_count"], 1)
        self.assertEqual(second["status_counts"][LEGACY], 1)
        self.assertNotIn("validation_error", second["status_counts"])
        third = run_shadow_batch(self.source, self.effective["inventory_path"], history_path=self.history,
                                 output_dir=self.root / "tomorrow", now=datetime(2026, 11, 24, 12, 2, tzinfo=timezone.utc))
        self.assertEqual(third["processed_count"], 0)
        self.assertEqual(third["already_assessed_count"], 3)
        self.assertNotEqual(first["evaluation_id"], third["evaluation_id"])
        self.assertIn(sha256_file(self.effective["inventory_path"]), first["evaluation_id"])
        self.assertIn("2026-11-23", first["evaluation_id"])
        self.assertEqual(source_hash, sha256_file(self.source))

    def test_changed_payload_is_reassessed_and_ledger_recovers_committed_forecasts(self):
        self.make_source(1)
        self.run_batch("first")
        with ForecastHistory(self.history, environment="test") as history:
            history.connection.execute("DELETE FROM shadow_processed")
        self.assertEqual(self.run_batch("recovered")["processed_count"], 0)
        with closing(sqlite3.connect(self.source)) as connection:
            value = json.loads(connection.execute("SELECT payload FROM incidents").fetchone()[0])
            value["risk_analysis"]["triaged_at"] = "2026-11-23T12:00:00+00:00"
            connection.execute("UPDATE incidents SET payload=?", (json.dumps(value, sort_keys=True),))
            connection.commit()
        self.assertEqual(self.run_batch("reordered-equivalent")["processed_count"], 0)
        with closing(sqlite3.connect(self.source)) as connection:
            value = json.loads(connection.execute("SELECT payload FROM incidents").fetchone()[0])
            value["risk_analysis"]["behavioral_score"] = 51
            connection.execute("UPDATE incidents SET payload=?", (json.dumps(value),))
            connection.commit()
        self.assertEqual(self.run_batch("changed")["processed_count"], 1)
        with ForecastHistory(self.history, environment="test") as history:
            history.purge(now=datetime(2028, 1, 1, tzinfo=timezone.utc))
            self.assertEqual(history.connection.execute("SELECT COUNT(*) FROM shadow_processed").fetchone()[0], 2)
        self.assertEqual(self.run_batch("after-purge")["processed_count"], 0)

    def test_operational_failures_are_retryable_and_missing_fields_are_not_backfilled(self):
        self.make_source(1)
        response = operational_error("synthetic_failure", "Synthetic failure", config=ForecastConfig(environment="test"))
        with patch("Prognostic_Agent.shadow_batch.ForecastService.assess", return_value=response):
            self.assertEqual(self.run_batch("failed")["status_counts"], {"operational_error": 1})
        self.assertEqual(self.run_batch("retry")["processed_count"], 1)
        with self.assertRaisesRegex(ValueError, "UTC run date"):
            self.run_batch("bad-evaluation", evaluation_id="wrong")

    def test_fresh_only_filters_old_triage_and_legacy_is_not_a_validation_error(self):
        self.make_source(2)
        with closing(sqlite3.connect(self.source)) as connection:
            value = json.loads(connection.execute("SELECT payload FROM incidents WHERE incident_id='shadow-fixture-1'").fetchone()[0])
            value["risk_analysis"]["triaged_at"] = "2026-11-21T12:00:00Z"
            connection.execute("UPDATE incidents SET payload=? WHERE incident_id='shadow-fixture-1'", (json.dumps(value),))
            connection.commit()
        result = self.run_batch("fresh", fresh_only=True)
        self.assertEqual(result["fresh_incident_count"], 1)
        self.assertEqual(result["processed_count"], 1)
        self.assertEqual(result["results"][0]["source_incident_id"], "shadow-fixture-0")
        self.assertEqual(missing_analyst_fields({"risk_analysis": {}}), ["behavioral_score", "technique_evidence"])
        self.assertEqual(missing_analyst_fields({"risk_analysis": {"behavioral_score": None, "technique_evidence": {}}}), [])
        self.assertEqual(missing_analyst_fields(None), [])

    def test_shadow_outputs_are_private_and_privacy_audit_detects_literal_identities(self):
        with self.assertRaisesRegex(ValueError, "private"):
            private_path(PRIVATE_DIR.parent / "forecasts" / "real.json")
        public = self.root / "public"
        (public / "examples").mkdir(parents=True)
        (public / "README.md").write_text("Synthetic examples only", encoding="utf-8")
        self.assertTrue(audit_identities(self.raw, root=public)["clean"])
        (public / "examples" / "leak.txt").write_text("LAB-PC\\alice", encoding="utf-8")
        audit = audit_identities(self.raw, root=public)
        self.assertFalse(audit["clean"])
        self.assertEqual(len(audit["matching_files"]), 1)

    def test_privacy_audit_also_covers_historical_hosts_and_qualified_users(self):
        public = self.root / "public-extended"
        public.mkdir()
        (public / "README.md").write_text("Historical-Example\\casey", encoding="utf-8")
        self.assertTrue(audit_identities(self.raw, root=public)["clean"])
        audit = audit_identities(self.raw, root=public, extra_identities=["HISTORICAL-EXAMPLE", "DOMAIN\\casey", "SYSTEM"])
        self.assertFalse(audit["clean"])
        self.assertEqual(audit["matching_files"], ["README.md"])
        ambiguous_role_word = "admin"
        (public / "README.md").write_text('privilege_level: admin; admin privileges', encoding="utf-8")
        self.assertTrue(audit_identities(self.raw, root=public, extra_identities=[ambiguous_role_word])["clean"])
        (public / "README.md").write_text(json.dumps({"user": ambiguous_role_word}), encoding="utf-8")
        self.assertFalse(audit_identities(self.raw, root=public, extra_identities=[ambiguous_role_word])["clean"])


if __name__ == "__main__":
    unittest.main()

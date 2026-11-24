from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from Prognostic_Agent.batch_replay import replay_batch, select_incidents
from Prognostic_Agent.config import ForecastConfig
from Prognostic_Agent.storage import ForecastHistory
from Prognostic_Agent.tests.test_adapter import incident
from Prognostic_Agent.tests.test_contracts import ROOT


class BatchReplayTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory(prefix="test-batch-", dir=ROOT)
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.source = self.base / "backend.db"
        self.history = self.base / "replay.db"

    def make_source(self, verdicts=("benign", "suspicious", "malicious", "unknown")):
        with closing(sqlite3.connect(self.source)) as connection:
            connection.execute("CREATE TABLE incidents(incident_id TEXT PRIMARY KEY,detected_at TEXT,payload TEXT)")
            for index, verdict in enumerate(verdicts):
                value = incident()
                value["incident_id"] = "persisted-" + str(index)
                value["events"][0]["message"] = "RAW_BATCH_EVIDENCE"
                if verdict == "unknown":
                    value["risk_analysis"] = {}
                else:
                    value["risk_analysis"]["verdict"] = verdict
                    value["risk_analysis"]["mitre_techniques"] = ["T1486" if verdict == "suspicious" else "T1059.001"]
                connection.execute("INSERT INTO incidents VALUES(?,?,?)", (value["incident_id"], f"2026-11-{23-index:02d}T12:00:00Z", json.dumps(value)))
            connection.commit()

    def test_selection_prioritizes_suspicious_and_source_is_unchanged(self):
        self.make_source(("benign", "malicious", "suspicious", "suspicious", "unknown"))
        before = hashlib.sha256(self.source.read_bytes()).hexdigest()
        selected, metadata = select_incidents(self.source, 2)
        self.assertEqual([row["analyst_verdict"] for row in selected], ["suspicious", "suspicious"])
        self.assertEqual(metadata["available_analyst_verdict_counts"]["suspicious"], 2)
        self.assertEqual(before, hashlib.sha256(self.source.read_bytes()).hexdigest())
        self.assertFalse(Path(str(self.source) + "-wal").exists())
        self.assertFalse(Path(str(self.source) + "-shm").exists())

    def test_demo_persistence_summary_export_and_idempotent_delivery(self):
        self.make_source()
        first = replay_batch(self.source, limit=20, history_path=self.history, output_dir=self.base / "results")
        self.assertEqual(first["processed_count"], 4)
        self.assertEqual(first["environment"], "demo")
        self.assertEqual(first["selected_analyst_verdict_counts"]["suspicious"], 1)
        self.assertEqual(first["status_counts"], {"abstained": 3, "validation_error": 1})
        self.assertEqual(first["top_unsupported_techniques"][0]["technique_id"], "T1486")
        self.assertEqual(first["new_forecasts"], 3)
        content = Path(first["results_file"]).read_text(encoding="utf-8")
        self.assertNotIn("RAW_BATCH_EVIDENCE", content)
        self.assertEqual(len(json.loads(content)["results"]), 4)
        second = replay_batch(self.source, limit=20, history_path=self.history)
        self.assertEqual(second["new_forecasts"], 0)
        self.assertEqual(second["replayed_forecasts"], 3)
        with ForecastHistory(self.history, environment="demo") as history:
            self.assertEqual(history.connection.execute("SELECT COUNT(*) FROM forecasts").fetchone()[0], 3)
            self.assertEqual(history.connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0], 8)
            self.assertEqual(history.connection.execute("SELECT DISTINCT environment FROM forecasts").fetchone()[0], "demo")
            self.assertNotIn("RAW_BATCH_EVIDENCE", history.connection.execute("SELECT input_json FROM forecasts LIMIT 1").fetchone()[0])

    def test_refuses_missing_source_active_wal_and_changed_snapshot(self):
        with self.assertRaises(ValueError):
            select_incidents(self.source, 20)
        self.assertFalse(self.source.exists())
        self.make_source()
        with closing(sqlite3.connect(self.source)) as writer:
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("UPDATE incidents SET detected_at='2030-01-01T00:00:00Z' WHERE incident_id='persisted-0'")
            writer.commit()
            self.assertTrue(Path(str(self.source) + "-wal").stat().st_size)
            with self.assertRaisesRegex(ValueError, "WAL"):
                replay_batch(self.source, history_path=self.history)
            self.assertFalse(self.history.exists())
        with patch("Prognostic_Agent.batch_replay._file_hash", side_effect=["before", "after"]):
            with self.assertRaisesRegex(ValueError, "changed"):
                replay_batch(self.source, history_path=self.history)
        self.assertFalse(self.history.exists())

    def test_write_scope_environment_and_limit_are_enforced(self):
        self.make_source()
        with self.assertRaises(ValueError):
            replay_batch(self.source, history_path=ROOT.parent / "outside-replay.db")
        with self.assertRaises(ValueError):
            replay_batch(self.source, history_path=self.history, config=ForecastConfig(environment="production"))
        with self.assertRaises(ValueError):
            replay_batch(self.source, history_path=self.source)
        for limit in (0, -1, True, 10001):
            with self.assertRaises(ValueError):
                select_incidents(self.source, limit)
        self.assertFalse(self.history.exists())

    def test_cli_batch_replay_prints_summary_and_writes_demo_history(self):
        self.make_source()
        result = subprocess.run([sys.executable, "-B", "-S", "-m", "Prognostic_Agent", "batch-replay", "--backend-db", str(self.source),
                                 "--history-db", str(self.history), "--limit", "2"], cwd=ROOT.parent, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["response_type"], "batch_replay_result")
        self.assertEqual(summary["processed_count"], 2)
        self.assertEqual(summary["selected_analyst_verdict_counts"], {"malicious": 1, "suspicious": 1})
        self.assertEqual(summary["environment"], "demo")


if __name__ == "__main__":
    unittest.main()

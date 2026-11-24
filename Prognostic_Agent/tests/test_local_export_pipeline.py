"""Real detector/Analyst replay with synthetic, non-private exporter data."""

import hashlib
import json
from pathlib import Path
import unittest
import uuid

from Prognostic_Agent.config import AGENT_DIR
from Prognostic_Agent.local_export_pipeline import run_local_export_pipeline
from Prognostic_Agent.synthetic_contrasts import probability_audit
from Prognostic_Agent.tests.test_import_inventory import raw_export


class LocalExportPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = AGENT_DIR / "private" / "test-runs" / "local-export" / ("verification_" + uuid.uuid4().hex)
        cls.root.mkdir(parents=True)
        source = cls.root / "raw.json"
        raw = raw_export()
        raw["errors"] = [{"section": "group:S-1-5-32-555", "message": "Lab collection failure"}]
        source.write_text(json.dumps(raw), encoding="utf-8")
        cls.source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        cls.report = run_local_export_pipeline(source, cls.root / "replay")
        cls.results = {row["incident"]: row for row in cls.report["comparison"]}

    def test_missing_control_and_network_facts_abstain_without_inventing_them(self):
        row = self.results["failed_logon"]
        self.assertEqual((row["status"], row["reason"]), ("abstained", "prerequisites_unresolved"))
        self.assertIsNone(row["path"])
        self.assertEqual(row["unresolved_guards"], ["account_authentication", "authentication_reachability"])

    def test_real_local_admin_scope_enables_local_paths_with_unknown_impact(self):
        for kind, path in (("successful_logon", ["T1078", "T1059.001"]),
                           ("process_creation", ["T1059.001", "T1003.001"])):
            with self.subTest(incident=kind):
                row = self.results[kind]
                self.assertEqual((row["status"], row["reason"]), ("partial", "asset_context_incomplete"))
                self.assertEqual(row["path"], path)
                self.assertIn("reachability_unresolved", row["unresolved_prerequisites"])
        self.assertTrue(all(row["risk_score"] is None for row in self.results.values()))

    def test_provenance_and_missing_topology_survive_replay_and_sources_are_unchanged(self):
        report = self.report
        self.assertEqual(report["environment"], "test")
        self.assertEqual(report["import"]["source_sha256"], self.source_hash)
        inventory = json.loads(Path(report["import"]["inventory_path"]).read_text(encoding="utf-8"))
        self.assertTrue(all("related_assets" not in row for row in inventory["entities"]))
        self.assertTrue(all(row["last_updated"] is None for row in inventory["entities"]))
        self.assertEqual(report["issues"]["quarantine"][0]["source_locator"], "$.errors[0]")
        self.assertTrue(report["pipeline"]["execution"]["protected_artifacts_unchanged"])
        self.assertIsNone(report["pipeline"]["execution"]["behavioral_score_override"])
        self.assertIsNone(report["pipeline"]["execution"]["technique_evidence_override"])
        self.assertTrue(probability_audit(report)["all_null"])
        self.assertEqual(self.results["successful_logon"]["guard_sources_not_evaluated"], ["T1110"])


if __name__ == "__main__":
    unittest.main()

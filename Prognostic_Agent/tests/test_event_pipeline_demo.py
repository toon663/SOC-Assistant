"""Integration smoke test; requires the existing Sentinel model and ML packages."""

import unittest
import uuid

from Prognostic_Agent.config import AGENT_DIR
from Prognostic_Agent.event_pipeline_demo import run_pipeline


class EventPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = AGENT_DIR / "private" / "test-runs" / "event-pipeline" / ("verification_" + uuid.uuid4().hex)
        cls.report = run_pipeline(cls.directory)
        cls.results = {item["event_type"]: item for item in cls.report["results"]}
        print("\nVerified full pipeline output: " + str(cls.directory / "pipeline_output.json"))

    def test_existing_detector_emits_all_seven_events_into_three_incidents(self):
        report = self.report
        self.assertEqual(report["input_document"]["eventCount"], 7)
        self.assertEqual(len(report["sentinel_anomalies"]), 7)
        self.assertEqual(len(report["normalized_events"]), 7)
        self.assertEqual(report["routine_process_launches_filtered"], [])
        self.assertEqual(set(self.results), {"failed_logon", "successful_logon", "process_creation"})
        self.assertTrue(report["execution"]["model_loaded_existing"])
        self.assertTrue(report["execution"]["protected_artifacts_unchanged"])

    def test_real_analyst_emits_command_and_correlated_logon_techniques(self):
        expected = {"failed_logon": {"T1110.001", "T1078"},
                    "successful_logon": {"T1110", "T1078"},
                    "process_creation": {"T1059.001", "T1027", "T1564.003"}}
        for kind, techniques in expected.items():
            with self.subTest(event_type=kind):
                item = self.results[kind]
                self.assertEqual(set(item["analyst_technique_ids"]), techniques)
                self.assertEqual(item["analyst_incident"]["risk_analysis"]["verdict"], "malicious")
        findings = self.results["process_creation"]["analyst_incident"]["risk_analysis"]["findings"]
        self.assertTrue(any("Write-Output 'synthetic-only'" in item["text"] for item in findings))

    def test_adapter_consumes_new_fields_and_keeps_unavailable_related_refs_coarse(self):
        for kind, item in self.results.items():
            with self.subTest(event_type=kind):
                request = item["adapter_request"]
                codes = {issue["code"] for issue in item["adapter_issues"]}
                expected_score = 80 if kind == "failed_logon" else 85
                self.assertEqual(request["triage_score"], expected_score)
                self.assertEqual(request["behavioral_score_source"], "supplied")
                self.assertNotIn("behavioral_score_missing", codes)
                self.assertEqual("coarse_technique_attribution" in codes, kind != "process_creation")
                self.assertEqual("related_evidence_not_supplied" in codes, kind != "process_creation")
                for technique in request["observed_techniques"]:
                    unavailable = (kind == "failed_logon" and technique["technique_id"] == "T1078") or (
                        kind == "successful_logon" and technique["technique_id"] == "T1110")
                    self.assertEqual(technique["attribution"], "coarse" if unavailable else "exact")
                    self.assertEqual(bool(technique["evidence_refs"]), not unavailable)
                self.assertEqual(request["adapter_metadata"]["behavioral_score_provenance"], "analyst.behavioral_score")
                self.assertEqual(request["adapter_metadata"]["technique_evidence_provenance"], "analyst.technique_evidence")

    def test_available_attribution_enables_paths_and_retains_honest_coverage_gaps(self):
        for kind, item in self.results.items():
            with self.subTest(event_type=kind):
                forecast = item["forecast"]
                self.assertEqual(forecast["response_type"], "risk_forecast")
                self.assertEqual(forecast["environment"], "test")
                expected = ("abstained", "unsupported_transition") if kind == "failed_logon" else ("partial", "candidate_coverage_incomplete")
                self.assertEqual((forecast["status"], forecast["reason"]), expected)
                self.assertEqual(forecast["asset_context"]["issues"], [])
                self.assertEqual(forecast["asset_context"]["fresh_field_coverage"], 1)
                self.assertEqual(forecast["impact_assessment"]["technical_impact_score"], 75)
                self.assertEqual(forecast["risk_score"], 78 if kind == "failed_logon" else 81)
                if kind == "failed_logon":
                    self.assertIsNone(forecast["predicted_path"])
                    self.assertIsNone(forecast["likelihood"])
                else:
                    self.assertIsNotNone(forecast["predicted_path"])
                    self.assertIsNone(forecast["likelihood"]["probability"])
        self.assertTrue((self.directory / "input_events.json").is_file())
        self.assertTrue((self.directory / "pipeline_output.json").is_file())


if __name__ == "__main__":
    unittest.main()

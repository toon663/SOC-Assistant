"""Opt-in guarded rule plus causal pipeline regressions against the local model."""

import unittest
import uuid

from Prognostic_Agent.config import AGENT_DIR, ForecastConfig
from Prognostic_Agent.contracts import parse_time
from Prognostic_Agent.lab_pipeline_demo import LAB_RULES, run_lab, verify_expected_failure_scope
from Prognostic_Agent.synthetic_contrasts import probability_audit
from Prognostic_Agent.transition_rules import load_rules, matching_rules


class LabArtifactTests(unittest.TestCase):
    def test_historical_scope_is_preserved_without_freezing_backend_decorators(self):
        result = verify_expected_failure_scope()
        self.assertEqual(result["historical_methods_count"], 8)
        self.assertTrue(result["all_original_methods_present"])
        self.assertEqual(result["exact_match"], result["decorators_match_historical_snapshot"])
        self.assertEqual(result["count"], len(result["methods"]))

    def test_opt_in_rules_preserve_defaults_and_restrict_the_new_edge(self):
        original = load_rules(ForecastConfig().rules_path)
        guarded = load_rules(LAB_RULES)
        self.assertEqual(len(original["rules"]), 3)
        self.assertEqual(guarded["schema_version"], 2)
        self.assertEqual(guarded["rules"][1:], original["rules"])
        edge = guarded["rules"][0]
        self.assertEqual((edge["source"], edge["target"]), ("T1110", "T1078"))
        self.assertTrue(edge["terminal"])
        self.assertEqual(len(edge["guards"]), 6)
        self.assertTrue(matching_rules("T1110.001", [edge]))
        self.assertFalse(matching_rules("T1110.002", [edge]))


class LabPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = AGENT_DIR / "private" / "test-runs" / "lab-pipeline" / ("verification_" + uuid.uuid4().hex)
        cls.report = run_lab(cls.directory)
        cls.results = {item["incident"]: item for item in cls.report["results"]}
        print("\nFull lab pipeline output: " + str(cls.directory / "lab_results.json"))

    def test_three_baselines_have_supported_paths_and_actual_analyst_scores(self):
        expected = {"failed_logon": ("complete", "assessment_complete", 50, 60, "T1110.001", "T1078"),
                    "successful_logon": ("partial", "candidate_coverage_incomplete", 85, 81, "T1078", "T1059.001"),
                    "process_creation": ("partial", "candidate_coverage_incomplete", 85, 81, "T1059.001", "T1003.001")}
        self.assertEqual(set(self.results), set(expected))
        for kind, (status, reason, behavioral, risk, source, target) in expected.items():
            item = self.results[kind]["baseline"]
            forecast = item["forecast"]
            self.assertEqual((forecast["status"], forecast["reason"]), (status, reason))
            self.assertEqual(forecast["risk_score"], risk)
            self.assertEqual(item["adapter_request"]["triage_score"], behavioral)
            self.assertEqual(forecast["predicted_path"]["starting_technique"], source)
            self.assertEqual(forecast["predicted_path"]["steps"][0]["technique_id"], target)
            self.assertEqual(forecast["environment"], "test")
            self.assertEqual(forecast["versions"]["rules"], "phase2.1-auth")
        failed = self.results["failed_logon"]["baseline"]
        self.assertEqual(failed["analyst_technique_ids"], ["T1110.001"])
        self.assertEqual(failed["adapter_request"]["adapter_issues"], [])
        self.assertTrue(all(item["status"] == "pass" for item in failed["forecast"]["predicted_path"]["steps"][0]["guard_evaluations"]))
        self.assertTrue(all(len(path["steps"]) == 1 for path in failed["forecast"]["candidate_paths"]))

    def test_one_fact_removals_have_expected_status_and_radius_degradation(self):
        failed = self.results["failed_logon"]["variant_forecast"]
        self.assertEqual((failed["status"], failed["reason"]), ("abstained", "prerequisites_unresolved"))
        self.assertEqual(failed["risk_score"], 60)
        self.assertEqual(failed["risk_score_basis"], "impact_assessment_only")
        self.assertTrue(any("guard_authentication_reachability_unresolved" in row["reasons"] for row in failed["diagnostics"]["rejected_transitions"]))
        success = self.results["successful_logon"]["variant_forecast"]
        self.assertEqual((success["status"], success["reason"]), ("partial", "asset_context_incomplete"))
        powershell = self.results["process_creation"]["variant_forecast"]
        self.assertEqual((powershell["status"], powershell["reason"]), ("partial", "candidate_coverage_incomplete"))
        self.assertEqual(powershell["blast_radius"]["unknown_relationship_entities"], ["host:fixture-workstation"])
        self.assertAlmostEqual(self.results["process_creation"]["baseline"]["forecast"]["likelihood"]["index"] - powershell["likelihood"]["index"], .15)
        for kind in ("successful_logon", "process_creation"):
            baseline, variant = self.results[kind]["baseline"]["forecast"], self.results[kind]["variant_forecast"]
            self.assertEqual(baseline["blast_radius"]["potential_count"], 1)
            self.assertEqual(variant["blast_radius"]["potential_count"], 0)
            self.assertEqual(variant["risk_score"], 81)

    def test_replay_is_causal_and_manual_evidence_is_separate_from_analyst_output(self):
        for item in self.results.values():
            baseline = item["baseline"]
            cutoff = parse_time(baseline["forecast"]["forecast_as_of"])
            self.assertTrue(all(parse_time(event["timestamp"]) <= cutoff for event in baseline["adapter_request"]["normalized_events"]))
            self.assertEqual(len(baseline["adapter_input_incident"]["events"]), len(baseline["analyst_incident"]["events"]) + 1)
            self.assertNotIn("guard_context", baseline["analyst_incident"]["risk_analysis"])
            self.assertEqual(baseline["forecast"]["blast_radius"]["observed_count"], 2)
        pipeline = self.report["pipeline"]
        self.assertTrue(pipeline["execution"]["causal_replay"])
        self.assertIsNone(pipeline["execution"]["behavioral_score_override"])
        self.assertIsNone(pipeline["execution"]["technique_evidence_override"])
        self.assertTrue(self.report["protected_artifacts_unchanged"])

    def test_batch_control_rejects_already_observed_target_and_probabilities_stay_null(self):
        batch = self.report["batch_control"]
        self.assertIn("T1078", batch["analyst_incident"]["risk_analysis"]["mitre_techniques"])
        self.assertEqual((batch["forecast"]["status"], batch["forecast"]["reason"]), ("abstained", "prerequisites_failed"))
        self.assertEqual(batch["forecast"]["risk_score"], 78)
        self.assertTrue(any("guard_target_not_observed_failed" in row["reasons"] for row in batch["forecast"]["diagnostics"]["rejected_transitions"]))
        audit = probability_audit(self.report)
        self.assertTrue(audit["all_null"])
        self.assertGreater(audit["fields_checked"], 0)

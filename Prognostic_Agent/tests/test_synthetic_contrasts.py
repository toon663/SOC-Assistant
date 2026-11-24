import unittest

from Prognostic_Agent.synthetic_contrasts import prepare_variant, run_contrasts


class SyntheticContrastTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_contrasts()
        cls.results = cls.report["responses"]

    def index(self, name):
        return (self.results[name].get("likelihood") or {}).get("index")

    def test_expected_statuses_and_reasons(self):
        expected = {
            "baseline": ("complete", "assessment_complete"),
            "user_level_privilege": ("complete", "assessment_complete"),
            "aged_evidence_12h": ("complete", "assessment_complete"),
            "no_reachability": ("complete", "assessment_complete"),
            "lower_behavioral_score": ("complete", "assessment_complete"),
            "stale_asset_record": ("partial", "asset_context_incomplete"),
            "expired_evidence_25h": ("abstained", "stale_evidence"),
            "coarse_attribution": ("abstained", "insufficient_evidence"),
        }
        self.assertEqual(set(self.results), set(expected))
        for name, (status, reason) in expected.items():
            with self.subTest(variant=name):
                self.assertEqual((self.results[name]["status"], self.results[name]["reason"]), (status, reason))
                self.assertEqual(self.results[name]["environment"], "test")

    def test_user_privilege_filters_credential_candidates_not_all_candidates(self):
        baseline = self.results["baseline"]
        result = self.results["user_level_privilege"]
        self.assertLess(self.index("user_level_privilege"), self.index("baseline"))
        self.assertEqual(result["predicted_path"]["starting_technique"], "T1078")
        self.assertFalse(any(step["technique_id"] == "T1003.001" for path in result["candidate_paths"] for step in path["steps"]))
        # The surviving path itself is NOT continuously penalized for privilege;
        # it clears the user gate and keeps its older-login baseline index.
        selected = result["predicted_path"]
        matching = next(path for path in baseline["candidate_paths"] if path["candidate_id"] == selected["candidate_id"])
        self.assertEqual(selected["likelihood_index"], matching["likelihood_index"])

    def test_aging_within_window_lowers_index_but_expiry_removes_likelihood(self):
        self.assertAlmostEqual(self.index("baseline") - self.index("aged_evidence_12h"), .025, places=6)
        self.assertEqual(self.results["aged_evidence_12h"]["risk_score"], 72)
        self.assertIsNone(self.index("expired_evidence_25h"))
        self.assertIsNone(self.results["expired_evidence_25h"]["predicted_path"])
        self.assertEqual(self.results["expired_evidence_25h"]["risk_score"], 72)

    def test_blocked_reachability_lowers_index_and_removes_remote_candidates(self):
        result = self.results["no_reachability"]
        self.assertAlmostEqual(self.index("baseline") - self.index("no_reachability"), .15, places=6)
        self.assertFalse(any(step["technique_id"] == "T1021.002" for path in result["candidate_paths"] for step in path["steps"]))
        self.assertEqual(result["blast_radius"]["potential_count"], 0)
        self.assertEqual(result["predicted_path"]["starting_technique"], "T1059.001")

    def test_behavioral_score_changes_impact_not_path_likelihood(self):
        result = self.results["lower_behavioral_score"]
        self.assertEqual(self.index("lower_behavioral_score"), self.index("baseline"))
        self.assertEqual(result["risk_score"], 42)
        self.assertLess(result["risk_score"], self.results["baseline"]["risk_score"])
        self.assertEqual(result["analyst_confidence"], self.results["baseline"]["analyst_confidence"])

    def test_stale_privilege_context_causes_partial_and_loses_admin_paths(self):
        result = self.results["stale_asset_record"]
        self.assertLess(self.index("stale_asset_record"), self.index("baseline"))
        self.assertEqual(result["predicted_path"]["starting_technique"], "T1078")
        self.assertEqual(result["risk_score"], 72)
        self.assertTrue(any(issue["code"] == "asset_context_stale" for issue in result["issues"]))
        self.assertLess(result["confidence"]["value"], self.results["baseline"]["confidence"]["value"])

    def test_probabilities_are_null_and_omitted_attribution_is_coarse(self):
        self.assertTrue(self.report["probability_audit"]["all_null"])
        self.assertGreaterEqual(self.report["probability_audit"]["fields_checked"], 6)
        request, _, _ = prepare_variant("coarse_attribution")
        self.assertTrue(all(item["attribution"] == "coarse" and item["evidence_refs"] == [] for item in request["observed_techniques"]))
        self.assertTrue(any(issue["code"] == "coarse_technique_attribution" for issue in self.results["coarse_attribution"]["issues"]))
        self.assertIsNone(self.results["coarse_attribution"]["likelihood"])

    def test_risk_contributions_and_selected_vs_three_step_ranking(self):
        explanation = self.report["baseline_explanation"]
        self.assertTrue(explanation["available"])
        self.assertEqual(explanation["risk_assessment"]["contributions"], {"analyst_behavior": 42, "technical_impact": 30})
        self.assertEqual(explanation["risk_assessment"]["risk_score"], 72)
        self.assertGreater(explanation["selected"]["index"], explanation["three_step"]["index"])
        self.assertEqual(explanation["selected"]["future_steps"], 1)
        self.assertEqual(explanation["three_step"]["future_steps"], 3)
        self.assertIn(2, explanation["equal_index_alternative_future_steps"])


if __name__ == "__main__":
    unittest.main()

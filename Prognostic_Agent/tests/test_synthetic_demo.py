import json
import unittest

from Prognostic_Agent.analyst_adapter import adapt_analyst_incident
from Prognostic_Agent.synthetic_demo import FIXTURE_DIR, run_fixture


class SyntheticFixtureTests(unittest.TestCase):
    def test_adapter_inventory_forecast_is_non_null_and_exercises_rules_one_and_two(self):
        response = run_fixture()
        self.assertEqual(response["response_type"], "risk_forecast")
        self.assertEqual(response["environment"], "test")
        self.assertIn(response["status"], {"complete", "partial"})
        self.assertIsNotNone(response["predicted_path"])
        self.assertEqual(response["predicted_path"]["starting_technique"], "T1059.001")
        self.assertEqual(response["predicted_path"]["steps"][0]["technique_id"], "T1003.001")
        sequences = [[step["rule_id"] for step in path["steps"]] for path in response["candidate_paths"]]
        self.assertTrue(any(sequence[:2] == ["valid-account-to-powershell", "powershell-to-lsass-access"] for sequence in sequences))
        self.assertEqual(response["behavioral_score_source"], "supplied")
        self.assertEqual(response["risk_score"], 72)
        self.assertEqual(response["impact_assessment"]["factor_contributions"]["analyst_behavior"], 42)
        self.assertEqual(response["explanation_status"], "deterministic")
        self.assertEqual(response["blast_radius"]["potential_count"], 1)
        self.assertIsNone(response["likelihood"]["probability"])
        self.assertNotIn("history", response)

    def test_fixture_attribution_is_explicit_and_separate_score_excludes_bonus(self):
        with (FIXTURE_DIR / "incident.json").open(encoding="utf-8") as stream:
            incident = json.load(stream)
        with (FIXTURE_DIR / "settings.json").open(encoding="utf-8") as stream:
            settings = json.load(stream)
        request = adapt_analyst_incident(incident, behavioral_score=settings["behavioral_score"], technique_evidence=settings["technique_evidence"])
        self.assertEqual(incident["risk_analysis"]["risk_score"], 80)
        self.assertEqual(request["triage_score"], 70)
        self.assertEqual(request["adapter_issues"], [])
        self.assertTrue(all(item["attribution"] == "exact" for item in request["observed_techniques"]))
        self.assertEqual({item["technique_id"]: item["evidence_refs"] for item in request["observed_techniques"]}, settings["technique_evidence"])


if __name__ == "__main__":
    unittest.main()

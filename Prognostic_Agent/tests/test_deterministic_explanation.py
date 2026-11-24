"""Independent template-only caveat change; no integration or provider calls."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from Prognostic_Agent.contracts import canonical_json
from Prognostic_Agent.prognostic_agent import DETERMINISTIC_CAVEATS, REASONS, _explain, build_risk_forecast
from Prognostic_Agent.tests import test_forecasting as fixture


def legacy_explain(paths, reason):
    if reason:
        return {"summary": REASONS[reason], "candidate_explanations": []}
    return {"summary": "Eligible paths are conditional hypotheses. Likelihood indices are heuristic rankings, not probabilities or evidence of future compromise.",
            "candidate_explanations": [
                {"candidate_id": p["candidate_id"], "evidence_refs": p["evidence_refs"],
                 "text": " Starting from " + p["starting_technique"] + ": " + " ".join(s["rationale"] for s in p["steps"]),
                 "assumptions": sorted({a for s in p["steps"] for a in s["assumptions"]})} for p in paths]}


class DeterministicExplanationTests(unittest.TestCase):
    def test_candidate_and_summary_have_all_standard_caveats(self):
        path = {"candidate_id": "fixture-candidate", "starting_technique": "T1059.001", "evidence_refs": ["fixture-event"],
                "steps": [{"rationale": "Existing rule rationale.", "assumptions": []}]}
        result = _explain([path], None)
        for caveat in DETERMINISTIC_CAVEATS:
            self.assertIn(caveat, result["summary"])
            self.assertIn(caveat, result["candidate_explanations"][0]["text"])

    def test_abstention_has_caveats_without_inventing_candidates(self):
        result = _explain([], "stale_evidence")
        self.assertEqual(result["candidate_explanations"], [])
        self.assertTrue(result["summary"].startswith(REASONS["stale_evidence"]))
        for caveat in DETERMINISTIC_CAVEATS:
            self.assertIn(caveat, result["summary"])

    def test_template_change_preserves_every_non_explanation_assessment_field(self):
        reference = fixture.run()
        with patch("Prognostic_Agent.prognostic_agent.enrich_asset_context", return_value=deepcopy(reference["asset_context"])), \
             patch("Prognostic_Agent.prognostic_agent.perf_counter", return_value=1.0):
            with patch("Prognostic_Agent.prognostic_agent._explain", side_effect=legacy_explain):
                before = build_risk_forecast(fixture.alert(), forecast_as_of=fixture.AS_OF)
            after = build_risk_forecast(fixture.alert(), forecast_as_of=fixture.AS_OF)
        exclude = {"explanation", "generated_at"}
        self.assertEqual(canonical_json({k:v for k,v in before.items() if k not in exclude}),
                         canonical_json({k:v for k,v in after.items() if k not in exclude}))
        self.assertEqual(after["explanation_status"], "deterministic")

"""Exercise the deterministic review merger only; never instantiate an LLM."""

from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))
from llm_analyst import apply_review

from Prognostic_Agent.analyst_adapter import adapt_analyst_incident
from Prognostic_Agent.contracts import AnalystAlert
from Prognostic_Agent.tests.test_adapter import incident


def analysis():
    value = incident()["risk_analysis"]
    value.update(behavioral_score=25, risk_score=35, rule="process_creation",
                 rule_verdict="suspicious", recommended_actions=[],
                 technique_evidence={"T1059.001": ["event-1"]})
    return value


def review(verdict="malicious", status="done"):
    return {"status": status, "verdict": verdict, "summary": "Offline regression check",
            "reasoning": "Synthetic review, no API call", "confidence": "high",
            "mitre_techniques": [], "recommended_actions": []}


class ReviewScoreTests(unittest.TestCase):
    def test_changed_total_invalidates_score_without_recomputation(self):
        for original_score in (25, None):
            with self.subTest(original_score=original_score):
                value = analysis()
                value["behavioral_score"] = original_score
                apply_review(value, review())
                self.assertEqual(value["risk_score"], 70)
                self.assertIsNone(value["behavioral_score"])
                self.assertIs(value["behavioral_score_stale"], True)
                payload = incident()
                payload["risk_analysis"] = value
                request = adapt_analyst_incident(payload)
                self.assertIsNone(request["triage_score"])
                self.assertEqual(request["behavioral_score_source"], "unknown")
                self.assertIn("behavioral_score_stale", {issue["code"] for issue in request["adapter_issues"]})
                AnalystAlert.from_dict(request)

    def test_unchanged_total_preserves_known_score(self):
        for mode in ("agreed", "pending", "disagreed", "changed_verdict_same_total"):
            with self.subTest(mode=mode):
                value = analysis()
                update = review()
                if mode == "agreed":
                    update = review("suspicious")
                elif mode == "pending":
                    update = review(status="pending")
                elif mode == "disagreed":
                    update = review("benign")
                else:
                    value["risk_score"] = 90
                before = deepcopy(value)
                apply_review(value, update)
                self.assertEqual(value["risk_score"], before["risk_score"])
                self.assertEqual(value["behavioral_score"], 25)
                self.assertNotIn("behavioral_score_stale", value)

    def test_stale_score_is_not_restored_by_later_reviews_or_overrides(self):
        value = analysis()
        apply_review(value, review())
        apply_review(value, review())
        self.assertIsNone(value["behavioral_score"])
        self.assertIs(value["behavioral_score_stale"], True)
        payload = incident()
        payload["risk_analysis"] = value
        # A stale marker also wins over an accidentally retained numeric value.
        payload["risk_analysis"]["behavioral_score"] = 95
        request = adapt_analyst_incident(payload, behavioral_score=50)
        self.assertIsNone(request["triage_score"])
        self.assertEqual(request["behavioral_score_source"], "unknown")
        self.assertEqual(request["adapter_metadata"]["behavioral_score_provenance"], "stale_after_review")
        self.assertIs(request["adapter_metadata"]["behavioral_score_stale"], True)
        AnalystAlert.from_dict(request)

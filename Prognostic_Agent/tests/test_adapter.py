from copy import deepcopy
import unittest

from Prognostic_Agent.analyst_adapter import adapt_analyst_incident
from Prognostic_Agent.contracts import AnalystAlert
from Prognostic_Agent import build_risk_forecast


def incident():
    return {"incident_id": "analyst-1", "anomaly_score": 70,
            "events": [{"event_id": "event-1", "timestamp": "2026-11-23T11:55:00Z", "event_type": "process_creation",
                        "user": "ALICE", "host": "HOST-01", "message": "Example", "metadata": {}}],
            "risk_analysis": {"triaged_at": "2026-11-23T12:00:00Z", "risk_score": 60,
                              "confidence": .65, "verdict": "suspicious", "mitre_techniques": ["T1059.001"],
                              "findings": [{"points": 50, "text": "Behavior"}, {"points": 10, "text": "High-criticality asset"}],
                              "correlations": []}}


class AdapterTests(unittest.TestCase):
    def test_no_invented_score_or_event_attribution(self):
        original = incident()
        before = deepcopy(original)
        request = adapt_analyst_incident(original)
        self.assertEqual(original, before)
        self.assertEqual(request["alert_id"], "analyst-1")
        self.assertTrue(request["analyst_revision"].startswith("triage:2026-11-23T12:00:00Z:"))
        self.assertIsNone(request["triage_score"])
        self.assertEqual(request["behavioral_score_source"], "unknown")
        self.assertEqual(request["observed_techniques"], [{"technique_id": "T1059.001", "attribution": "coarse", "evidence_refs": []}])
        self.assertEqual(request["user_id"], "user:alice")
        self.assertEqual(request["host_id"], "host:host-01")
        AnalystAlert.from_dict(request)
        response = build_risk_forecast(request, forecast_as_of="2026-11-23T12:00:00Z")
        self.assertEqual(response["status"], "abstained")
        self.assertIsNone(response["risk_score"])
        self.assertIn("behavioral_score_missing", {issue["code"] for issue in response["issues"]})

    def test_explicit_behavioral_score_and_attribution_are_preserved(self):
        request = adapt_analyst_incident(incident(), behavioral_score=50, technique_evidence={"T1059.001": ["event-1"]})
        self.assertEqual(request["triage_score"], 50)
        self.assertEqual(request["behavioral_score_source"], "supplied")
        self.assertEqual(request["observed_techniques"][0]["attribution"], "exact")
        self.assertEqual(request["observed_techniques"][0]["evidence_refs"], ["event-1"])
        AnalystAlert.from_dict(request)

    def test_structured_analyst_fields_are_consumed_without_overrides(self):
        value = incident()
        value["risk_analysis"].update(behavioral_score=50, technique_evidence={"T1059.001": ["event-1"]})
        original = deepcopy(value)
        request = adapt_analyst_incident(value)
        self.assertEqual(value, original)
        self.assertEqual(request["triage_score"], 50)
        self.assertEqual(request["adapter_metadata"]["behavioral_score_provenance"], "analyst.behavioral_score")
        self.assertEqual(request["adapter_metadata"]["technique_evidence_provenance"], "analyst.technique_evidence")
        self.assertEqual(request["observed_techniques"], [{"technique_id": "T1059.001", "attribution": "exact", "evidence_refs": ["event-1"]}])
        self.assertEqual(request["adapter_issues"], [])
        AnalystAlert.from_dict(request)

    def test_explicit_overrides_take_precedence_and_zero_is_a_supplied_score(self):
        value = incident()
        value["risk_analysis"].update(behavioral_score=50, technique_evidence={"T1059.001": ["missing-event"]})
        request = adapt_analyst_incident(value, behavioral_score=0, technique_evidence={"T1059.001": ["event-1"]})
        self.assertEqual(request["triage_score"], 0)
        self.assertEqual(request["behavioral_score_source"], "supplied")
        self.assertEqual(request["adapter_metadata"]["behavioral_score_provenance"], "explicit_argument")
        self.assertEqual(request["adapter_metadata"]["technique_evidence_provenance"], "explicit_argument")
        self.assertEqual(request["adapter_issues"], [])

    def test_new_attribution_with_unavailable_related_events_stays_coarse(self):
        value = incident()
        value["risk_analysis"].update(behavioral_score=50, technique_evidence={"T1059.001": ["event-1", "related-event"]})
        request = adapt_analyst_incident(value)
        self.assertEqual(request["observed_techniques"][0], {"technique_id": "T1059.001", "attribution": "coarse", "evidence_refs": []})
        issue = next(item for item in request["adapter_issues"] if item["code"] == "coarse_technique_attribution")
        self.assertEqual(issue["unavailable_event_refs"], ["related-event"])
        self.assertNotIn("behavioral_score_missing", {item["code"] for item in request["adapter_issues"]})

    def test_stale_or_malformed_marker_prevents_score_reuse(self):
        for marker in (True, None, "true", 0):
            with self.subTest(marker=marker):
                value = incident()
                value["risk_analysis"].update(behavioral_score=50, behavioral_score_stale=marker)
                request = adapt_analyst_incident(value, behavioral_score=70)
                self.assertIsNone(request["triage_score"])
                self.assertEqual(request["behavioral_score_source"], "unknown")
                self.assertIn("behavioral_score_stale", {item["code"] for item in request["adapter_issues"]})
                AnalystAlert.from_dict(request)

    def test_explicit_false_stale_marker_preserves_valid_structured_score(self):
        value = incident()
        value["risk_analysis"].update(behavioral_score=50, behavioral_score_stale=False)
        request = adapt_analyst_incident(value)
        self.assertEqual(request["triage_score"], 50)
        self.assertEqual(request["behavioral_score_source"], "supplied")

    def test_revision_tracks_review_changes_and_missing_references_are_coarse(self):
        first = incident()
        second = deepcopy(first)
        second["risk_analysis"]["confidence"] = .85
        self.assertNotEqual(adapt_analyst_incident(first)["analyst_revision"], adapt_analyst_incident(second)["analyst_revision"])
        request = adapt_analyst_incident(first, technique_evidence={"T1059.001": ["unseen-event"]})
        self.assertEqual(request["observed_techniques"][0]["evidence_refs"], [])

    def test_missing_triage_time_is_reported_and_fails_request_validation(self):
        value = incident()
        del value["risk_analysis"]["triaged_at"]
        request = adapt_analyst_incident(value)
        self.assertIn("analyst_triaged_at_missing_or_invalid", {issue["code"] for issue in request["adapter_issues"]})
        self.assertEqual(build_risk_forecast(request)["response_type"], "validation_error")

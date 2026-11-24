from copy import deepcopy
import json
from pathlib import Path
import unittest

from Prognostic_Agent import build_risk_forecast
from Prognostic_Agent.contracts import AnalystAlert

ROOT = Path(__file__).resolve().parents[1]


def alert():
    return json.loads((ROOT / "examples" / "analyst_alert.json").read_text(encoding="utf-8"))


class ContractTests(unittest.TestCase):
    def test_canonical_identity_ignores_transport_order_and_timezone_spelling(self):
        original = alert()
        other = deepcopy(original)
        other["request_id"] = "redelivery"
        other["entities"].reverse()
        other["normalized_events"][0]["entity_ids"].reverse()
        other["timestamp"] = "2026-11-23T04:00:00-08:00"
        other["anomaly_score"] = 82.0
        self.assertEqual(AnalystAlert.from_dict(original).input_fingerprint, AnalystAlert.from_dict(other).input_fingerprint)
        other["normalized_events"][0]["message"] += " Changed evidence."
        self.assertNotEqual(AnalystAlert.from_dict(original).input_fingerprint, AnalystAlert.from_dict(other).input_fingerprint)

    def test_validation_envelope_has_no_forecast_status_or_scores(self):
        request = alert()
        request["timestamp"] = "2026-11-23T12:00:00"
        request["normalized_events"][0]["entity_ids"] = ["unknown"]
        response = build_risk_forecast(request)
        self.assertEqual(response["response_type"], "validation_error")
        self.assertNotIn("status", response)
        self.assertNotIn("risk_score", response)
        self.assertEqual({item["code"] for item in response["errors"]}, {"timezone_required", "unresolved_reference"})

    def test_duplicate_events_are_rejected_not_silently_deduplicated(self):
        request = alert()
        request["normalized_events"].append(deepcopy(request["normalized_events"][0]))
        self.assertEqual(build_risk_forecast(request)["errors"][0]["code"], "duplicate_identity")

    def test_nonfinite_and_invalid_shapes_are_validation_errors(self):
        for payload in ([], None, {"schema_version": True}, {**alert(), "anomaly_score": float("nan")}, {**alert(), "anomaly_score": 10 ** 500}, {**alert(), "normalized_events": "wrong"}, {**alert(), "entities": [{"entity_id": "x", "entity_type": []}]}):
            with self.subTest(payload=type(payload).__name__):
                self.assertEqual(build_risk_forecast(payload)["response_type"], "validation_error")

    def test_input_is_not_mutated(self):
        original = alert()
        before = deepcopy(original)
        AnalystAlert.from_dict(original)
        self.assertEqual(original, before)


if __name__ == "__main__":
    unittest.main()

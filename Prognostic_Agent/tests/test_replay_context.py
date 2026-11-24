from datetime import datetime, timezone
import unittest

from Prognostic_Agent.analyst_adapter import adapt_analyst_incident
from Prognostic_Agent.replay_context import causal_inventory, host_form
from Prognostic_Agent.tests.test_adapter import incident


class ReplayContextTests(unittest.TestCase):
    def test_source_ip_placeholders_are_unknown_without_changing_input(self):
        for value in ("", " ", "-", "::1", "127.0.0.1", None):
            source = incident()
            source["events"][0]["source_ip"] = value
            request = adapt_analyst_incident(source)
            self.assertIsNone(request["source_ip"])
            self.assertIsNone(request["normalized_events"][0]["source_ip"])
            self.assertEqual(source["events"][0]["source_ip"], value)
        source["events"][0]["source_ip"] = "192.0.2.42"
        self.assertEqual(adapt_analyst_incident(source)["source_ip"], "192.0.2.42")

    def test_replay_assumption_does_not_backdate_observed_inventory(self):
        inventory = {"entities": [{"entity_id": "user:example", "entity_type": "user", "as_of": "2026-11-24T00:00:00Z", "privilege_level": "admin"}]}
        result = causal_inventory(inventory, [{"host": "EXAMPLE-HOST"}], datetime(2026, 11, 23, tzinfo=timezone.utc))
        self.assertEqual(len(result["entities"]), 1)
        host = result["entities"][0]
        self.assertEqual(host["asset_criticality"], "normal")
        self.assertEqual(host["source"], "operator_replay")
        self.assertIsNone(host["privilege_level"])
        self.assertNotIn("related_assets", host)
        self.assertEqual(inventory["entities"][0]["privilege_level"], "admin")
        self.assertEqual(host_form("HOST:Example-Host."), "example-host")

import unittest

from agents import (
    AnalystAgent,
    BIAgent,
    DemoExternalSystems,
    PrognosticAgent,
    SecurityEvent,
    SentinelAgent,
    Severity,
    utc_now,
)


class AgentUnitTests(unittest.TestCase):
    def event(self, event_id="evt-1", severity=Severity.HIGH):
        return SecurityEvent(
            event_id=event_id,
            timestamp=utc_now(),
            source="test-siem",
            event_type="suspicious_login",
            user="user@example.com",
            host="prod-db-1",
            source_ip="203.0.113.5",
            severity=severity,
        )

    def test_sentinel_rejects_empty_input(self):
        with self.assertRaises(ValueError):
            SentinelAgent().detect_anomaly([])

    def test_sentinel_creates_alert(self):
        incident = SentinelAgent().detect_anomaly([self.event()])
        self.assertEqual(incident.alert["normalized_event_count"], 1)
        self.assertGreater(incident.anomaly_score, 0)

    def test_analyst_enriches_asset_and_risk(self):
        incident = SentinelAgent().detect_anomaly([self.event()])
        AnalystAgent(DemoExternalSystems()).analyze(incident)
        self.assertEqual(incident.asset_context["criticality"], "high")
        self.assertIn("risk_score", incident.risk_analysis)

    def test_prognostic_and_bi_agents_produce_outputs(self):
        incident = SentinelAgent().detect_anomaly([self.event()])
        systems = DemoExternalSystems()
        AnalystAgent(systems).analyze(incident)
        PrognosticAgent(systems).forecast_risk(incident)
        BIAgent().assess(incident)
        self.assertIn("risk_path", incident.forecast)
        self.assertIn("impact_score", incident.business_impact)


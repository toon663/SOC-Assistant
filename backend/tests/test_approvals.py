"""Human decisions, persisted state, replay prevention, and concurrent reviews."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch

from agents import SecurityEvent, SecurityOperationsPipeline, Severity, utc_now
from database import IncidentRepository
from integrations import IntegrationHub

try:
    from fastapi.testclient import TestClient
    import config
    with patch.object(config, "settings", replace(config.settings, database_path=":memory:")):
        import api
except ImportError:
    TestClient = None


def pending_incident(systems):
    events = [SecurityEvent(
        event_id=f"review-event-{index}", timestamp=utc_now(), source="test",
        event_type="suspicious_login", user="alice", host="prod-db-01",
        severity=Severity.CRITICAL,
    ) for index in range(5)]
    return SecurityOperationsPipeline(systems=systems).run(events)


@unittest.skipIf(TestClient is None, "FastAPI and httpx are optional dependencies")
class ApprovalApiTests(unittest.TestCase):
    def setUp(self):
        self.repository = IncidentRepository(":memory:")
        self.systems = IntegrationHub()
        self.incident = pending_incident(self.systems)
        self.assertEqual(self.incident.selected_playbook, "contain_and_disable_user")
        self.repository.save_incident(self.incident)
        with patch.object(api, "IncidentRepository", return_value=self.repository), patch.object(api, "IntegrationHub", return_value=self.systems):
            self.client = TestClient(api.create_app())
        self.url = f"/incidents/{self.incident.incident_id}/decision"

    def tearDown(self):
        self.client.close()
        self.repository.close()

    def decide(self, decision="approve", **changes):
        return self.client.post(self.url, json={"decision": decision, "reviewer": " Analyst One ", "reason": " Reviewed evidence ", **changes})

    def test_approval_resumes_stored_response_and_persists_audit(self):
        response = self.decide()
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["action_result"]["status"], "executed")
        self.assertEqual(result["selected_playbook"], self.incident.selected_playbook)
        self.assertEqual(self.systems.edr.actions[0]["target"], "prod-db-01")
        self.assertEqual(self.systems.iam.actions[0]["target"], "alice")
        self.assertEqual(len(self.systems.ticketing.tickets), 1)
        approval = result["action_result"]["approval"]
        self.assertEqual(approval["reviewer"], "Analyst One")
        self.assertEqual(approval["reason"], "Reviewed evidence")
        self.assertTrue(approval["decided_at"])
        self.assertIn("response_decision", [entry["action"] for entry in result["audit_log"]])
        stored = self.client.get(f"/incidents/{self.incident.incident_id}").json()
        self.assertEqual(stored, result)
        row = self.repository.connection.execute("SELECT payload FROM audit_log WHERE agent = 'human'").fetchone()
        self.assertIn("Analyst One", row[0])

    def test_denial_records_decision_without_response_actions(self):
        response = self.decide("deny")
        self.assertEqual(response.status_code, 200)
        result = response.json()["action_result"]
        self.assertEqual(result["status"], "denied")
        self.assertEqual(result["actions"], [])
        self.assertEqual(result["approval"]["decision"], "deny")
        self.assertEqual(self.systems.edr.actions, [])
        self.assertEqual(self.systems.iam.actions, [])

    def test_repeated_or_conflicting_decisions_do_not_repeat_actions(self):
        self.assertEqual(self.decide().status_code, 200)
        self.assertEqual(self.decide().status_code, 409)
        self.assertEqual(self.decide("deny").status_code, 409)
        self.assertEqual(len(self.systems.edr.actions), 1)
        self.assertEqual(len(self.systems.iam.actions), 1)

    def test_denied_incident_cannot_be_approved_later(self):
        self.assertEqual(self.decide("deny").status_code, 200)
        self.assertEqual(self.decide().status_code, 409)
        self.assertEqual(self.systems.edr.actions, [])

    def test_invalid_input_never_executes_a_response(self):
        for changes in [{"reviewer": " "}, {"reviewer": True}, {"reason": ""}, {"reason": "x" * 2001}, {"decision": "yes"}, {"decision": {"approve": True}}]:
            with self.subTest(changes=changes):
                self.assertEqual(self.decide(**changes).status_code, 422)
        self.assertEqual(self.systems.edr.actions, [])

    def test_unknown_incident_returns_404(self):
        response = self.client.post("/incidents/missing/decision", json={"decision": "deny", "reviewer": "Analyst", "reason": "No evidence"})
        self.assertEqual(response.status_code, 404)

    def test_reingestion_preserves_denial_and_decision_audit(self):
        decided = self.decide("deny").json()
        events = [{"event_id": event.event_id, "event_type": event.event_type, "severity": "critical", "host": event.host, "user": event.user} for event in self.incident.events]
        response = self.client.post("/events", json={"events": events})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), decided)
        self.assertEqual(self.decide().status_code, 409)

    def test_monitor_playbook_can_be_reviewed_without_containment(self):
        self.incident.selected_playbook = "monitor_and_investigate"
        self.repository.update_pending_incident(self.incident.incident_id, lambda incident: setattr(incident, "selected_playbook", "monitor_and_investigate"))
        response = self.decide()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["action_result"]["actions"], [])
        self.assertEqual(self.systems.edr.actions, [])


class DecisionConcurrencyTests(unittest.TestCase):
    def test_two_database_connections_can_execute_only_one_decision(self):
        with TemporaryDirectory() as directory:
            path = str(Path(directory) / "approvals.db")
            first, second = IncidentRepository(path), IncidentRepository(path)
            systems = IntegrationHub()
            incident = pending_incident(systems)
            first.save_incident(incident)
            orchestrator = SecurityOperationsPipeline(systems=systems).orchestrator
            barrier = threading.Barrier(2)

            def review(repository):
                barrier.wait(timeout=5)
                try:
                    repository.update_pending_incident(incident.incident_id, lambda pending: orchestrator.review_response(pending, "approve", "Analyst", "Verified"))
                    return "accepted"
                except ValueError:
                    return "conflict"

            try:
                with ThreadPoolExecutor(max_workers=2) as executor:
                    outcomes = list(executor.map(review, [first, second]))
                self.assertCountEqual(outcomes, ["accepted", "conflict"])
                self.assertEqual(len(systems.edr.actions), 1)
                self.assertEqual(len(systems.iam.actions), 1)
            finally:
                first.close()
                second.close()

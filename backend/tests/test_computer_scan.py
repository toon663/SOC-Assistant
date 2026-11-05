"""Windows Security XML parsing, collection errors, and dashboard API tests."""
from dataclasses import replace
import base64
import json
import subprocess
import unittest
from unittest.mock import patch

from agents import SentinelAgent
from anomaly import detect_anomalies
from gatherer import SecurityLogBatch, WindowsSecurityRecord, gather_security_events, parse_security_record


def record(event_id=4625, record_id=10):
    return WindowsSecurityRecord(record_id, event_id, "2026-10-21T12:00:00Z", "test-host", "Microsoft-Windows-Security-Auditing", {"TargetUserName": "alice", "TargetDomainName": "LAB", "IpAddress": "192.0.2.10"})


def batch(*events):
    return SecurityLogBatch("test-host", "2026-10-21T12:01:00Z", "Security", 200, False, list(events))


def event_xml(event_id=4625, payload=None):
    data = payload if payload is not None else '<EventData><Data Name="TargetUserName">alice</Data><Data Name="IpAddress">192.0.2.10</Data></EventData>'
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>{event_id}</EventID><TimeCreated SystemTime="2026-10-21T12:00:00Z"/><EventRecordID>10</EventRecordID><Channel>Security</Channel><Computer>test-host</Computer></System>{data}</Event>'''


class SecurityDetectionTests(unittest.TestCase):
    def test_successful_logon_is_not_a_finding(self):
        self.assertEqual(SentinelAgent().inspect_computer(batch(record(4624))), [])

    def test_each_rule_selects_its_windows_event_id(self):
        for event_id in (4625, 4740, 4719, 1102):
            with self.subTest(event_id=event_id):
                findings = detect_anomalies(batch(record(event_id)))
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["windows_event_id"], event_id)

    def test_sentinel_preserves_evidence_and_stable_identity(self):
        event = SentinelAgent().inspect_computer(batch(record()))[0]
        again = SentinelAgent().inspect_computer(batch(record()))[0]
        self.assertEqual(event.event_id, again.event_id)
        self.assertEqual(event.user, "LAB\\alice")
        self.assertEqual(event.source_ip, "192.0.2.10")
        self.assertEqual(event.metadata["record_id"], 10)
        changed = replace(record(), timestamp="2026-10-21T12:01:00Z")
        self.assertNotEqual(event.event_id, SentinelAgent().inspect_computer(batch(changed))[0].event_id)

    def test_parse_named_event_data(self):
        parsed = parse_security_record(event_xml())
        self.assertEqual(parsed.event_id, 4625)
        self.assertEqual(parsed.record_id, 10)
        self.assertEqual(parsed.host, "test-host")
        self.assertEqual(parsed.data["TargetUserName"], "alice")

    def test_parse_log_clear_user_data_namespace(self):
        payload = '<UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"><SubjectUserName>admin</SubjectUserName></LogFileCleared></UserData>'
        parsed = parse_security_record(event_xml(1102, payload))
        self.assertEqual(parsed.data["SubjectUserName"], "admin")


class CollectorTests(unittest.TestCase):
    def collect(self, stdout="[]", returncode=0, **kwargs):
        result = subprocess.CompletedProcess([], returncode, stdout, "")
        with patch("gatherer.os.name", "nt"), patch("gatherer.subprocess.run", return_value=result) as run:
            collected = gather_security_events(**kwargs)
        self.assertEqual(run.call_args.kwargs["timeout"], 30)
        self.assertNotIn("shell", run.call_args.kwargs)
        script = base64.b64decode(run.call_args.args[0][-1]).decode("utf-16-le")
        self.assertIn("Get-WinEvent -LogName Security", script)
        self.assertIn(f"-MaxEvents {kwargs.get('limit', 200) + 1}", script)
        self.assertNotIn("FilterHashtable", script)
        return collected

    def test_empty_log_window(self):
        self.assertEqual(self.collect().events, [])

    def test_single_record_and_truncation(self):
        single = self.collect(json.dumps([event_xml()]))
        self.assertEqual(len(single.events), 1)
        self.assertFalse(single.truncated)
        limited = self.collect(json.dumps([event_xml(), event_xml()]), limit=1)
        self.assertEqual(len(limited.events), 1)
        self.assertTrue(limited.truncated)

    def test_permission_denied_is_not_an_empty_result(self):
        with self.assertRaises(PermissionError):
            self.collect(returncode=5)

    def test_failed_query_and_invalid_records(self):
        for output, code in [("", 1), ("not JSON", 0), ('["<broken>"]', 0)]:
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                self.collect(output, code)

    def test_timeout(self):
        with patch("gatherer.os.name", "nt"), patch("gatherer.subprocess.run", side_effect=subprocess.TimeoutExpired("powershell.exe", 30)):
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                gather_security_events()

    def test_unsupported_host_and_invalid_limits(self):
        with patch("gatherer.os.name", "posix"), self.assertRaisesRegex(RuntimeError, "Windows"):
            gather_security_events()
        with patch("gatherer.os.name", "nt"):
            for limit in [0, 1001, "1; exit", True]:
                with self.subTest(limit=limit), self.assertRaises(ValueError):
                    gather_security_events(limit=limit)


try:
    from fastapi.testclient import TestClient
    import config
    from database import IncidentRepository
    with patch.object(config, "settings", replace(config.settings, database_path=":memory:")):
        import api
except ImportError:
    TestClient = None


@unittest.skipIf(TestClient is None, "FastAPI and httpx are optional dependencies")
class ScanApiTests(unittest.TestCase):
    def setUp(self):
        self.repository = IncidentRepository(":memory:")
        with patch.object(api, "IncidentRepository", return_value=self.repository):
            self.client = TestClient(api.create_app())

    def tearDown(self):
        self.client.close()
        self.repository.close()

    def test_normal_records_are_returned_without_incidents(self):
        with patch.object(api, "gather_security_events", return_value=batch(record(4624))):
            response = self.client.post("/scan")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["snapshot"]["events"][0]["event_id"], 4624)
        self.assertEqual(response.json()["anomalies"], [])
        self.assertIsNone(response.json()["incident"])
        self.assertEqual(self.client.get("/incidents").json(), [])

    def test_findings_persist_and_identical_scans_reuse_incident_id(self):
        with patch.object(api, "gather_security_events", return_value=batch(record())):
            first = self.client.post("/scan")
            second = self.client.post("/scan")
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.json()["anomalies"][0]["windows_event_id"], 4625)
        incidents = self.client.get("/incidents").json()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["incident_id"], second.json()["incident"]["incident_id"])
        self.assertEqual(incidents[0]["events"][0]["metadata"]["record_id"], 10)
        self.assertTrue(incidents[0]["audit_log"])

    def test_access_denied_is_actionable(self):
        with patch.object(api, "gather_security_events", side_effect=PermissionError("Run backend as Administrator")):
            response = self.client.post("/scan")
        self.assertEqual(response.status_code, 403)
        self.assertIn("Administrator", response.json()["detail"])
        self.assertEqual(self.client.get("/incidents").json(), [])

    def test_failed_collection_returns_service_unavailable(self):
        with patch.object(api, "gather_security_events", side_effect=RuntimeError("unavailable")), self.assertLogs("api", level="ERROR"):
            response = self.client.post("/scan")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.client.get("/incidents").json(), [])

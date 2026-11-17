import importlib.util
import os
import tempfile
import unittest
from unittest import mock

from agents import SecurityEvent, SecurityOperationsPipeline, SentinelAgent, Severity, utc_now
from database import IncidentRepository
from windows_ingest import (
    MAX_STORED_EVENTS,
    WindowsIngestService,
    anomaly_to_event,
    extract_source_ip,
    extract_user,
    group_events,
    severity_for,
)

import gatherer

HAS_ML = all(importlib.util.find_spec(name) for name in ("numpy", "pandas", "sklearn", "joblib"))

FAILED_LOGON_MESSAGE = (
    "An account failed to log on.\r\n\r\nSubject:\r\n\tAccount Name:\t\tHOST$\r\n\r\n"
    "Account For Which Logon Failed:\r\n\tAccount Name:\t\t{user}\r\n\r\n"
    "Network Information:\r\n\tSource Network Address:\t{ip}\r\n"
)


def windows_event(record_id, event_id=4625, *, log="Security", level=0, message=None, user_id=None):
    return {
        "recordId": record_id,
        "timeCreatedUtc": f"2026-10-18T21:40:{record_id % 60:02d}.0000000Z",
        "eventId": event_id,
        "provider": "Microsoft-Windows-Security-Auditing",
        "level": level,
        "levelName": "Information",
        "keywords": ["Audit Failure"],
        "logName": log,
        "machineName": "HOST",
        "userId": user_id,
        "processId": 700,
        "threadId": 800,
        "task": "Logon",
        "opcode": "Info",
        "message": message if message is not None else FAILED_LOGON_MESSAGE.format(user="bob", ip="203.0.113.9"),
        "eventData": ["a", "b"],
    }


def anomaly(event_id=4625, *, log="Security", level=0, mitre=(), cisa=(), user="bob", record_id=1):
    return {
        "computerName": "HOST",
        "modelScore": 0.99,
        "model": "RandomForestClassifier",
        "mitreTechniques": list(mitre),
        "cisaMatches": list(cisa),
        "reasons": ["high-risk eventId"],
        "event": {
            "recordId": record_id,
            "timeCreatedUtc": "2026-10-18T21:40:33Z",
            "eventId": event_id,
            "provider": "Provider",
            "level": level,
            "levelName": "Information",
            "logName": log,
            "userId": None,
            "message": FAILED_LOGON_MESSAGE.format(user=user, ip="203.0.113.9"),
        },
    }


class MappingTests(unittest.TestCase):
    def test_extracts_target_account_not_subject_machine_account(self):
        self.assertEqual(extract_user({"message": FAILED_LOGON_MESSAGE.format(user="bob", ip="-")}), "bob")

    def test_service_identities_are_not_users(self):
        self.assertIsNone(extract_user({"message": "", "userId": "S-1-5-18"}))
        self.assertIsNone(extract_user({"message": "Account Name:\tSYSTEM\r\n", "userId": "S-1-5-21-1"}))

    def test_falls_back_to_user_sid(self):
        self.assertEqual(extract_user({"message": "no account", "userId": "S-1-5-21-1"}), "S-1-5-21-1")

    def test_source_ip_validation(self):
        self.assertEqual(extract_source_ip("Source Network Address:\t203.0.113.9"), "203.0.113.9")
        for message in ("Source Network Address:\t-", "Source Network Address:\t127.0.0.1", "no address"):
            self.assertIsNone(extract_source_ip(message))

    def test_severity_comes_from_evidence(self):
        cases = [
            (anomaly(1102), Severity.CRITICAL),
            (anomaly(999, level=1), Severity.CRITICAL),
            (anomaly(999, cisa=[{"type": "cve", "value": "CVE-2024-1"}]), Severity.CRITICAL),
            (anomaly(4625), Severity.HIGH),
            (anomaly(4672), Severity.HIGH),
            (anomaly(4672, user="SYSTEM"), Severity.LOW),
            (anomaly(4624, mitre=["T1078"], user="SYSTEM"), Severity.LOW),
            # Other high-risk events stay high even for service accounts.
            (anomaly(4625, user="SYSTEM"), Severity.HIGH),
            (anomaly(999, mitre=["T1078"]), Severity.HIGH),
            (anomaly(7036, log="System", mitre=["T1489"]), Severity.MEDIUM),
            (anomaly(10010, log="System", level=2), Severity.MEDIUM),
            # Sysmon ID 1 collides with routine events in native channels.
            (anomaly(1, log="System", level=4), Severity.LOW),
        ]
        for item, expected in cases:
            with self.subTest(event_id=item["event"]["eventId"]):
                self.assertEqual(severity_for(item), expected)

    def test_mapping_carries_detection_evidence(self):
        event = anomaly_to_event(anomaly(mitre=["T1110"]))
        self.assertEqual(event.event_type, "failed_logon")
        self.assertEqual((event.host, event.user, event.source_ip), ("HOST", "bob", "203.0.113.9"))
        self.assertEqual(event.detector_score, 0.99)
        self.assertEqual(event.metadata["mitre_techniques"], ["T1110"])

    def test_grouping_keeps_accounts_separate(self):
        events = [
            anomaly_to_event(anomaly(record_id=1)),
            anomaly_to_event(anomaly(record_id=2)),
            anomaly_to_event(anomaly(record_id=3, user="alice")),
        ]
        self.assertEqual(sorted(len(group) for group in group_events(events)), [1, 2])


class SentinelScoringTests(unittest.TestCase):
    def event(self, severity, detector_score=None):
        return SecurityEvent(
            event_id="e", timestamp=utc_now(), source="test", event_type="x",
            severity=severity, detector_score=detector_score,
        )

    def test_score_without_detector_is_unchanged(self):
        incident = SentinelAgent().detect_anomaly([self.event(Severity.HIGH)])
        self.assertEqual(incident.anomaly_score, 52.5)
        self.assertNotIn("mitre_techniques", incident.alert)

    def test_detector_score_cannot_make_low_severity_critical(self):
        incident = SentinelAgent().detect_anomaly([self.event(Severity.LOW, detector_score=1.0)])
        self.assertLess(incident.anomaly_score, 65)


class GathererTests(unittest.TestCase):
    def test_channel_failure_keeps_other_channels(self):
        def fake_collect(log_name, *args, **kwargs):
            if log_name == "Security":
                raise RuntimeError("unauthorized")
            return [{"eventId": 1, "timeCreatedUtc": "2026-10-18T00:00:00Z"}]

        with mock.patch.object(gatherer, "collect_log", side_effect=fake_collect):
            document = gatherer.collect_document(["Security", "System"], hours=1)
        self.assertEqual(document["eventCount"], 1)
        self.assertEqual(document["errors"], [{"logName": "Security", "message": "unauthorized"}])
        self.assertEqual(document["lookbackHours"], 1)


@unittest.skipUnless(HAS_ML, "detector dependencies are not installed")
class IngestEndToEndTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.repository = IncidentRepository(os.path.join(directory.name, "test.db"))
        self.addCleanup(self.repository.close)
        self.service = WindowsIngestService(SecurityOperationsPipeline(require_approval=True), self.repository)
        self.document = {
            "computerName": "HOST",
            "errors": [{"logName": "Security", "message": "denied"}],
            "events": [
                windows_event(1),
                windows_event(2),
                windows_event(3, event_id=1102, message="The audit log was cleared.", user_id="S-1-5-21-1"),
                windows_event(4, event_id=7, log="Application", level=4, message="Routine status"),
            ],
        }

    def test_detected_events_become_persisted_incidents(self):
        summary = self.service.ingest_document(self.document)

        self.assertEqual(summary["events_scanned"], 4)
        self.assertEqual(summary["errors"], self.document["errors"])
        by_type = {item["title"]: item for item in summary["incidents"]}
        failed_logons = by_type["Potential failed_logon incident"]
        self.assertEqual(failed_logons["occurrence_count"], 2)
        self.assertEqual(failed_logons["severity"], "high")
        self.assertEqual(by_type["Potential audit_log_cleared incident"]["severity"], "critical")

        stored = self.repository.get_incident(failed_logons["incident_id"])
        self.assertEqual(stored["events"][0]["user"], "bob")
        self.assertEqual(stored["events"][0]["host"], "HOST")
        self.assertIn("summary", stored["alert"])
        self.assertTrue(stored["alert"]["detection_reasons"])

    def test_high_impact_playbooks_never_execute_during_ingest(self):
        for item in self.service.ingest_document(self.document)["incidents"]:
            self.assertEqual(item["status"], "approval_required")

    def test_overlapping_collection_does_not_duplicate_incidents(self):
        first = self.service.ingest_document(self.document)
        second = self.service.ingest_document(self.document)
        self.assertEqual(second["incidents"], [])
        self.assertEqual(second["duplicates_skipped"], first["anomalies_detected"])
        self.assertEqual(len(self.repository.list_incidents()), len(first["incidents"]))

    def test_repeat_in_later_scan_updates_the_open_incident(self):
        first = self.service.ingest_document(self.document)
        original = next(i for i in first["incidents"] if i["title"] == "Potential failed_logon incident")
        before = self.repository.get_incident(original["incident_id"])

        self.document["events"].append(windows_event(5))
        summary = self.service.ingest_document(self.document)

        self.assertEqual(len(summary["incidents"]), 1)
        merged = summary["incidents"][0]
        self.assertTrue(merged["merged"])
        self.assertEqual(merged["incident_id"], original["incident_id"])
        self.assertEqual((merged["new_events"], merged["occurrence_count"]), (1, 3))

        stored = self.repository.get_incident(original["incident_id"])
        self.assertEqual(stored["alert"]["occurrence_count"], 3)
        self.assertEqual(stored["alert"]["ticket_id"], before["alert"]["ticket_id"])
        self.assertEqual(stored["detected_at"], before["detected_at"])
        self.assertEqual(stored["audit_log"][: len(before["audit_log"])], before["audit_log"])
        self.assertLess(stored["alert"]["first_seen"], stored["alert"]["last_seen"])
        self.assertEqual(len(self.repository.list_incidents()), len(first["incidents"]))

    def test_repeat_after_response_opens_a_new_incident(self):
        first = self.service.ingest_document(self.document)
        self.repository.connection.execute("UPDATE incidents SET status = 'executed'")
        self.repository.connection.commit()

        self.document["events"].append(windows_event(5))
        summary = self.service.ingest_document(self.document)

        self.assertFalse(summary["incidents"][0]["merged"])
        self.assertNotIn(summary["incidents"][0]["incident_id"], [i["incident_id"] for i in first["incidents"]])

    def test_count_stays_exact_when_stored_evidence_is_capped(self):
        document = {"computerName": "HOST", "events": [windows_event(i) for i in range(1, 121)]}
        incident_id = self.service.ingest_document(document)["incidents"][0]["incident_id"]
        stored = self.repository.get_incident(incident_id)
        self.assertEqual(stored["alert"]["occurrence_count"], 120)
        self.assertEqual(len(stored["events"]), MAX_STORED_EVENTS)

        # Events dropped from storage must still count as processed.
        repeat = self.service.ingest_document(document)
        self.assertEqual((repeat["incidents"], repeat["duplicates_skipped"]), ([], 120))

    def test_empty_document_is_a_no_op(self):
        summary = self.service.ingest_document({"events": []})
        self.assertEqual((summary["anomalies_detected"], summary["incidents"]), (0, []))

    def test_malformed_document_is_rejected(self):
        for document in ({}, {"events": "x"}, {"events": ["x"]}):
            with self.assertRaises(ValueError):
                self.service.ingest_document(document)

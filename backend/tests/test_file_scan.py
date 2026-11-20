import importlib.util
import os
import tempfile
import unittest

from agents import SecurityOperationsPipeline, Severity
from database import IncidentRepository
from file_scan import FileScanService, ScanUnavailable, extract_executable_paths, result_to_event
from windows_ingest import WindowsIngestService, group_key

HAS_ML = all(importlib.util.find_spec(name) for name in ("numpy", "pandas", "sklearn", "joblib"))

PROFILE = {"techniques": [{"id": "T1547.001", "name": "Registry Run Keys", "tactic": "persistence", "share": 0.6}],
           "tactics": ["persistence", "command and control"]}


def scan_result(verdict="malicious", sha="a" * 64, family="berbew", name="dropper.exe"):
    result = {
        "sha256": sha, "file_name": name, "file_path": f"C:\\Users\\bob\\{name}", "size_bytes": 1000,
        "verdict": verdict, "score": {"malicious": 0.99, "suspicious": 0.7, "clean": 0.01}[verdict],
        "suspicious_threshold": 0.577, "malicious_threshold": 0.973, "family": None,
        "explanation": {"toward_malicious": [{"feature_group": "imported APIs", "contribution": 1.2}], "toward_benign": []},
    }
    if verdict != "clean" and family:
        result.update(family=family, family_probability=0.91, family_profile=PROFILE,
                      family_candidates=[{"family": family, "probability": 0.91}])
    return result


class FakeScanner:
    def __init__(self, verdict="malicious"):
        self.verdict = verdict
        self.calls = 0

    def info(self):
        return {"detector": "fake"}

    def scan_file(self, path):
        self.calls += 1
        return scan_result(self.verdict, sha=f"{abs(hash(str(path))):064d}"[:64], name=os.path.basename(str(path)))

    def scan_bytes(self, data, name=""):
        return scan_result(self.verdict, name=name)


def process_event(record_id, path, *, event_id=4688, provider="Microsoft-Windows-Security-Auditing", log="Security"):
    label = "Image:" if event_id == 1 else "New Process Name:"
    return {
        "recordId": record_id, "timeCreatedUtc": f"2026-11-19T10:00:{record_id:02d}Z", "eventId": event_id,
        "provider": provider, "level": 0, "levelName": "Information", "logName": log, "machineName": "HOST",
        "userId": None, "processId": 1, "threadId": 1, "task": "Process Creation", "opcode": "Info",
        "keywords": ["Audit Success"], "eventData": [],
        "message": f"A new process has been created.\r\n\r\nProcess Information:\r\n\t{label}\t{path}\r\n",
    }


class ExtractionTests(unittest.TestCase):
    def test_finds_process_paths_and_dedupes(self):
        events = [
            process_event(1, "C:\\Temp\\a.exe"),
            process_event(2, "c:\\temp\\A.EXE"),
            process_event(3, "C:\\Temp\\b.exe", event_id=1, provider="Microsoft-Windows-Sysmon", log="Microsoft-Windows-Sysmon/Operational"),
            # Event ID 1 from another provider is not a Sysmon process launch.
            process_event(4, "C:\\Temp\\c.exe", event_id=1, provider="Service Control Manager", log="System"),
            process_event(5, "-"),
        ]
        self.assertEqual([path for path, _ in extract_executable_paths(events)], ["C:\\Temp\\a.exe", "C:\\Temp\\b.exe"])


class MappingTests(unittest.TestCase):
    def test_clean_and_unsupported_files_create_no_event(self):
        self.assertIsNone(result_to_event(scan_result("clean"), host="HOST"))
        self.assertIsNone(result_to_event({**scan_result(), "verdict": "unsupported"}, host="HOST"))

    def test_flagged_file_maps_to_event(self):
        event = result_to_event(scan_result(), host="HOST", user="bob")
        self.assertEqual(event.event_type, "malware_detected")
        self.assertEqual(event.severity, Severity.CRITICAL)
        self.assertEqual(event.metadata["malware_family"], "berbew")
        self.assertEqual(event.metadata["mitre_techniques"], ["T1547.001"])
        self.assertEqual(result_to_event(scan_result("suspicious"), host="HOST").severity, Severity.HIGH)
        self.assertEqual(group_key(event), f"HOST|malware-scan|{'a' * 64}")

    def test_pipeline_uses_family_and_tactics(self):
        incident = SecurityOperationsPipeline().run([result_to_event(scan_result(), host="HOST")])
        self.assertEqual(incident.alert["title"], "Malware detected: berbew (dropper.exe)")
        self.assertEqual(incident.alert["malware"]["sha256"], "a" * 64)
        self.assertIn("T1547.001", incident.alert["mitre_techniques"])
        self.assertEqual(incident.forecast["risk_path"], ["persistence", "command and control"])
        self.assertEqual(incident.action_result["status"], "approval_required")


class ServiceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = directory.name
        self.repository = IncidentRepository(os.path.join(self.dir, "test.db"))
        self.addCleanup(self.repository.close)
        self.scanner = FakeScanner()
        self.service = WindowsIngestService(
            SecurityOperationsPipeline(require_approval=True), self.repository,
            file_scan=FileScanService(lambda: self.scanner),
        )

    def test_on_demand_scan_opens_one_incident_per_file(self):
        first = self.service.ingest_scan_result(scan_result(), host="HOST")
        self.assertEqual(first["incident"]["title"], "Malware detected: berbew (dropper.exe)")
        again = self.service.ingest_scan_result(scan_result(), host="HOST")
        self.assertTrue(again["already_reported"])
        self.assertEqual(again["incident_id"], first["incident"]["incident_id"])
        self.assertIsNone(self.service.ingest_scan_result(scan_result("clean"), host="HOST")["incident"])
        self.assertEqual(len(self.repository.list_incidents()), 1)

    def test_missing_files_are_reported_not_raised(self):
        events, stats = self.service.file_scan.scan_process_events([process_event(1, "C:\\gone\\x.exe")], host="HOST")
        self.assertEqual((events, stats["files_scanned"]), ([], 0))
        self.assertEqual(len(stats["errors"]), 1)

    def test_unavailable_scanner_degrades_gracefully(self):
        def broken():
            raise ScanUnavailable("models missing")
        service = FileScanService(broken)
        self.assertEqual(service.status(), {"available": False, "detail": "models missing"})
        path = os.path.join(self.dir, "a.exe")
        open(path, "wb").close()
        events, stats = service.scan_process_events([process_event(1, path)], host="HOST")
        self.assertEqual((events, stats["errors"]), ([], ["models missing"]))

    def test_repeated_launches_are_read_once(self):
        path = os.path.join(self.dir, "a.exe")
        open(path, "wb").close()
        for _ in range(3):
            self.service.file_scan.scan_process_events([process_event(1, path)], host="HOST")
        self.assertEqual(self.scanner.calls, 1)

    def test_resolved_incident_leaves_open_queue(self):
        incident_id = self.service.ingest_scan_result(scan_result(), host="HOST")["incident"]["incident_id"]
        resolved = self.repository.resolve_incident(incident_id, resolved_at="2026-11-19T12:00:00+00:00")
        self.assertEqual(resolved["action_result"]["status"], "resolved")
        self.assertEqual(resolved["action_result"]["previous_status"], "approval_required")
        self.assertEqual(resolved["audit_log"][-1]["action"], "resolve_incident")
        self.assertEqual(self.repository.get_incident(incident_id)["action_result"]["status"], "resolved")
        self.assertIsNone(self.repository.find_open_incident(f"HOST|malware-scan|{'a' * 64}"))
        self.assertIsNone(self.repository.resolve_incident("missing", resolved_at="x"))

    @unittest.skipUnless(HAS_ML, "detector dependencies are not installed")
    def test_resolved_records_stay_resolved_on_rescan(self):
        failed = ("An account failed to log on.\r\n\tAccount Name:\t\tbob\r\n"
                  "\tSource Network Address:\t203.0.113.9\r\n")
        event = {**process_event(1, "-"), "eventId": 4625, "message": failed}
        document = {"computerName": "HOST", "events": [event]}
        first = self.service.ingest_document(document)
        self.repository.resolve_incident(first["incidents"][0]["incident_id"], resolved_at="2026-11-19T12:00:00+00:00")

        again = self.service.ingest_document(document)
        self.assertEqual((again["incidents"], again["duplicates_skipped"], again["duplicates_in_resolved"]), ([], 1, 1))

        document["events"].append({**event, "recordId": 2, "timeCreatedUtc": "2026-11-19T10:00:02Z"})
        repeat = self.service.ingest_document(document)
        self.assertEqual(len(repeat["incidents"]), 1)
        self.assertFalse(repeat["incidents"][0]["merged"])
        self.assertNotEqual(repeat["incidents"][0]["incident_id"], first["incidents"][0]["incident_id"])

    @unittest.skipUnless(HAS_ML, "detector dependencies are not installed")
    def test_routine_process_launches_do_not_open_incidents(self):
        self.scanner.verdict = "clean"
        path = os.path.join(self.dir, "tool.exe")
        open(path, "wb").close()
        summary = self.service.ingest_document({"computerName": "HOST", "events": [process_event(1, path), process_event(2, path)]})
        self.assertEqual(summary["incidents"], [])
        self.assertEqual(summary["process_launches_skipped"], 2)

    @unittest.skipUnless(HAS_ML, "detector dependencies are not installed")
    def test_process_creation_ingest_opens_malware_incident(self):
        path = os.path.join(self.dir, "dropper.exe")
        open(path, "wb").close()
        document = {"computerName": "HOST", "events": [process_event(1, path), process_event(2, path)]}
        summary = self.service.ingest_document(document)
        self.assertEqual(summary["malware_detected"], 1)
        self.assertEqual(summary["malware_scan"]["files_scanned"], 1)
        titles = [item["title"] for item in summary["incidents"]]
        self.assertIn("Malware detected: berbew (dropper.exe)", titles)

        repeat = self.service.ingest_document(document)
        self.assertNotIn("Malware detected: berbew (dropper.exe)", [item["title"] for item in repeat["incidents"]])

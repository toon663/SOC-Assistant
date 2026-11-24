"""Fake OS probes only: no event generation, audit changes or live log queries."""
import json
import subprocess
import unittest
from unittest.mock import patch

from Prognostic_Agent.controlled_check import diagnose_capture, preflight
from Prognostic_Agent.private_paths import PRIVATE_DIR


class ControlledCheckTests(unittest.TestCase):
    def test_no_matching_security_event(self):
        self.assertEqual(diagnose_capture([], {"matching_4688_count": 0}), "no_4688_in_security_log")

    def test_event_exists_but_incident_not_ingested(self):
        self.assertEqual(diagnose_capture([], {"matching_4688_count": 1}), "no_incident_ingested")

    def test_ingested_without_required_technique(self):
        self.assertEqual(diagnose_capture([{"T1059_001_present": False}], {"matching_4688_count": 1}), "incident_with_no_technique")

    def test_log_denial_is_not_reported_as_missing_event(self):
        self.assertIsNone(diagnose_capture([], {"matching_4688_count": None, "errors": ["access_denied"]}))

    def test_retained_incident_overrides_rotated_security_log(self):
        self.assertIsNone(diagnose_capture([{"T1059_001_present": True}], {"matching_4688_count": 0}))

    def test_missing_forecast_is_not_misreported_as_missing_technique(self):
        self.assertIsNone(diagnose_capture([{"T1059_001_present": True, "status": "not_in_this_batch"}], {}))

    @patch("Prognostic_Agent.controlled_check.subprocess.run")
    def test_preflight_uses_fixed_read_only_probe_and_parses_json(self, run):
        expected = {"elevated": True, "process_creation_success_on": True, "command_lines_on": True,
                    "both_settings_on": True, "security_log": {"maximum_bytes": 100, "current_file_bytes": 40},
                    "backend_started_after_analyst": False}
        run.return_value = subprocess.CompletedProcess([], 0, json.dumps(expected), "")
        self.assertEqual(preflight(), expected)
        self.assertTrue(run.call_args.args[0][-1].endswith("controlled_probe.ps1"))
        self.assertNotIn("-ExecutionPolicy", run.call_args.args[0])

    @patch("Prognostic_Agent.controlled_check.subprocess.run", side_effect=OSError("private identifier"))
    def test_probe_failure_is_redacted(self, run):
        self.assertNotIn("private identifier", json.dumps(preflight()))

    @patch("Prognostic_Agent.controlled_check.subprocess.run", side_effect=subprocess.CalledProcessError(1, [], stderr="ScriptContainedMaliciousContent private identifier"))
    def test_security_block_is_reported_without_error_contents(self, run):
        result = preflight()
        self.assertEqual(result["errors"], ["windows_security_blocked_probe"])
        self.assertNotIn("private identifier", json.dumps(result))

    def test_backup_restore_uses_saved_values_and_targeted_subcategory(self):
        text = (PRIVATE_DIR.parent / "audit_settings.ps1").read_text()
        for token in ("GetValueKind", "DoNotExpandEnvironmentNames", "Export-Clixml", "Import-Clixml",
                      "$saved.AuditFlags -band 1", "$saved.AuditFlags -band 2", "$saved.ValueExists", "$saved.ValueKind", "$saved.Value"):
            self.assertIn(token, text)
        self.assertNotIn("auditpol.exe /restore", text)
        self.assertIn("Choose a new backup directory", text)

    def test_probe_exposes_no_settings_mutators(self):
        for filename in ("controlled_probe.ps1", "audit_policy_read.ps1"):
            text = (PRIVATE_DIR.parent / filename).read_text()
            for setter in ("AuditSet", "auditpol.exe /set", "New-ItemProperty", "Remove-ItemProperty", "Start-Process"):
                self.assertNotIn(setter, text)

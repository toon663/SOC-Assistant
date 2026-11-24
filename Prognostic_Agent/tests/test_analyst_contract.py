"""Direct additive Analyst contract regressions, kept inside Prognostic_Agent."""

import base64
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "_prognostic_analyst_contract", Path(__file__).resolve().parents[2] / "backend" / "analyst.py")
analyst = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = analyst
SPEC.loader.exec_module(analyst)


def event(code, identity="primary", *, minute=20, user="alice", message="", ip="203.0.113.42"):
    return SimpleNamespace(event_id=identity, timestamp=f"2026-11-23T11:{minute:02d}:00Z",
                           event_type="test", user=user, host="fixture-host", source_ip=ip,
                           message=message, destination="test", detector_score=None,
                           metadata={"windows_event_id": code, "log_name": "Security"})


def incident(events, **alert):
    return SimpleNamespace(events=events, alert=alert, anomaly_score=50)


def process(message=None):
    encoded = base64.b64encode("Write-Output 'synthetic-only'".encode("utf-16-le")).decode()
    return event(4688, message=message or (
        "New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
        "Creator Process Name: C:\\Windows\\System32\\cmd.exe\n"
        f"Process Command Line: powershell -enc {encoded} -w hidden -ep bypass"))


class AnalystContractTests(unittest.TestCase):
    def test_behavior_excludes_bonus_and_preserves_flat_techniques_and_total(self):
        source = incident([process()])
        normal = analyst.triage(source, asset_context={"criticality": "normal"})
        high = analyst.triage(source, asset_context={"criticality": "high"})
        self.assertEqual((normal["behavioral_score"], high["behavioral_score"]), (85, 85))
        self.assertEqual((normal["risk_score"], high["risk_score"]), (85, 95))
        self.assertEqual(high["findings"][:-1], normal["findings"])
        self.assertEqual(high["mitre_techniques"], ["T1059.001", "T1027", "T1564.003"])
        self.assertEqual(high["technique_evidence"], {technique: ["primary"] for technique in high["mitre_techniques"]})

    def test_behavioral_clamp_and_benign_cap_match_existing_score_bounds(self):
        source = incident([process("Process Command Line: IEX DownloadString -w hidden -ep bypass procdump")])
        result = analyst.triage(source, asset_context={"criticality": "high"})
        self.assertEqual((result["behavioral_score"], result["risk_score"]), (100, 100))

        def benign(ctx):
            ctx.add(70, "Benign cap boundary")
            return analyst.Outcome(analyst.BENIGN, "routine_activity", "test", .8)

        with patch.object(analyst, "select_rule", return_value=benign):
            result = analyst.triage(source, asset_context={"criticality": "high"})
        self.assertEqual((result["behavioral_score"], result["risk_score"]), (30, 30))
        self.assertEqual(len(result["findings"]), 1)

    def test_failed_logon_attribution_distinguishes_failures_from_related_success(self):
        failures = [event(4625, f"failure-{n}", minute=10+n) for n in range(5)]
        success = event(4624, "success", minute=19)
        result = analyst.triage(incident(failures), [analyst.RelatedEvent(success, incident_id="success-incident")])
        self.assertEqual(result["mitre_techniques"], ["T1110.001", "T1078"])
        self.assertEqual(result["technique_evidence"], {"T1110.001": [item.event_id for item in failures], "T1078": ["success"]})

    def test_successful_logon_attribution_distinguishes_related_failures(self):
        failures = [event(4625, f"failure-{n}", minute=10+n) for n in range(5)]
        success = event(4624, "success", message="Logon Type: 3")
        result = analyst.triage(incident([success]), [analyst.RelatedEvent(item) for item in failures])
        self.assertEqual(result["mitre_techniques"], ["T1110", "T1078"])
        self.assertEqual(result["technique_evidence"], {"T1110": [item.event_id for item in failures], "T1078": ["success"]})

    def test_spray_uses_own_and_related_failure_events(self):
        failures = [event(4625, f"failure-{n}", minute=10+n) for n in range(5)]
        spray = [event(4625, "bob-failure", user="bob"), event(4625, "carol-failure", user="carol")]
        result = analyst.triage(incident(failures), [analyst.RelatedEvent(item) for item in spray])
        self.assertEqual(result["technique_evidence"]["T1110.003"], sorted(item.event_id for item in failures + spray))

    def test_account_creation_and_group_change_reference_the_actual_records(self):
        created = event(4720, "created", minute=10, message=(
            "New Account:\n  Account Name: backdoor\n  Security ID: S-1-5-21-123"))
        added = event(4732, "added", minute=15, message=(
            "Group:\n  Group Name: Administrators\nMember:\n  Security ID: S-1-5-21-123\n  Account Name: backdoor"))
        creation = analyst.triage(incident([created]), [analyst.RelatedEvent(added)])
        addition = analyst.triage(incident([added]), [analyst.RelatedEvent(created)])
        expected = {"T1136.001": ["created"], "T1098": ["added"]}
        self.assertEqual(creation["technique_evidence"], expected)
        self.assertEqual(addition["technique_evidence"], expected)

    def test_benign_rules_that_clear_flat_techniques_export_empty_maps(self):
        cases = [event(4697, message="Service Name: test\nService File Name: C:\\Program Files\\Vendor\\service.exe"),
                 event(4698, message="Task Name: \\Microsoft\\Windows\\Test")]
        for source in cases:
            with self.subTest(code=source.metadata["windows_event_id"]):
                result = analyst.triage(incident([source]))
                self.assertEqual(result["verdict"], "benign")
                self.assertEqual(result["mitre_techniques"], [])
                self.assertEqual(result["technique_evidence"], {})

    def test_repeated_techniques_merge_deduplicated_evidence_without_reordering_flat_list(self):
        primary = process()
        ctx = analyst.TriageContext(incident([primary]), [])
        ctx.technique("T1059.001", "T1027")
        ctx.technique("T1059.001", events=[primary, event(4688, "second"), primary])
        self.assertEqual(ctx.techniques, ["T1059.001", "T1027"])
        self.assertEqual(ctx.technique_evidence["T1059.001"], ["primary", "second"])

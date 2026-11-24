from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from Prognostic_Agent.contracts import canonical_json, content_hash
from Prognostic_Agent.llm_explanation import ExplanationConfig, Pseudonymizer, explain_forecast, prepare, audit_logged_payloads
from Prognostic_Agent.prognostic_agent import build_risk_forecast
from Prognostic_Agent.service import ForecastService
from Prognostic_Agent.storage import ForecastHistory
from Prognostic_Agent.config import ForecastConfig
from Prognostic_Agent.private_paths import PRIVATE_DIR
from Prognostic_Agent.tests import test_forecasting as fixture
from Prognostic_Agent.tests.fake_explanation_provider import FakeExplanationProvider


def protected(value):
    return canonical_json({k: v for k, v in value.items() if k not in {"explanation", "explanation_status", "issues"}})


class LLMExplanationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.request = fixture.alert()
        cls.baseline = fixture.run()
        if not cls.baseline.get("candidate_paths"):
            raise AssertionError("Deterministic fixture must produce candidates")

    def setUp(self):
        self.work = TemporaryDirectory(dir=PRIVATE_DIR, prefix="test-llm-")
        self.addCleanup(self.work.cleanup)
        self.directory = Path(self.work.name)
        self.config = ExplanationConfig(enabled=True, audit_directory=self.directory)

    def invoke(self, mode="success", **kwargs):
        return explain_forecast(self.baseline, self.request, config=kwargs.get("config", self.config),
                                provider=FakeExplanationProvider(mode))

    def test_success_changes_only_explanation_fields(self):
        result = self.invoke()
        self.assertEqual(result["explanation_status"], "llm_selected")
        self.assertEqual(protected(result), protected(self.baseline))
        self.assertEqual(result["issues"], self.baseline["issues"])
        self.assertEqual({k for k in result if result[k] != self.baseline[k]}, {"explanation", "explanation_status"})

    def test_invalid_shape_is_rejected(self):
        result = self.invoke("invalid")
        self.assertEqual(result["issues"][-1]["code"], "llm_output_rejected")
        self.assertEqual(result["explanation_status"], "deterministic")
        self.assertEqual(result["explanation"], self.baseline["explanation"])
        self.assertEqual(protected(result), protected(self.baseline))

    def test_number_change_and_added_technique_prose_candidate_or_clause_are_rejected(self):
        for mode in ("number", "technique", "prose", "candidate", "comment"):
            with self.subTest(mode=mode):
                result = self.invoke(mode)
                self.assertEqual(result["issues"][-1]["code"], "llm_output_rejected")
                self.assertEqual(protected(result), protected(self.baseline))
                self.assertEqual(result["explanation"], self.baseline["explanation"])

    def test_timeout_terminates_uncooperative_provider_inside_total_deadline(self):
        started = time.monotonic()
        result = self.invoke("timeout", config=replace(self.config, timeout_seconds=1.5))
        self.assertLess(time.monotonic() - started, 1.9)
        self.assertEqual(result["issues"][-1]["code"], "llm_timeout")
        self.assertEqual(protected(result), protected(self.baseline))
        self.assertEqual(result["explanation_status"], "deterministic")
        self.assertEqual(len(list(self.directory.glob("*.json"))), 1)

    def test_failure_is_redacted_and_does_not_make_assessment_partial(self):
        result = self.invoke("error")
        self.assertEqual(result["issues"][-1]["code"], "llm_provider_error")
        self.assertEqual(result["status"], self.baseline["status"])
        self.assertEqual(result["numeric_assessment_status"], self.baseline["numeric_assessment_status"])
        self.assertNotIn("sensitive provider response", canonical_json(result))
        self.assertEqual(protected(result), protected(self.baseline))

    def test_retry_uses_remaining_total_budget_and_logs_both_attempts(self):
        result = self.invoke("retry")
        self.assertEqual(result["explanation_status"], "llm_selected")
        self.assertEqual(result["explanation"]["llm"]["attempts"], 2)
        self.assertEqual(len(list(self.directory.glob("*.json"))), 2)
        self.assertEqual(protected(result), protected(self.baseline))

    def test_disabled_is_byte_identical_without_io_sdk_credentials_or_network(self):
        with patch("Prognostic_Agent.llm_explanation._invoke", side_effect=AssertionError("must not run")), \
             patch("Prognostic_Agent.llm_explanation.write_private", side_effect=AssertionError("must not log")), \
             patch("socket.socket.connect", side_effect=AssertionError("must not connect")):
            result = explain_forecast(self.baseline, self.request, config=replace(self.config, enabled=False), provider=FakeExplanationProvider("error"))
        self.assertIs(result, self.baseline)
        self.assertEqual(canonical_json(result).encode(), canonical_json(self.baseline).encode())
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_pseudonymization_round_trip_including_substrings_and_overlaps(self):
        alias = Pseudonymizer([("user", "mira"), ("user", "miranda"), ("host", "LAB-WORKSTATION"),
                               ("sid", "S-1-5-21-123-456"), ("ip", "192.0.2.123")])
        raw = "prefix-mira-suffix; miranda; LAB-WORKSTATION; S-1-5-21-123-456; 192.0.2.123"
        redacted = alias.redact(raw)
        self.assertNotIn("mira", redacted)
        self.assertIn("prefix-user_", redacted)
        self.assertEqual(alias.restore(redacted), raw)
        self.assertEqual(alias.redact(raw.upper()).lower(), redacted.lower())
        again = Pseudonymizer([("user", "miranda"), ("user", "mira"), ("ip", "192.0.2.123"),
                                ("host", "LAB-WORKSTATION"), ("sid", "S-1-5-21-123-456")])
        self.assertEqual(alias.redact(raw), again.redact(raw))

    def test_payload_journal_matches_exact_request_and_excludes_raw_evidence(self):
        request = deepcopy(self.request)
        request["normalized_events"][0]["message"] = "RAW-EVENT-DO-NOT-SEND powershell -enc PRIVATE-COMMAND"
        request["normalized_events"][0]["metadata"] = {"subject_sid": "S-1-5-21-123-456"}
        response = explain_forecast(self.baseline, request, config=self.config, provider=FakeExplanationProvider())
        self.assertEqual(response["explanation_status"], "llm_selected")
        projection, _, aliases = prepare(self.baseline, request)
        logs = list(self.directory.glob("*.json"))
        self.assertEqual(len(logs), 1)
        journal = json.loads(logs[0].read_text())
        self.assertEqual(journal["request_sha256"], content_hash(journal["request"]))
        self.assertEqual(json.loads(journal["request"]["messages"][0]["content"]), projection)
        self.assertTrue(aliases.audit(journal["request"])["clean"])
        text = logs[0].read_text()
        for secret in ("RAW-EVENT-DO-NOT-SEND", "PRIVATE-COMMAND", "S-1-5-21-123-456", request["host_id"], request["user_id"], request["source_ip"]):
            if secret:
                self.assertNotIn(secret, text)
        for name in (request["host_id"], request["user_id"]):
            if name:
                self.assertIn(name, canonical_json(response["explanation"]))
        self.assertTrue(audit_logged_payloads(self.directory, forbidden_strings=["RAW-EVENT-DO-NOT-SEND"])["clean"])

    def test_payload_audit_rejects_tampered_body(self):
        self.invoke()
        path = next(self.directory.glob("*.json"))
        journal = json.loads(path.read_text())
        journal["request"]["raw_message"] = "sensitive"
        path.write_text(json.dumps(journal))
        self.assertFalse(audit_logged_payloads(self.directory)["clean"])

    def test_core_api_opt_in_preserves_all_assessment_fields(self):
        base = build_risk_forecast(self.request, asset_provider=fixture.MemoryProvider(fixture.inventory()), forecast_as_of=fixture.AS_OF)
        result = build_risk_forecast(self.request, asset_provider=fixture.MemoryProvider(fixture.inventory()), forecast_as_of=fixture.AS_OF,
                                     explanation_config=self.config, explanation_provider=FakeExplanationProvider())
        ignored = {"generated_at", "diagnostics", "explanation", "explanation_status"}
        # Independent calls measure different asset-provider elapsed time. Strip
        # only clock observations, retaining the rest of the asset context.
        def assessment(value):
            value = deepcopy({k:v for k,v in value.items() if k not in ignored})
            for stat in value["asset_context"]["provider_stats"]:
                stat.pop("elapsed_ms", None)
            return canonical_json(value)
        self.assertEqual(assessment(base), assessment(result))
        self.assertEqual(result["explanation_status"], "llm_selected")

    def test_service_persists_and_replays_without_duplicate_llm_call(self):
        with ForecastHistory(self.directory / "history.db", environment="test") as history:
            service = ForecastService(history, config=ForecastConfig(environment="test"),
                                      explanation_config=self.config, explanation_provider=FakeExplanationProvider())
            first = service.assess(self.request, asset_provider=fixture.MemoryProvider(fixture.inventory()), forecast_as_of=fixture.AS_OF)
            second = service.assess(self.request, asset_provider=fixture.MemoryProvider(fixture.inventory()), forecast_as_of=fixture.AS_OF)
        self.assertEqual(first["explanation_status"], "llm_selected")
        self.assertTrue(second["history"]["idempotent_replay"])
        self.assertEqual(first["history"]["forecast_id"], second["history"]["forecast_id"])
        self.assertEqual(len(list(self.directory.glob("*.json"))), 1)

    def test_disabled_core_runs_with_sdk_import_and_network_blocked(self):
        with patch.dict("sys.modules", {"anthropic": None}), \
             patch("socket.socket.connect", side_effect=AssertionError("must not connect")):
            result = build_risk_forecast(self.request, asset_provider=fixture.MemoryProvider(fixture.inventory()), forecast_as_of=fixture.AS_OF,
                                         explanation_config=replace(self.config, enabled=False))
        self.assertEqual(result["risk_score"], self.baseline["risk_score"])
        self.assertEqual(result["candidate_paths"], self.baseline["candidate_paths"])
        self.assertEqual(result["explanation_status"], "deterministic")

    def test_unpseudonymizable_entity_and_alias_collision_skip_before_logging(self):
        for bad in (None, "user_1"):
            request = deepcopy(self.request)
            request["entities"][0]["entity_id"] = bad
            result = explain_forecast(self.baseline, request, config=self.config, provider=FakeExplanationProvider())
            self.assertEqual(result["issues"][-1]["code"], "llm_privacy_skipped")
            self.assertEqual(protected(result), protected(self.baseline))
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_audit_failure_skips_provider(self):
        with patch("Prognostic_Agent.llm_explanation.write_private", side_effect=OSError()), \
             patch("Prognostic_Agent.llm_explanation._invoke", side_effect=AssertionError("must not call")):
            result = self.invoke()
        self.assertEqual(result["issues"][-1]["code"], "llm_audit_unavailable")

    def test_no_candidates_means_no_call_even_when_enabled(self):
        response = deepcopy(self.baseline)
        response["candidate_paths"] = []
        self.assertIs(explain_forecast(response, self.request, config=self.config, provider=FakeExplanationProvider()), response)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_deadline_and_attempt_limits_are_validated(self):
        for values in ({"timeout_seconds": 10.1}, {"timeout_seconds": 0}, {"max_attempts": 3}, {"enabled": 1}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                ExplanationConfig(**values)

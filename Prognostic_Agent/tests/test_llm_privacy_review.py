from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import pickle
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from Prognostic_Agent import __main__ as cli
from Prognostic_Agent.contracts import validate_response
from Prognostic_Agent.llm_explanation import ExplanationConfig, Pseudonymizer, explain_forecast
from Prognostic_Agent.llm_privacy_review import run_review
from Prognostic_Agent.private_paths import PRIVATE_DIR


class LLMPrivacyReviewTests(unittest.TestCase):
    def test_configurable_haiku_default_and_cli_override(self):
        self.assertEqual(ExplanationConfig().model, "claude-haiku-5-5")
        self.assertEqual(ExplanationConfig(model="claude-sonnet-5-5").model, "claude-sonnet-5-5")
        for extra, expected in (([], "claude-haiku-5-5"), (["--llm-model", "claude-sonnet-5-5"], "claude-sonnet-5-5")):
            with patch("Prognostic_Agent.__main__.build_risk_forecast", return_value={"response_type":"risk_forecast"}) as build, redirect_stdout(io.StringIO()):
                code = cli.main(["--no-history", "--llm-explanation", "--input", str(PRIVATE_DIR.parent / "examples/analyst_alert.json"), *extra])
            self.assertEqual(code, 0)
            self.assertEqual(build.call_args.kwargs["explanation_config"].model, expected)

    def test_alias_map_cannot_be_pickled_or_encoded_as_json(self):
        mapping = Pseudonymizer([("user", "LAB\\synthetic-user")])
        with self.assertRaises(TypeError):
            pickle.dumps(mapping)
        with self.assertRaises(TypeError):
            json.dumps(mapping)

    def test_six_forecasts_and_five_payloads_have_no_alias_maps_or_identity_leaks(self):
        with TemporaryDirectory(dir=PRIVATE_DIR, prefix="test-review-") as work:
            result = run_review(Path(work) / "review")
        self.assertEqual(result["forecasts_audited"], 6)
        self.assertEqual(result["payloads_audited"], 5)
        self.assertTrue(result["all_clean"])
        self.assertFalse(any(row["alias_map_persisted"] for row in result["cases"]))
        cases = {r["case"]:r for r in result["cases"]}
        self.assertEqual(cases["complete"]["status"], "complete")
        self.assertEqual(cases["partial"]["status"], "partial")
        self.assertEqual(cases["abstained"]["status"], "abstained")
        self.assertEqual(cases["abstained"]["payloads_logged"], 0)
        self.assertEqual(cases["abstained"]["explanation_status"], "deterministic")
        self.assertTrue(cases["embedded_hostname"]["round_trip_passed"])
        self.assertEqual(cases["embedded_hostname"]["embedded_redaction"], "prefix-host_1-suffix")

    def test_credential_is_absent_from_logs_errors_and_captured_child_output(self):
        env = os.environ.copy()
        sentinel = "offline-test-credential-boundary"
        env["ANTHROPIC_API_KEY"] = sentinel
        env.pop("ANTHROPIC_AUTH_TOKEN", None)
        result = subprocess.run([sys.executable, "-B", "-m", "Prognostic_Agent.llm_privacy_review", "--credential-probe"],
                                cwd=PRIVATE_DIR.parent.parent, env=env, capture_output=True, text=True, timeout=30)
        # Boolean assertions intentionally do not dump captured content if bad.
        self.assertTrue(sentinel not in result.stdout + result.stderr, "Credential marker exposed")
        self.assertTrue(result.returncode == 0, "Offline credential boundary probe failed")
        self.assertTrue(json.loads(result.stdout)["fake_credential_probe_passed"])

    def test_disabled_does_not_access_credentials(self):
        value = {"response_type":"risk_forecast"}
        with patch("Prognostic_Agent.llm_explanation._credential_values", side_effect=AssertionError("credential access")):
            self.assertIs(explain_forecast(value, {}, config=ExplanationConfig()), value)

    def test_new_status_matches_schema_and_old_status_is_rejected(self):
        schema = json.loads((PRIVATE_DIR.parent / "schemas/response.schema.json").read_text())
        values = schema["$defs"]["forecast"]["properties"]["explanation_status"]["enum"]
        self.assertIn("llm_selected", values)
        self.assertNotIn("llm", values)
        from Prognostic_Agent.tests import test_forecasting as fixture
        response = fixture.run()
        response["explanation_status"] = "llm_selected"
        self.assertIs(validate_response(response), response)
        response["explanation_status"] = "llm"
        with self.assertRaises(ValueError):
            validate_response(response)

    def test_credential_in_request_is_blocked_before_journaling(self):
        from Prognostic_Agent.tests import test_forecasting as fixture
        from Prognostic_Agent.tests.fake_explanation_provider import FakeExplanationProvider
        request, base = fixture.alert(), fixture.run()
        with TemporaryDirectory(dir=PRIVATE_DIR, prefix="test-secret-") as work:
            sentinel = "offline-test-secret-model"
            with patch.dict(os.environ, {"ANTHROPIC_API_KEY":sentinel}):
                result = explain_forecast(base, request, config=ExplanationConfig(enabled=True, model="claude-"+sentinel, audit_directory=Path(work)), provider=FakeExplanationProvider())
            self.assertEqual(result["issues"][-1]["code"], "llm_credential_skipped")
            self.assertFalse(list(Path(work).iterdir()))
            self.assertTrue(sentinel not in json.dumps(result), "Credential marker exposed")

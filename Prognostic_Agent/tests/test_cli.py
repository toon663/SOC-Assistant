import json
import os
import subprocess
import sys
import unittest
from tempfile import TemporaryDirectory
from pathlib import Path

from Prognostic_Agent.tests.test_contracts import ROOT
from Prognostic_Agent import build_risk_forecast
from Prognostic_Agent.asset_context import LocalJSONAssetProvider


class CLITests(unittest.TestCase):
    def command(self, *args, input=None):
        return subprocess.run([sys.executable, "-B", "-S", "-m", "Prognostic_Agent", *map(str, args)],
                              input=input, capture_output=True, text=True, cwd=ROOT.parent, timeout=15)

    def test_cli_works_with_no_api_credentials_and_does_not_write_by_default(self):
        def storage_snapshot():
            return sorted((str(path.relative_to(ROOT)), path.stat().st_size, path.stat().st_mtime_ns)
                          for path in (ROOT / "storage").rglob("*") if path.is_file())
        before = storage_snapshot()
        env = {key: value for key, value in os.environ.items() if "API_KEY" not in key}
        # -S disables site-packages: the CLI must work without installed SDKs.
        command = [sys.executable, "-B", "-S", "-m", "Prognostic_Agent", "--input", str(ROOT / "examples" / "analyst_alert.json"),
                   "--asset-inventory", str(ROOT / "assets" / "sample_asset_inventory.json"),
                   "--as-of", "2026-11-23T12:00:00Z", "--no-llm", "--no-history"]
        result = subprocess.run(command, capture_output=True, text=True, env=env, cwd=ROOT.parent, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output["status"], "complete")
        self.assertEqual(output["explanation_status"], "deterministic")
        self.assertEqual(before, storage_snapshot())
        payload = json.loads((ROOT / "examples" / "analyst_alert.json").read_text(encoding="utf-8"))
        expected = build_risk_forecast(payload, asset_provider=LocalJSONAssetProvider(ROOT / "assets" / "sample_asset_inventory.json"), forecast_as_of="2026-11-23T12:00:00Z")
        output.pop("generated_at")
        expected.pop("generated_at")
        for item in (output, expected):
            item["diagnostics"].pop("total_ms")
            item["diagnostics"].pop("stage_timings_ms")
            item["asset_context"].pop("provider_stats")
        self.assertEqual(output, expected)

    def test_invalid_json_has_machine_readable_error_and_exit_two(self):
        result = subprocess.run([sys.executable, "-B", "-m", "Prognostic_Agent", "--no-history"], input="{", capture_output=True,
                                text=True, cwd=ROOT.parent, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["response_type"], "validation_error")

    def test_alternate_rule_weight_paths_and_error_provenance(self):
        with TemporaryDirectory(prefix="test-cli-", dir=ROOT) as directory:
            directory = Path(directory)
            rules = json.loads((ROOT / "rules/attack_transitions.json").read_text())
            weights = json.loads((ROOT / "rules/scoring_weights.json").read_text())
            rules["version"], weights["version"] = "test-rules", "test-weights"
            rules_path, weights_path = directory / "rules.json", directory / "weights.json"
            rules_path.write_text(json.dumps(rules), encoding="utf-8")
            weights_path.write_text(json.dumps(weights), encoding="utf-8")
            for input, expected in (("{}", "validation_error"), ("{", "validation_error")):
                result = self.command("--no-history", "--rules-path", rules_path, "--weights-path", weights_path, input=input)
                output = json.loads(result.stdout)
                self.assertEqual(output["response_type"], expected)
                self.assertEqual(output["versions"]["rules"], "test-rules")
                self.assertEqual(output["versions"]["weights"], "test-weights")
            result = self.command("--no-history", "--weights-path", directory / "missing.json", "--input", ROOT / "examples/analyst_alert.json")
            output = json.loads(result.stdout)
            self.assertEqual(result.returncode, 1)
            self.assertIsNone(output["versions"]["weights"])
            self.assertIn("config_version", output)

    def test_history_report_exports_purge_and_operational_attempt_logging(self):
        with TemporaryDirectory(prefix="test-cli-", dir=ROOT) as directory:
            directory = Path(directory)
            database = directory / "history.db"
            request = json.loads((ROOT / "examples/analyst_alert.json").read_text())
            request["observed_techniques"][0]["technique_id"] = "T1486"
            flags = ["--history-db", database]
            first = json.loads(self.command(*flags, "--as-of", "2026-11-23T12:00:00Z", input=json.dumps(request)).stdout)
            second = json.loads(self.command(*flags, "--as-of", "2026-11-23T12:00:00Z", input=json.dumps(request)).stdout)
            self.assertEqual(first["history"]["forecast_id"], second["history"]["forecast_id"])
            result = self.command("history", *flags, "--alert-id", request["alert_id"])
            self.assertEqual(len(json.loads(result.stdout)["items"]), 1)
            for format in ("json", "csv"):
                path = directory / ("unsupported." + format)
                result = self.command("unsupported-report", *flags, "--format", format, "--report-output", path)
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertTrue(path.exists())
            result = self.command(*flags, "--min-candidate-score", "2", input="{}")
            self.assertEqual(result.returncode, 1)
            output = json.loads(result.stdout)
            self.assertIsNone(output["versions"]["config_hash"])
            report = json.loads(self.command("shadow-report", *flags).stdout)
            self.assertEqual(report["attempt_count"], 3)
            self.assertEqual(report["idempotent_replays"], 1)
            self.assertEqual(self.command("purge", *flags).returncode, 0)

    def test_cli_environment_tags_and_report_filters(self):
        with TemporaryDirectory(prefix="test-cli-", dir=ROOT) as directory:
            database = Path(directory) / "history.db"
            request = json.loads((ROOT / "examples/analyst_alert.json").read_text())
            request["observed_techniques"][0]["technique_id"] = "T1486"
            for environment in ("test", "production"):
                result = self.command("--history-db", database, "--environment", environment, input=json.dumps(request))
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertEqual(json.loads(result.stdout)["environment"], environment)
            report = json.loads(self.command("unsupported-report", "--history-db", database, "--environment", "production").stdout)
            self.assertEqual([row["environment"] for row in report["items"]], ["production"])
            combined = json.loads(self.command("unsupported-report", "--history-db", database, "--report-environment", "all").stdout)
            self.assertEqual({row["environment"] for row in combined["items"]}, {"test", "production"})


if __name__ == "__main__":
    unittest.main()

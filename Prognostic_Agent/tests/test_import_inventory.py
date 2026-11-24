from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from Prognostic_Agent.asset_context import LocalJSONAssetProvider, _validate_record
from Prognostic_Agent.config import AGENT_DIR, ForecastConfig
from Prognostic_Agent.contracts import AnalystAlert, parse_time
from Prognostic_Agent.importers.core import convert_bytes, import_inventory
from Prognostic_Agent.scoring import load_weights
from Prognostic_Agent.transition_rules import forecast_risk_path, load_rules
from Prognostic_Agent.tests.test_contracts import alert
from Prognostic_Agent.tests.test_forecasting import inventory as legacy_inventory

COLLECTED = "2026-11-23T12:00:00Z"
IMPORTED = "2026-11-23T12:01:00Z"
LOCAL_SID = "S-1-5-21-101-102-103-1001"


def raw_export():
    return {"schema": "local_context_raw.v1", "collected_at": COLLECTED, "collector": "export_local_context.ps1",
            "run_as_admin": False, "host": {"hostname": "LAB-PC", "platform": "windows", "domain_joined": True,
                "domain_or_workgroup": "LAB", "os_caption": "Windows Lab", "os_version": "10", "os_build": "1"},
            "accounts": [{"name": "alice", "sid": LOCAL_SID, "disabled": False, "locked_out": False,
                          "last_logon": "2020-01-01T00:00:00Z", "password_required": True},
                         {"name": "bob", "sid": "S-1-5-21-101-102-103-1002", "disabled": True, "locked_out": False}],
            "groups": {"administrators": [
                {"name": "LAB-PC\\alice", "sid": LOCAL_SID, "object_class": "User", "source": "Local"},
                {"name": "LAB\\carol", "sid": "S-1-5-21-201-202-203-1001", "object_class": "User", "source": "ActiveDirectory"},
                {"name": "LAB\\Domain Admins", "sid": "S-1-5-21-201-202-203-512", "object_class": "Group", "source": "ActiveDirectory"}],
                "remote_desktop_users": []},
            "addresses": [{"ip": "10.0.0.2", "interface": "Ethernet"}],
            "listeners": [{"port": 445, "bind_address": "0.0.0.0", "process": "System"}],
            "firewall_profiles": [{"profile": "Public", "enabled": False, "default_inbound_action": "Allow"}],
            "errors": []}


def convert(value=None, **kwargs):
    return convert_bytes(json.dumps(value if value is not None else raw_export()).encode("utf-8-sig"),
                         adapter_name="local_export", source_path="synthetic/local.json", environment="test",
                         imported_at=IMPORTED, **kwargs)


class InventoryImportTests(unittest.TestCase):
    def test_local_admin_scope_domain_null_provenance_and_no_edges(self):
        document = raw_export()
        encoded = json.dumps(document).encode("utf-8-sig")
        result, issues = convert(document)
        records = {record["entity_id"]: record for record in result["entities"]}
        admin = records["user:lab-pc\\alice"]
        self.assertEqual(admin["privilege_level"], "admin")
        self.assertEqual(admin["privilege_scope_host_ids"], ["host:lab-pc"])
        self.assertIsNone(records["user:lab\\carol"]["privilege_level"])
        self.assertIsNone(records["user:bob"]["privilege_level"])
        self.assertEqual(records["user:alice"]["canonical_id"], admin["canonical_id"])
        self.assertTrue(all("related_assets" not in record for record in records.values()))
        self.assertTrue(all(record["as_of"] == COLLECTED and record["last_updated"] is None for record in records.values()))
        self.assertTrue(all(record["asset_criticality"] is None and record["exposure"] is None for record in records.values()))
        self.assertEqual(admin["provenance"]["source_sha256"], hashlib.sha256(encoded).hexdigest())
        self.assertEqual(issues["quarantine"], [])
        self.assertTrue(all(record["environment"] == "test" for record in records.values()))
        for record in records.values():
            _validate_record(record, record["entity_id"], parse_time(IMPORTED), ForecastConfig())

    def test_microsoft_linked_principal_with_verified_local_sid_remains_host_scoped(self):
        value = raw_export()
        value["groups"]["administrators"][0]["source"] = "MicrosoftAccount"
        result, _ = convert(value)
        admin = next(row for row in result["entities"] if row["entity_id"] == "user:alice")
        self.assertEqual(admin["privilege_level"], "admin")
        self.assertEqual(admin["privilege_scope_host_ids"], ["host:lab-pc"])

    def test_domain_groups_remain_null_and_are_not_expanded_into_users(self):
        result, _ = convert()
        self.assertNotIn("user:lab\\domain admins", {row["entity_id"] for row in result["entities"]})
        host = next(row for row in result["entities"] if row["entity_type"] == "host")
        group = host["source_attributes"]["administrator_principals"][2]
        self.assertIsNone(group["privilege_level"])

    def test_collection_error_is_quarantined_and_admin_failure_cannot_grant_privilege(self):
        value = raw_export()
        value["errors"] = [{"section": "group:S-1-5-32-544", "message": "Access denied"}]
        result, issues = convert(value)
        self.assertEqual(issues["status"], "partial")
        self.assertEqual(issues["quarantine"][0]["code"], "collection_failed")
        self.assertEqual(issues["quarantine"][0]["source_locator"], "$.errors[0]")
        self.assertEqual(issues["quarantine"][0]["section"], "group:S-1-5-32-544")
        self.assertTrue(all(row["privilege_level"] is None for row in result["entities"]))

    def test_missing_group_is_distinct_from_collection_failure_and_does_not_invent_edges(self):
        value = raw_export()
        value["groups"]["remote_desktop_users"] = None
        value["errors"] = [{"section": "group:S-1-5-32-555", "message": "Group S-1-5-32-555 was not found."}]
        result, issues = convert(value)
        self.assertEqual(issues["quarantine"], [])
        not_found = next(item for item in issues["issues"] if item["code"] == "group_not_found")
        self.assertEqual(not_found["source_status"], "not_present")
        self.assertTrue(all("related_assets" not in row for row in result["entities"]))
        for message in ("Access denied", "RPC server unavailable", "Group enumeration was not found in cache"):
            value["errors"][0]["message"] = message
            _, issues = convert(value)
            self.assertEqual(issues["quarantine"][0]["code"], "collection_failed")
            self.assertEqual(issues["quarantine"][0]["source_status"], "unavailable")

    def test_conflicting_local_sid_and_domain_source_is_not_used_as_admin(self):
        value = raw_export()
        value["groups"]["administrators"][0]["source"] = "ActiveDirectory"
        result, issues = convert(value)
        self.assertIn("principal_source_conflict", {row["code"] for row in issues["quarantine"]})
        self.assertIsNone(next(row for row in result["entities"] if row["entity_id"] == "user:alice")["privilege_level"])

    def test_boolean_strings_are_unknown_and_password_or_logon_dates_do_not_become_update_dates(self):
        value = raw_export()
        value["accounts"][0]["disabled"] = "False"
        value["accounts"][0]["locked_out"] = "False"
        result, issues = convert(value)
        account = next(row for row in result["entities"] if row["entity_id"] == "user:alice")
        self.assertIsNone(account["account_controls"]["enabled"])
        self.assertIsNone(account["account_controls"]["locked"])
        self.assertIsNone(account["account_controls"]["blocked"])
        self.assertIsNone(account["last_updated"])
        self.assertIn("invalid_optional_boolean", {row["code"] for row in issues["issues"]})

    def test_missing_naive_and_future_collection_times_quarantine_document(self):
        for timestamp in (None, "bad", "2026-11-23T12:00:00", "2026-11-24T12:00:00Z"):
            value = raw_export()
            value["collected_at"] = timestamp
            result, issues = convert(value)
            self.assertFalse(result["publishable"])
            self.assertEqual(result["entities"], [])
            self.assertEqual(issues["status"], "quarantined")

    def test_unsupported_schema_and_nonfinite_json_quarantine_document(self):
        for value in ({**raw_export(), "schema": "other.v1"}, {**raw_export(), "bad": float("nan")}):
            result, issues = convert(value)
            self.assertEqual(result["entities"], [])
            self.assertEqual(issues["quarantine"][0]["code"], "document_quarantined")

    def test_alias_collisions_quarantine_all_ambiguous_source_records(self):
        value = raw_export()
        duplicate = deepcopy(value["accounts"][0])
        duplicate["sid"] = "S-1-5-21-101-102-103-1999"
        value["accounts"].append(duplicate)
        result, issues = convert(value)
        self.assertNotIn("user:alice", {row["entity_id"] for row in result["entities"]})
        self.assertEqual(sum(row["code"] == "identity_collision" for row in issues["quarantine"]), 2)

    def test_powershell_singleton_collections_and_missing_groups_are_safe(self):
        value = raw_export()
        value["accounts"] = value["accounts"][0]
        value["groups"]["administrators"] = value["groups"]["administrators"][0]
        result, issues = convert(value)
        self.assertEqual(next(row for row in result["entities"] if row["entity_id"] == "user:alice")["privilege_level"], "admin")
        self.assertIn("singleton_collection_normalized", {row["code"] for row in issues["issues"]})
        self.assertEqual(next(row for row in result["entities"] if row["entity_id"] == "user:alice")["provenance"]["source_locator"], "$.accounts")
        value["groups"]["administrators"] = None
        result, _ = convert(value)
        self.assertTrue(all(row["privilege_level"] is None for row in result["entities"]))

    def test_invalid_identity_is_quarantined_without_discarding_valid_host(self):
        value = raw_export()
        value["accounts"][0]["sid"] = None
        result, issues = convert(value)
        self.assertTrue(result["publishable"])
        self.assertIn("invalid_principal_identity", {row["code"] for row in issues["quarantine"]})

    def test_import_time_requires_an_explicit_timezone(self):
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            convert_bytes(b"{}", adapter_name="local_export", source_path="unused", environment="test",
                          imported_at=datetime(2026, 11, 23, 12, 1))

    def test_files_are_versioned_source_is_unchanged_and_provider_reads_nulls(self):
        with TemporaryDirectory(prefix="test-import-", dir=AGENT_DIR) as name:
            directory = Path(name).resolve()
            self.assertTrue(directory.is_relative_to(AGENT_DIR))
            source = directory / "raw.json"
            original = json.dumps(raw_export()).encode("utf-8-sig")
            source.write_bytes(original)
            first = import_inventory(source, environment="test", output_root=directory / "out", imported_at=IMPORTED)
            second = import_inventory(source, environment="test", output_root=directory / "out", imported_at=IMPORTED)
            self.assertNotEqual(first["inventory_path"], second["inventory_path"])
            self.assertEqual(source.read_bytes(), original)
            self.assertTrue(Path(first["issues_path"]).is_file())
            record = LocalJSONAssetProvider(first["inventory_path"]).lookup({"entity_id": "user:alice"}, deadline=0)
            self.assertIsNone(record["asset_criticality"])
            self.assertNotIn("related_assets", record)

    def test_output_scope_and_unimplemented_ad_adapter_are_explicit(self):
        with self.assertRaisesRegex(ValueError, "inside Prognostic_Agent"):
            import_inventory("unused", environment="test", output_root=AGENT_DIR.parent / "outside-import")
        with self.assertRaisesRegex(ValueError, "documented follow-up"):
            convert_bytes(b"{}", adapter_name="ad_csv", source_path="unused", environment="test")

    def test_import_cli_requires_no_optional_packages(self):
        with TemporaryDirectory(prefix="test-import-cli-", dir=AGENT_DIR) as name:
            directory = Path(name).resolve()
            self.assertTrue(directory.is_relative_to(AGENT_DIR))
            source = directory / "raw.json"
            source.write_text(json.dumps(raw_export()), encoding="utf-8")
            result = subprocess.run([sys.executable, "-B", "-S", "-m", "Prognostic_Agent.import_inventory",
                "--input", str(source), "--environment", "test", "--output-root", str(directory / "out")],
                cwd=AGENT_DIR.parent, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["environment"], "test")

    def test_privilege_from_another_host_cannot_satisfy_execution_prerequisites(self):
        request = AnalystAlert.from_dict(alert()).data
        config = ForecastConfig()
        records = legacy_inventory()
        records["user:alice"]["privilege_scope_host_ids"] = ["host:other"]
        records["host:workstation-01"]["privilege_level"] = None
        for record in records.values():
            record.update(stale=False, provider="test")
        def assess():
            return forecast_risk_path(request, {"entities": list(records.values())}, {}, config,
                parse_time("2026-11-23T12:00:00Z"), load_rules(config.rules_path), load_weights(config.weights_path))
        self.assertFalse(assess()["candidate_paths"])
        records["user:alice"]["privilege_scope_host_ids"] = ["host:workstation-01"]
        self.assertTrue(assess()["candidate_paths"])

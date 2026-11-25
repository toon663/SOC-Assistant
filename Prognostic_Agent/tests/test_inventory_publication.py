from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from Prognostic_Agent.importers.core import import_inventory
from Prognostic_Agent.inventory_publication import collected_inventory, publish_inventory
from Prognostic_Agent.operator_overlay import apply_overlay
from Prognostic_Agent.orchestrator_client import OrchestratorClientConfig, OrchestratorForecastClient
from Prognostic_Agent.private_paths import PRIVATE_DIR
from Prognostic_Agent.tests.test_import_inventory import raw_export
from Prognostic_Agent.tests.test_orchestrator_client import incident, fake_transport
from Prognostic_Agent.tests.test_orchestrator_contract import AS_OF


class InventoryPublicationTests(unittest.TestCase):
    def setUp(self):
        self.work=TemporaryDirectory(dir=PRIVATE_DIR,prefix="test-inventory-publication-")
        self.addCleanup(self.work.cleanup)
        self.root=Path(self.work.name)
        self.now=datetime.now(timezone.utc)
        raw=raw_export();raw["collected_at"]=(self.now-timedelta(minutes=1)).isoformat()
        self.raw=self.root/"raw.json";self.raw.write_text(json.dumps(raw))
        self.overlay=self.root/"overlay.json"
        self.overlay.write_text(json.dumps({"schema_version":1,"environment":"test","approved_at":(self.now-timedelta(minutes=2)).isoformat(),"provenance":{"source":"operator"},"hosts":[{"host_id":"host:lab-pc","asset_criticality":"normal"}]}))
        imported=import_inventory(self.raw,environment="test",output_root=self.root/"imports")
        effective=apply_overlay(imported["inventory_path"],self.overlay,self.root/"effective")
        self.inventory=Path(effective["inventory_path"])
        self.destination=self.root/"inventory-latest.json"
        self.original=self.inventory.read_bytes()

    def publish(self):
        return publish_inventory(self.inventory,self.raw,self.overlay,destination=self.destination,now=self.now)

    def test_publication_replaces_exact_bytes_after_flush_preserving_collection_and_hashes(self):
        self.destination.write_bytes(b"previous")
        import os
        replace=os.replace
        def inspect(source,destination):
            self.assertEqual(self.destination.read_bytes(),b"previous")
            self.assertEqual(Path(source).read_bytes(),self.original)
            self.assertEqual(Path(source).parent,self.destination.parent)
            replace(source,destination)
        with patch("Prognostic_Agent.inventory_publication.os.replace",side_effect=inspect) as operation:
            result=self.publish()
        operation.assert_called_once()
        self.assertEqual(self.destination.read_bytes(),self.original)
        self.assertEqual(result["inventory_file_sha256"],hashlib.sha256(self.original).hexdigest())
        self.assertEqual(result["collected_at"],json.loads(self.original)["source"]["collected_at"])
        self.assertEqual(list(self.root.glob(".*.tmp")),[])

    def test_rejected_publications_leave_previous_bytes_and_timestamp_untouched(self):
        self.publish();before=self.destination.read_bytes();mtime=self.destination.stat().st_mtime_ns
        for change in ("unpublishable","hash","overlay","stale","timestamp","corrupt"):
            with self.subTest(change=change):
                document=json.loads(self.original)
                if change=="unpublishable":document["publishable"]=False
                elif change=="hash":document["source"]["source_sha256"]="0"*64
                elif change=="overlay":document["entities"][0]["asset_criticality"]="critical"
                elif change=="stale":document["source"]["collected_at"]=(self.now-timedelta(hours=25)).isoformat()
                elif change=="timestamp":document["source"].pop("collected_at")
                # For overlay mutation target all hosts, including aliases.
                if change=="overlay":
                    for entity in document["entities"]:
                        if entity["entity_type"]=="host":entity["asset_criticality"]="critical"
                self.inventory.write_bytes(b"{" if change=="corrupt" else json.dumps(document).encode())
                with self.assertRaises((ValueError,KeyError)):self.publish()
                self.assertEqual(self.destination.read_bytes(),before)
                self.assertEqual(self.destination.stat().st_mtime_ns,mtime)

    def test_replace_failure_preserves_latest_and_removes_temporary(self):
        self.destination.write_bytes(b"previous")
        with patch("Prognostic_Agent.inventory_publication.os.replace",side_effect=PermissionError()):
            with self.assertRaises(PermissionError):self.publish()
        self.assertEqual(self.destination.read_bytes(),b"previous")
        self.assertEqual(list(self.root.glob(".*.tmp")),[])

    def test_client_fresh_stale_missing_corrupt_and_invalid_timestamp_files(self):
        client=OrchestratorForecastClient(OrchestratorClientConfig(inventory_path=self.inventory,history_path=self.root/"history.db"),transport=fake_transport)
        self.assertEqual(client.assess(incident(),forecast_as_of=AS_OF)["response_type"],"risk_forecast")
        for change in ("stale","missing","corrupt","no_timestamp","invalid_timestamp","future"):
            with self.subTest(change=change):
                document=json.loads(self.original)
                if change=="stale":document["source"]["collected_at"]=(self.now-timedelta(hours=25)).isoformat()
                elif change=="no_timestamp":document["source"].pop("collected_at")
                elif change=="invalid_timestamp":document["source"]["collected_at"]="not-a-time"
                elif change=="future":document["source"]["collected_at"]=(self.now+timedelta(hours=1)).isoformat()
                self.inventory.write_bytes(b"{" if change=="corrupt" else json.dumps(document).encode())
                if change=="missing":self.inventory.unlink()
                transport=Mock(side_effect=AssertionError("No forecast call"));client.transport=transport
                before=incident()
                result=client.assess(before,forecast_as_of=AS_OF)
                transport.assert_not_called()
                self.assertEqual(result["response_type"],"operational_error")
                self.assertEqual(result["reason"],"inventory_stale")
                self.assertIsNone(result["risk_score"])
                self.assertEqual(before,incident())

    def test_exact_24_hours_is_allowed_but_one_microsecond_older_is_not(self):
        document=json.loads(self.original)
        document["source"]["collected_at"]=(self.now-timedelta(hours=24)).isoformat()
        raw=json.dumps(document).encode()
        self.assertTrue(collected_inventory(raw,now=self.now))
        with self.assertRaises(ValueError):collected_inventory(raw,now=self.now+timedelta(microseconds=1))

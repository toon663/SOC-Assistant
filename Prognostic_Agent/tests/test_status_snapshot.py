import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock

from Prognostic_Agent.private_paths import PRIVATE_DIR
from Prognostic_Agent.snapshot_orchestrator_status import snapshot_status


class StatusSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.work=TemporaryDirectory(dir=PRIVATE_DIR,prefix="test-status-snapshot-")
        self.addCleanup(self.work.cleanup)
        self.root=Path(self.work.name)

    def test_get_only_unique_private_snapshots_retain_compatible_response(self):
        opener=Mock()
        value={"model_loaded":False,"decided_by":"rules_fallback","prognostic_observer":{"mode":"shadow","environment":"test","counts":{}}}
        opener.open.side_effect=lambda *args,**kwargs:io.BytesIO(json.dumps(value).encode())
        first=snapshot_status(output_dir=self.root,opener=opener)
        second=snapshot_status(output_dir=self.root,opener=opener)
        self.assertNotEqual(first,second)
        result=json.loads(first.read_text())
        self.assertEqual(result["prognostic_observer"],value["prognostic_observer"])
        self.assertEqual(result["snapshot_metadata"]["method"],"GET")
        for call in opener.open.call_args_list:
            self.assertEqual(call.args[0].get_method(),"GET")
            self.assertIsNone(call.args[0].data)

    def test_remote_redirect_credentials_and_wrong_endpoint_are_refused(self):
        opener=Mock()
        for url in ("http://example.invalid/orchestrator/status","http://name:secret@localhost:8000/orchestrator/status","http://localhost:8000/other"):
            with self.assertRaises(ValueError):snapshot_status(url=url,output_dir=self.root,opener=opener)
        opener.open.assert_not_called()
        from Prognostic_Agent.snapshot_orchestrator_status import NoRedirect
        with self.assertRaises(ValueError):NoRedirect().redirect_request(None,None,302,"",{},"http://example.invalid")

    def test_corrupt_oversized_and_unavailable_status_write_no_snapshot(self):
        for raw in (b"{",b"x"*65537,b"{}"):
            opener=Mock();opener.open.return_value=io.BytesIO(raw)
            with self.assertRaises(ValueError):snapshot_status(output_dir=self.root,opener=opener)
        opener=Mock();opener.open.side_effect=OSError("unavailable")
        with self.assertRaises(OSError):snapshot_status(output_dir=self.root,opener=opener)
        self.assertEqual(list(self.root.glob("*.json")),[])

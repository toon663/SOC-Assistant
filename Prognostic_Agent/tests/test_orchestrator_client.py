from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from Prognostic_Agent.contracts import AnalystAlert
from Prognostic_Agent.orchestrator_client import OrchestratorClientConfig, OrchestratorForecastClient
from Prognostic_Agent.orchestrator_contract import empty_record
from Prognostic_Agent.orchestrator_shadow_log import ShadowDecisionLog
from Prognostic_Agent.private_paths import PRIVATE_DIR
from Prognostic_Agent.synthetic_demo import FIXTURE_DIR
from Prognostic_Agent.tests.test_orchestrator_contract import AS_OF, record
from Prognostic_Agent.tests.test_orchestrator_advisory import options


def incident():
    value=json.loads((FIXTURE_DIR/"incident.json").read_text())
    settings=json.loads((FIXTURE_DIR/"settings.json").read_text())
    value["risk_analysis"]["behavioral_score"]=settings["behavioral_score"]
    value["risk_analysis"]["technique_evidence"]=settings["technique_evidence"]
    return value


def fake_transport(request, *, deadline):
    reply=record()
    alert=AnalystAlert.from_dict(request["alert"])
    reply.update(alert_id=alert.data["alert_id"],analyst_revision=alert.data["analyst_revision"],input_fingerprint=alert.input_fingerprint,
                 request_id=request["request_id"],environment=request["environment"])
    return reply


class OrchestratorClientTests(unittest.TestCase):
    def setUp(self):
        self.work=TemporaryDirectory(dir=PRIVATE_DIR,prefix="test-orchestrator-client-");self.addCleanup(self.work.cleanup)
        self.root=Path(self.work.name)
        inventory=json.loads((FIXTURE_DIR/"inventory.json").read_text())
        inventory["source"]={"collected_at":datetime.now(timezone.utc).isoformat()}
        path=self.root/"inventory.json";path.write_text(json.dumps(inventory))
        self.config=OrchestratorClientConfig(inventory_path=path,history_path=self.root/"history.db",timeout_seconds=8)

    def test_benign_skips_before_adapter_inventory_history_and_worker_and_is_counted(self):
        value={"incident_id":"benign-fixture","risk_analysis":{"verdict":"benign"}}
        config=replace(self.config,inventory_path=self.root/"does-not-exist.json")
        client=OrchestratorForecastClient(config)
        with patch.object(client,"_run_worker",side_effect=AssertionError("must not call forecast")), \
             patch("Prognostic_Agent.orchestrator_client.adapt_analyst_incident",side_effect=AssertionError("must not adapt")):
            result=client.assess_and_log(value,options(),shadow_log=ShadowDecisionLog(self.root/"decisions"))
        self.assertEqual(result["assessment"]["response_type"],"skipped_benign")
        self.assertIsNone(result["assessment"]["risk_score"])
        self.assertEqual(ShadowDecisionLog(self.root/"decisions").summary()["notification_skipped_count"],1)
        self.assertFalse(self.config.history_path.exists())

    def test_actual_local_worker_forecast_is_persisted_and_deterministic(self):
        client=OrchestratorForecastClient(self.config)
        result=client.assess(incident(),forecast_as_of=AS_OF)
        self.assertEqual(result["response_type"],"risk_forecast",result["reason"])
        self.assertEqual(result["status"],"complete")
        self.assertEqual(result["explanation_status"],"deterministic")
        self.assertEqual(result["risk_score"],72)
        self.assertTrue(self.config.history_path.is_file())
        repeated=client.assess(incident(),forecast_as_of=AS_OF)
        self.assertEqual(result["forecast_id"],repeated["forecast_id"])
        self.assertEqual(result["forecast_revision"],repeated["forecast_revision"])

    def test_fake_transport_and_revision_mismatch(self):
        client=OrchestratorForecastClient(self.config,transport=fake_transport)
        self.assertEqual(client.assess(incident(),forecast_as_of=AS_OF)["status"],"complete")
        def bad(request,*,deadline):
            value=fake_transport(request,deadline=deadline);value["analyst_revision"]="wrong";return value
        value=OrchestratorForecastClient(self.config,transport=bad).assess(incident(),forecast_as_of=AS_OF)
        self.assertEqual(value["reason"],"forecast_contract_invalid")
        self.assertIsNone(value["risk_score"])

    def test_timeout_unavailable_and_malformed_reply_are_no_forecast(self):
        def timeout(*args,**kwargs):raise TimeoutError()
        def unavailable(*args,**kwargs):raise ImportError("must not expose details")
        def malformed(*args,**kwargs):return {}
        for transport,expected in ((timeout,"forecast_timeout"),(unavailable,"forecast_unavailable"),(malformed,"forecast_contract_invalid")):
            result=OrchestratorForecastClient(self.config,transport=transport).assess(incident(),forecast_as_of=AS_OF)
            self.assertEqual(result["reason"],expected)
            self.assertIsNone(result["risk_score"])
            self.assertIsNone(result["status"])
            self.assertNotIn("must not expose",json.dumps(result))

    def test_real_worker_timeout_terminates_process(self):
        config=replace(self.config,timeout_seconds=1.5)
        client=OrchestratorForecastClient(config)
        command=[sys.executable,"-B","-c","import sys,time; sys.stdin.read(); time.sleep(30)"]
        started=time.monotonic()
        with patch.object(client,"_command",return_value=command):
            result=client.assess(incident(),forecast_as_of=AS_OF)
        self.assertEqual(result["reason"],"forecast_timeout")
        self.assertLess(time.monotonic()-started,2.0)

    def test_timeout_terminates_worker_descendants(self):
        pid_path=self.root/"child.pid"
        script=("import sys,subprocess,time,pathlib; sys.stdin.read(); "
                "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
                "pathlib.Path("+repr(str(pid_path))+").write_text(str(p.pid)); time.sleep(30)")
        client=OrchestratorForecastClient(replace(self.config,timeout_seconds=2))
        with patch.object(client,"_command",return_value=[sys.executable,"-B","-c",script]):
            result=client.assess(incident(),forecast_as_of=AS_OF)
        self.assertEqual(result["reason"],"forecast_timeout")
        self.assertTrue(pid_path.exists(),"Descendant fixture must have started")
        pid=int(pid_path.read_text())
        if sys.platform=="win32":
            import ctypes as c
            from ctypes import wintypes as w
            kernel=c.WinDLL('kernel32',use_last_error=True)
            kernel.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];kernel.OpenProcess.restype=w.HANDLE
            kernel.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];kernel.CloseHandle.argtypes=[w.HANDLE]
            handle=kernel.OpenProcess(0x100000,False,pid)
            try:
                self.assertTrue(not handle or kernel.WaitForSingleObject(handle,500)==0,"Descendant must be terminated")
            finally:
                if handle:kernel.CloseHandle(handle)
        else:
            import os
            try:os.kill(pid,0)
            except ProcessLookupError:return
            stat=Path('/proc')/str(pid)/'stat'
            self.assertTrue(stat.exists() and stat.read_text().split()[2]=='Z',"Descendant must not be running")

    def test_missing_inventory_and_invalid_incident(self):
        result=OrchestratorForecastClient(replace(self.config,inventory_path=None)).assess(incident(),forecast_as_of=AS_OF)
        self.assertEqual(result["reason"],"asset_inventory_unavailable")
        result=OrchestratorForecastClient(self.config).assess({},forecast_as_of=AS_OF)
        self.assertEqual(result["response_type"],"validation_error")

    def test_history_failure_does_not_return_computed_score(self):
        blocked=self.root/"blocked";blocked.write_text("not a directory")
        result=OrchestratorForecastClient(replace(self.config,history_path=blocked/"history.db")).assess(incident(),forecast_as_of=AS_OF)
        self.assertEqual(result["response_type"],"operational_error")
        self.assertIsNone(result["risk_score"])

    def test_log_failure_does_not_change_assessment_or_execute(self):
        client=OrchestratorForecastClient(self.config,transport=fake_transport)
        log=ShadowDecisionLog(self.root/"logs")
        with patch.object(log,"record",side_effect=OSError("private path must not be returned")):
            result=client.assess_and_log(incident(),options(),shadow_log=log,forecast_as_of=AS_OF)
        self.assertEqual(result["assessment"]["status"],"complete")
        self.assertEqual(result["log_error"],"shadow_log_unavailable")

    def test_production_historical_override_is_refused(self):
        result=OrchestratorForecastClient(replace(self.config,environment="production"),transport=fake_transport).assess(incident(),forecast_as_of=AS_OF)
        self.assertEqual(result["reason"],"production_historical_cutoff_refused")

    def test_client_config_refuses_backend_history_and_invalid_timeout(self):
        for values in ({"timeout_seconds":True},{"timeout_seconds":0},{"timeout_seconds":float("inf")},
                       {"history_path":self.root/"soc_agents.db"},{"history_path":PRIVATE_DIR.parent.parent/"backend/other.db"}):
            with self.assertRaises(ValueError):OrchestratorClientConfig(**values)

"""Real legacy Orchestrator/API, detached fake clients, in-memory actuator spies."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import threading
import unittest
from unittest.mock import Mock, patch

FIXED = "2026-11-24T12:00:00+00:00"
LEGACY_APPROVAL_SHA256 = '3cfaee59b60617e9d14a79294ef7fa078fa0f7775d384635b8b808b1a9e3a208'
LEGACY_EXECUTED_SHA256 = '197b8567da9a49f640393c7bdda5a41df6489bc74f4258fdc7ba6bbff0bed7d7'


def _frame(incident):
    from Prognostic_Agent.analyst_adapter import adapt_analyst_incident
    from Prognostic_Agent.config import ForecastConfig
    from Prognostic_Agent.contracts import AnalystAlert
    from Prognostic_Agent.orchestrator_contract import empty_record
    from Prognostic_Agent.provenance import provenance
    alert = AnalystAlert.from_dict(adapt_analyst_incident(incident))
    now = datetime.now(timezone.utc)
    value = empty_record("risk_forecast", "assessment_complete", alert_id=alert.data["alert_id"],
        analyst_revision=alert.data["analyst_revision"], input_fingerprint=alert.input_fingerprint)
    value.update(forecast_id="synthetic-observer-forecast", forecast_revision=1, status="complete",
        numeric_assessment_status="complete", explanation_status="deterministic", risk_score=72,
        risk_score_basis="contextual_risk_assessment", risk_score_may_include_asset_impact=True, behavioral_score_source="supplied",
        selected_path={"candidate_id":"synthetic-candidate", "starting_technique":"T1059.001",
            "steps":[{"technique_id":"T1003.001","rule_id":"synthetic-rule"}],
            "source_entity_ids":[e["entity_id"] for e in alert.data["entities"]],
            "evidence_refs":[e["event_id"] for e in alert.data["normalized_events"]]},
        destination_technique="T1003.001", likelihood_index=0.8,
        time_horizon={"start":now.isoformat(),"end":(now+timedelta(hours=24)).isoformat(),"hours":24.0,"method":"configured_window_not_time_to_attack"},
        generated_at=now.isoformat(), forecast_as_of=now.isoformat(), versions=provenance(ForecastConfig(environment="test"))["versions"])
    value["blast_radius"].update(observed_entities=[{"entity_id":e["entity_id"],"entity_type":e["entity_type"],"evidence_refs":[],"source_entity_id":None} for e in alert.data["entities"]],
        potentially_reachable_entities=[], observed_count=len(alert.data["entities"]),potentially_reachable_count=0,inventory_coverage=1.0,truncated=False)
    return value


class SuccessfulClient:
    def assess(self, incident):
        return _frame(incident)


class RaisingClient:
    def assess(self, incident):
        raise RuntimeError("Do not copy provider error text")


class HangingClient:
    def assess(self, incident):
        time.sleep(30)


class MissingPackageClient:
    def assess(self, incident):
        raise ImportError("Do not expose local paths")


class MutatingClient:
    def assess(self, incident):
        result = _frame(incident)
        incident["forecast"].clear()
        incident["response_plan"].clear()
        incident["risk_analysis"]["verdict"] = "benign"
        incident["action_result"] = {"status":"executed", "approval":{"decision":"approve"}}
        return result


class BoundaryProbeClient:
    def assess(self, incident):
        import sqlite3
        outside=Path(incident["boundary_outside_path"])
        inside=Path(incident["boundary_inside_path"])
        inside.write_text("private probe")
        with sqlite3.connect(str(inside)+".db") as connection:
            connection.execute("CREATE TABLE probe (value INTEGER)")
        connection.close()
        for operation in (lambda:outside.write_text("forbidden"),
                          lambda:outside.with_suffix(".directory").mkdir(),
                          lambda:sqlite3.connect(str(outside)+".db")):
            try:
                operation()
            except ValueError:
                continue
            raise AssertionError("Outside-private operation was not blocked")
        return _frame(incident)


def systems_with_spies():
    from integrations import IntegrationHub
    systems = IntegrationHub()
    for name in ("isolate_endpoint","disable_user","block_ip","quarantine_file","create_ticket"):
        setattr(systems,name,Mock(wraps=getattr(systems,name)))
    return systems


def event_payload():
    return {"events":[{"event_id":f"observer-fixture-{i}","timestamp":FIXED,"source":"test",
        "event_type":"suspicious_login","severity":"critical","user":"fixture-operator","host":"fixture-db"} for i in range(5)]}


def legacy_run(observer=None, require_approval=True):
    import agents
    systems = systems_with_spies()
    pipeline = agents.SecurityOperationsPipeline(systems=systems,require_approval=require_approval,response_model=None)
    if observer is not None:
        pipeline.orchestrator.prognostic_observer = observer
    events = [agents.SecurityEvent(**{**e,"severity":agents.Severity(e["severity"])}) for e in event_payload()["events"]]
    with patch.object(agents,"utc_now",return_value=FIXED):
        result = pipeline.run(events)
    return result, systems


def fingerprint(incident):
    from agents import incident_to_dict
    return hashlib.sha256(json.dumps(incident_to_dict(incident),sort_keys=True,separators=(",", ":")).encode()).hexdigest()


def calls(systems):
    return {name:getattr(systems,name).call_count for name in ("isolate_endpoint","disable_user","block_ip","quarantine_file","create_ticket")}


class PrognosticShadowTests(unittest.TestCase):
    def setUp(self):
        import prognostic_bridge as bridge
        self.bridge = bridge
        self.work = TemporaryDirectory(dir=bridge.WORKSPACE_ROOT/"Prognostic_Agent/private",prefix="test-observer-preview-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)

    def observer(self, factory=SuccessfulClient, **kwargs):
        obj = self.bridge.SideChannelObserver(client_factory=factory,timeout_seconds=1.5,
              directory=self.root/(factory.__name__+str(len(list(self.root.iterdir())))),**kwargs)
        self.addCleanup(obj.close)
        return obj

    def test_off_matches_frozen_unmodified_legacy_bytes(self):
        for approved,expected in ((True,LEGACY_APPROVAL_SHA256),(False,LEGACY_EXECUTED_SHA256)):
            incident,_=legacy_run(require_approval=approved)
            self.assertEqual(fingerprint(incident),expected)
        import agents
        incident,systems=legacy_run()
        agent=agents.OrchestratorAgent(systems,response_model=None)
        with patch.object(agents,"deepcopy",side_effect=AssertionError("Off must not copy")):
            agent._notify_prognostic_observer(incident)

    def test_queue_overflow_drops_new_job_without_blocking(self):
        from agents import incident_to_dict
        observer=self.observer(capacity=1)
        started=threading.Event();release=threading.Event()
        self.addCleanup(release.set)
        def blocked(job):
            started.set()
            release.wait(5)
            return {"ok":True}
        with patch.object(observer,"_call",side_effect=blocked):
            snapshot=incident_to_dict(legacy_run()[0])
            self.assertTrue(observer.submit(snapshot))
            self.assertTrue(started.wait(2))
            self.assertTrue(observer.submit(snapshot))
            self.assertFalse(observer.submit(snapshot))
            self.assertEqual(observer.status()["queued"],1)
            self.assertEqual(observer.status()["counts"]["observer_queue_full"],1)
            release.set()
            self.assertTrue(observer.wait_idle(3))

    def test_shutdown_drops_pending_finishes_active_and_refuses_new_jobs(self):
        from agents import incident_to_dict
        observer=self.observer(capacity=2)
        started=threading.Event();release=threading.Event();dropped=threading.Event()
        self.addCleanup(release.set)
        original=observer.record_failure
        def diagnostic(reason):
            original(reason)
            if reason=="observer_shutdown_dropped":dropped.set()
        def blocked(job):
            started.set();release.wait(5)
            return {"ok":True}
        with patch.object(observer,"_call",side_effect=blocked) as worker,patch.object(observer,"record_failure",side_effect=diagnostic):
            snapshot=incident_to_dict(legacy_run()[0])
            self.assertTrue(observer.submit(snapshot));self.assertTrue(started.wait(2))
            self.assertTrue(observer.submit(snapshot))
            closer=threading.Thread(target=observer.close)
            closer.start()
            try:
                self.assertTrue(dropped.wait(2))
                release.set();closer.join(3)
                self.assertFalse(closer.is_alive())
                self.assertFalse(observer.thread.is_alive())
                self.assertEqual(worker.call_count,1)
                self.assertEqual(observer.status()["counts"]["observer_shutdown_dropped"],1)
                self.assertFalse(observer.submit(snapshot))
                self.assertEqual(observer.status()["counts"]["observer_closed"],1)
            finally:
                release.set();closer.join(3)

    def test_api_shutdown_observer_failure_is_contained(self):
        import agents,api
        from database import IncidentRepository
        from fastapi.testclient import TestClient
        observer=Mock()
        observer.close.side_effect=RuntimeError("Do not expose cleanup details")
        repository=IncidentRepository(":memory:")
        try:
            with patch.object(api,"settings",replace(api.settings,llm_triage="off",prognostic_mode="shadow")), \
                 patch.object(api,"IncidentRepository",return_value=repository), \
                 patch.object(agents.ResponseModel,"load",return_value=None), \
                 patch.object(self.bridge,"create_observer",return_value=observer):
                with TestClient(api.create_app()):pass
            observer.close.assert_called_once()
            observer.record_failure.assert_called_once_with("observer_shutdown_failed")
        finally:
            repository.close()

    def test_real_orchestrator_on_raising_hanging_and_mutating_add_no_actuators(self):
        baseline,baseline_systems=legacy_run(require_approval=False)
        for factory in (SuccessfulClient,RaisingClient,HangingClient,MutatingClient):
            with self.subTest(factory=factory.__name__):
                observer=self.observer(factory)
                incident,systems=legacy_run(observer,require_approval=False)
                before=fingerprint(incident)
                self.assertEqual(before,fingerprint(baseline))
                self.assertTrue(observer.wait_idle(8))
                self.assertEqual(fingerprint(incident),before)
                self.assertEqual(calls(systems),calls(baseline_systems))

    def test_real_api_on_off_failure_timeout_and_stored_incident_unchanged(self):
        import agents,api
        from database import IncidentRepository
        from fastapi.testclient import TestClient
        expected_response=expected_calls=None
        for factory in (None,SuccessfulClient,RaisingClient,HangingClient,MutatingClient):
            with self.subTest(factory=factory.__name__ if factory else "off"):
                observer=self.observer(factory) if factory else None
                systems=systems_with_spies()
                repository=IncidentRepository(":memory:")
                settings=replace(api.settings,llm_triage="off",prognostic_mode="shadow" if observer else "off")
                try:
                    with patch.object(api,"settings",settings),patch.object(api,"IncidentRepository",return_value=repository), \
                         patch.object(api,"IntegrationHub",return_value=systems),patch.object(agents.ResponseModel,"load",return_value=None), \
                         patch.object(self.bridge,"create_observer",return_value=observer) as make,patch.object(agents,"utc_now",return_value=FIXED):
                        with TestClient(api.create_app()) as client:
                            response=client.post("/events",json=event_payload())
                            self.assertEqual(response.status_code,200)
                            stored=response.json();identity=stored["incident_id"]
                            before=deepcopy(repository.get_incident(identity))
                            if observer:self.assertTrue(observer.wait_idle(8))
                            else:make.assert_not_called()
                            self.assertEqual(repository.get_incident(identity),before)
                            decision=client.post(f"/incidents/{identity}/decision",json={"decision":"approve","reviewer":"fixture-reviewer","reason":"fixture evidence"})
                            self.assertEqual(decision.status_code,200)
                            if factory is None:
                                expected_response=response.content;expected_calls=calls(systems)
                            else:
                                self.assertEqual(response.content,expected_response)
                                self.assertEqual(calls(systems),expected_calls)
                finally:
                    repository.close()

    def test_benign_skips_before_snapshot_or_client_work(self):
        import agents
        observer=self.observer(HangingClient)
        incident,systems=legacy_run()
        incident.risk_analysis["verdict"]="benign"
        agent=agents.OrchestratorAgent(systems,response_model=None,prognostic_observer=observer)
        with patch.object(agents,"incident_to_dict",side_effect=AssertionError("No snapshot for benign")):
            agent._notify_prognostic_observer(incident)
        self.assertTrue(observer.wait_idle(8))
        self.assertEqual(observer.status()["counts"].get("skipped_benign"),1)
        self.assertEqual(observer.status()["counts"].get("completed"),1)

    def test_missing_inventory_package_and_logging_failure_are_recorded(self):
        incident,_=legacy_run()
        from agents import incident_to_dict
        observer=self.observer(MissingPackageClient)
        observer.submit(incident_to_dict(incident));self.assertTrue(observer.wait_idle(8))
        self.assertEqual(observer.status()["counts"].get("observer_package_missing"),1)
        broken=self.root/"not-a-directory";broken.write_text("fixture")
        observer=self.bridge.SideChannelObserver(client_factory=SuccessfulClient,directory=broken,timeout_seconds=1.5)
        self.addCleanup(observer.close)
        observer.submit(incident_to_dict(incident));self.assertTrue(observer.wait_idle(8))
        self.assertEqual(observer.status()["counts"].get("observer_logging_failed"),1)
        self.assertEqual(observer.status()["counts"].get("observer_failure_log_failed"),1)
        observer=self.bridge.SideChannelObserver(inventory_path=None,directory=self.root/"missing-inventory",timeout_seconds=3)
        self.addCleanup(observer.close)
        observer.submit(incident_to_dict(incident));self.assertTrue(observer.wait_idle(8))
        self.assertEqual(observer.status()["counts"].get("forecast_errors"),1)
        row=json.loads(next(observer.directory.glob("*.json")).read_text())
        self.assertEqual(row["forecast_reason"],"asset_inventory_unavailable")
        for case in ("missing-file","corrupt-file"):
            with self.subTest(case=case):
                inventory=self.root/(case+".json")
                if case=="corrupt-file":inventory.write_text("{")
                observer=self.bridge.SideChannelObserver(inventory_path=inventory,directory=self.root/case,timeout_seconds=3)
                self.addCleanup(observer.close)
                observer.submit(incident_to_dict(incident));self.assertTrue(observer.wait_idle(8))
                row=json.loads(next(observer.directory.glob("*.json")).read_text())
                self.assertEqual(row["forecast_response_type"],"operational_error")
                self.assertEqual(row["forecast_reason"],"asset_inventory_unavailable")
                self.assertFalse(row["order_changed"])

    def test_real_forecast_worker_reads_inventory_and_completes_assessment(self):
        from agents import incident_to_dict
        inventory=self.root/"inventory.json"
        document={"schema_version":1,"source":{"collected_at":datetime.now(timezone.utc).isoformat()},"entities":[
            {"entity_id":"host:fixture-db","entity_type":"host","asset_criticality":"normal","last_updated":datetime.now(timezone.utc).isoformat()}
        ]}
        inventory.write_text(json.dumps(document))
        observer=self.bridge.SideChannelObserver(inventory_path=inventory,directory=self.root/"real-engine",timeout_seconds=3)
        self.addCleanup(observer.close)
        incident,_=legacy_run()
        before=fingerprint(incident)
        observer.submit(incident_to_dict(incident))
        self.assertTrue(observer.wait_idle(8))
        row=json.loads(next(observer.directory.glob("*.json")).read_text())
        self.assertEqual(row["forecast_response_type"],"risk_forecast")
        self.assertIn(row["forecast_status"],{"complete","partial","abstained"})
        for case in ("missing-timestamp","stale-timestamp","future-timestamp"):
            with self.subTest(case=case):
                changed=deepcopy(document)
                if case=="missing-timestamp":changed["source"].pop("collected_at")
                else:
                    changed["source"]["collected_at"]=(datetime.now(timezone.utc)+timedelta(hours=-25 if case=="stale-timestamp" else 1)).isoformat()
                inventory=self.root/(case+".json");inventory.write_text(json.dumps(changed))
                observer=self.bridge.SideChannelObserver(inventory_path=inventory,directory=self.root/case,timeout_seconds=3)
                self.addCleanup(observer.close)
                observer.submit(incident_to_dict(incident));self.assertTrue(observer.wait_idle(8))
                row=json.loads(next(observer.directory.glob("*.json")).read_text())
                self.assertEqual(row["forecast_response_type"],"operational_error")
                self.assertEqual(row["forecast_reason"],"inventory_stale")
                self.assertEqual(row["numeric_assessment_status"],"unavailable")
                self.assertEqual(row["options_without_forecast"],row["options_with_forecast"])
                self.assertEqual(row["executed_actions"],[])
                self.assertEqual(fingerprint(incident),before)

    def test_snapshot_failure_never_reaches_legacy_result(self):
        import agents
        observer=self.observer()
        with patch.object(agents,"incident_to_dict",side_effect=ValueError("Do not expose error")):
            incident,_=legacy_run(observer)
        self.assertEqual(incident.action_result["status"],"approval_required")
        self.assertEqual(observer.status()["counts"].get("observer_submission_failed"),1)

    def test_environment_default_is_test_and_never_inferred(self):
        import config
        import os
        with patch.dict(os.environ,{"SOC_PROGNOSTIC_MODE":"shadow","SOC_ENVIRONMENT":"production"}):
            with patch.dict(os.environ,{},clear=False):
                original=os.environ.pop("SOC_PROGNOSTIC_ENVIRONMENT",None)
                try:self.assertEqual(config.Settings.from_env().prognostic_environment,"test")
                finally:
                    if original is not None:os.environ["SOC_PROGNOSTIC_ENVIRONMENT"]=original
        observer=self.observer()
        self.assertEqual(observer.status()["environment"],"test")

    def test_real_worker_boundary_allows_private_and_blocks_outside_file_directory_sqlite(self):
        from agents import incident_to_dict
        import uuid
        outside=self.bridge.WORKSPACE_ROOT/"Prognostic_Agent"/(".boundary-probe-"+uuid.uuid4().hex)
        inside=self.root/"allowed.txt"
        snapshot=incident_to_dict(legacy_run()[0])
        snapshot.update(boundary_outside_path=str(outside),boundary_inside_path=str(inside))
        observer=self.observer(BoundaryProbeClient)
        try:
            observer.submit(snapshot)
            self.assertTrue(observer.wait_idle(8))
            self.assertEqual(observer.status()["counts"].get("completed"),1)
            self.assertEqual(inside.read_text(),"private probe")
            self.assertTrue(Path(str(inside)+".db").is_file())
            self.assertFalse(outside.exists())
            self.assertFalse(outside.with_suffix(".directory").exists())
            self.assertFalse(Path(str(outside)+".db").exists())
        finally:
            for path in (outside,Path(str(outside)+".db")):
                if path.exists():path.unlink()
            if outside.with_suffix(".directory").exists():outside.with_suffix(".directory").rmdir()

    def test_status_is_read_only_and_observer_data_is_mode_gated(self):
        import agents,api
        from database import IncidentRepository
        from fastapi.testclient import TestClient
        for mode in ("off","shadow"):
            observer=self.observer()
            repository=IncidentRepository(":memory:")
            systems=systems_with_spies()
            try:
                with patch.object(api,"settings",replace(api.settings,llm_triage="off",prognostic_mode=mode)), \
                     patch.object(api,"IncidentRepository",return_value=repository), \
                     patch.object(api,"IntegrationHub",return_value=systems), \
                     patch.object(agents.ResponseModel,"load",return_value=None), \
                     patch.object(self.bridge,"create_observer",return_value=observer) as make:
                    with TestClient(api.create_app()) as client:
                        before=observer.status();changes=repository.connection.total_changes;actions=calls(systems)
                        first=client.get("/orchestrator/status").json()
                        self.assertEqual(client.get("/orchestrator/status").json(),first)
                        self.assertEqual(observer.status(),before)
                        self.assertEqual(repository.connection.total_changes,changes)
                        self.assertEqual(calls(systems),actions)
                        if mode=="off":
                            self.assertNotIn("prognostic_observer",first);make.assert_not_called()
                        else:
                            self.assertEqual(first["prognostic_observer"],before)
            finally:
                repository.close()

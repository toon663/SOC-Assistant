"""Opt-in side-channel observer. Stdlib-only import; no actuator/DB handles."""
from collections import Counter, deque
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import queue
import sys
import threading
import time
import uuid

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
MAPPING_VERSION = "destination-option-priority.v1"
MAPPING_HASH = "f4a4b4d6a6b20e46b7e85b0240e9d3b16bfee8685f108e37b28de917bb66c953"


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def _baseline_options(snapshot):
    steps = snapshot.get("response_plan", {}).get("steps", [])
    result = []
    for index, original in enumerate(snapshot.get("response_options", [])):
        option = deepcopy(original)
        step = next((s for s in steps if s.get("action") == option.get("action") and s.get("target") == option.get("target")), {})
        policy = step.get("policy", {})
        target_type = step.get("target_field")
        target = option.get("target")
        option.update(option_id=str(index)+":"+str(option.get("action")),
                      target_entity_id=(target_type+":"+target.strip().casefold()) if target_type in {"user", "host"} and isinstance(target, str) else None,
                      eligible=option.get("selected") is True and policy.get("allowed") is True,
                      approval_required=policy.get("requires_approval") if type(policy.get("requires_approval")) is bool else None,
                      policy=deepcopy(policy))
        result.append(option)
    return result


def _option_views(options):
    known = {"isolate_endpoint", "disable_user", "block_ip", "quarantine_file", "monitor", "create_ticket"}
    return [{"option_ref":_hash(o.get("option_id", i)), "action":o.get("action") if o.get("action") in known else "other",
             "target_ref":_hash(o["target_entity_id"]) if o.get("target_entity_id") else None,
             "eligible":o.get("eligible"), "approval_required":o.get("approval_required")} for i,o in enumerate(options)]


class SideChannelObserver:
    def __init__(self, *, environment="test", inventory_path=None, timeout_seconds=3.0, capacity=64,
                 directory=None, client_factory=None):
        if environment not in {"test", "demo", "production"}:
            raise ValueError("Invalid observer environment")
        self.environment = environment
        self.inventory_path = str(inventory_path) if inventory_path else None
        self.timeout = float(timeout_seconds)
        if not 0.25 <= self.timeout <= 30 or type(capacity) is not int or not 1 <= capacity <= 256:
            raise ValueError("Invalid observer bounds")
        private = (WORKSPACE_ROOT/"Prognostic_Agent/private").resolve()
        self.directory = Path(directory or private/"orchestrator-observer").resolve()
        if not self.directory.is_relative_to(private):
            raise ValueError("Observer output must be private")
        self.factory = None
        if client_factory is not None:
            # Trusted test injection only; no HTTP/environment option exposes it.
            if "<locals>" in client_factory.__qualname__:
                raise ValueError("Client factory must be importable")
            self.factory = {"file":str(Path(sys.modules[client_factory.__module__].__file__).resolve()), "name":client_factory.__name__}
        self.pending = queue.Queue(maxsize=capacity)
        self.lock = threading.RLock()
        self.counts = Counter()
        self.recent = deque(maxlen=16)
        self.thread = None
        self.closed = False

    def record_failure(self, reason):
        # Always record aggregate + bounded recent diagnostic in memory first.
        # No raw exception, incident text or identifiers are retained here.
        with self.lock:
            self.counts[reason] += 1
            self.recent.append(reason)

    def _enqueue(self, job):
        try:
            encoded = json.dumps(job, ensure_ascii=False, allow_nan=False)
            if len(encoded.encode("utf-8")) > 1024*1024:
                self.record_failure("observer_snapshot_too_large")
                return False
            with self.lock:
                if self.closed:
                    self.record_failure("observer_closed")
                    return False
                if self.thread is None:
                    self.thread = threading.Thread(target=self._loop, name="prognostic-observer", daemon=True)
                    self.thread.start()
                try:
                    self.pending.put_nowait(encoded)
                except queue.Full:
                    self.record_failure("observer_queue_full")
                    return False
                self.counts["accepted"] += 1
            return True
        except Exception:
            self.record_failure("observer_submission_failed")
            return False

    def _job(self, alert_id):
        return {"job_id":uuid.uuid4().hex, "workspace_root":str(WORKSPACE_ROOT),
                "environment":self.environment, "inventory_path":self.inventory_path,
                "directory":str(self.directory), "timeout_seconds":self.timeout,
                "alert_id":alert_id if isinstance(alert_id, str) else None, "client_factory":self.factory}

    def skip_benign(self, alert_id):
        with self.lock:
            self.counts["skipped_benign"] += 1
        job = self._job(alert_id)
        job.update(kind="skipped_benign", options=[])
        return self._enqueue(job)

    def submit(self, snapshot):
        # A second guard covers callers outside OrchestratorAgent.
        if snapshot.get("risk_analysis", {}).get("verdict") == "benign":
            return self.skip_benign(snapshot.get("incident_id"))
        job = self._job(snapshot.get("incident_id"))
        job.update(kind="assess", incident=snapshot, options=_baseline_options(snapshot))
        return self._enqueue(job)  # Only immutable serialized bytes enter the queue.

    def _call(self, job):
        # Load only the optional package namespace, without changing the legacy
        # process's sys.path resolution order. This supports launch from backend/.
        if "Prognostic_Agent" not in sys.modules:
            location = WORKSPACE_ROOT/"Prognostic_Agent/__init__.py"
            spec = importlib.util.spec_from_file_location("Prognostic_Agent", location,
                submodule_search_locations=[str(location.parent)])
            package = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = package
            try:
                spec.loader.exec_module(package)
            except Exception:
                sys.modules.pop(spec.name, None)
                raise ImportError("Optional forecast package unavailable") from None
        from Prognostic_Agent.orchestrator_client import OrchestratorForecastClient
        class Worker(OrchestratorForecastClient):
            def _command(inner):
                return [sys.executable, "-B", str(Path(__file__).resolve()), "--worker"]
        return Worker()._run_worker(job, deadline=time.monotonic()+self.timeout)

    def _failure_log(self, job, reason):
        # Core package may be missing. Keep a stdlib-only, pinned-mapping record.
        self.record_failure(reason)
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            views = _option_views(job.get("options", []))
            row = {"schema_version":1, "response_type":"orchestrator_shadow_decision", "decision_id":job["job_id"],
                "created_at":__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
                "environment":self.environment, "incident_ref":_hash(job["alert_id"]) if job["alert_id"] else None,
                "correlation_ref":_hash(job["job_id"]), "forecast_id":None, "forecast_revision":None,
                "forecast_response_type":"operational_error", "forecast_status":None, "forecast_reason":reason,
                "numeric_assessment_status":"unavailable", "mapping_version":MAPPING_VERSION, "mapping_hash":MAPPING_HASH,
                "mapping_applied":False, "options_without_forecast":views, "options_with_forecast":views,
                "order_changed":False, "advisory_reason":reason, "issue_codes":[reason], "dry_run":True, "executed_actions":[]}
            # Per-job identity prevents a late acknowledgement from duplicating a
            # decision that was already atomically published by the worker.
            with (self.directory/(job["job_id"]+".json")).open("x", encoding="utf-8") as stream:
                json.dump(row, stream, ensure_ascii=False, allow_nan=False)
        except FileExistsError:
            if not (self.directory/(job["job_id"]+".json")).is_file():
                self.record_failure("observer_failure_log_failed")
        except Exception:
            self.record_failure("observer_failure_log_failed")

    def _loop(self):
        while True:
            encoded = self.pending.get()
            try:
                if encoded is None:
                    return
                job = json.loads(encoded)
                try:
                    outcome = self._call(job)
                    if not isinstance(outcome, dict) or outcome.get("ok") is not True:
                        reason = outcome.get("reason") if isinstance(outcome, dict) else None
                        allowed = {"observer_client_failed", "observer_package_missing", "observer_logging_failed", "observer_mapping_mismatch", "observer_contract_invalid"}
                        self._failure_log(job, reason if reason in allowed else "observer_failed")
                    else:
                        with self.lock:
                            self.counts["completed"] += 1
                            if outcome.get("forecast_error"):
                                self.counts["forecast_errors"] += 1
                except TimeoutError:
                    self._failure_log(job, "observer_timeout")
                except ImportError:
                    self._failure_log(job, "observer_package_missing")
                except Exception:
                    self._failure_log(job, "observer_failed")
            except Exception:
                self.record_failure("observer_worker_loop_failed")
            finally:
                self.pending.task_done()

    def status(self):
        with self.lock:
            return {"mode":"shadow", "environment":self.environment, "capacity":self.pending.maxsize,
                    "queued":self.pending.qsize(), "counts":dict(self.counts), "recent_error_codes":list(self.recent),
                    "durability":"best_effort_disk_plus_process_memory", "executed_actions":0}

    def wait_idle(self, timeout=10):
        deadline = time.monotonic()+timeout
        while self.pending.unfinished_tasks and time.monotonic()<deadline:
            time.sleep(0.01)
        return not self.pending.unfinished_tasks

    def close(self):
        with self.lock:
            self.closed = True
            if self.thread is None:
                return
            while True:
                try:
                    pending = self.pending.get_nowait()
                    self.pending.task_done()
                    if pending is not None:
                        self.record_failure("observer_shutdown_dropped")
                except queue.Empty:
                    break
            self.pending.put_nowait(None)
        self.thread.join(timeout=self.timeout+0.3)


def create_observer(settings):
    return SideChannelObserver(environment=settings.prognostic_environment,
        inventory_path=settings.prognostic_inventory_path, timeout_seconds=settings.prognostic_timeout_seconds,
        capacity=int(settings.prognostic_queue_size))


def _worker_main():
    job = json.loads(sys.stdin.read(1024*1024+1))
    root = Path(job["workspace_root"]).resolve()
    sys.path.insert(0, str(root))
    try:
        from Prognostic_Agent.private_paths import confine_private_runtime, private_path
        confine_private_runtime()  # No backend writes/SQLite handles or network.
        from Prognostic_Agent.orchestrator_advisory import MAPPING_HASH as actual_hash, MAPPING_VERSION as actual_version
        from Prognostic_Agent.orchestrator_contract import empty_record, validate_contract
        from Prognostic_Agent.orchestrator_shadow_log import ShadowDecisionLog
        if (actual_version, actual_hash) != (MAPPING_VERSION, MAPPING_HASH):
            print(json.dumps({"ok":False,"reason":"observer_mapping_mismatch"})); return
        directory = private_path(job["directory"])
        if job["kind"] == "skipped_benign":
            record = empty_record("skipped_benign", "skipped_benign", environment=job["environment"], alert_id=job["alert_id"])
        else:
            if job["client_factory"] is not None:
                descriptor = job["client_factory"]
                spec = importlib.util.spec_from_file_location("_trusted_observer_test_clients", descriptor["file"])
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)
                client = getattr(module, descriptor["name"])()
            else:
                from Prognostic_Agent.orchestrator_client import OrchestratorClientConfig, OrchestratorForecastClient, _worker_main as forecast_main
                from contextlib import redirect_stdout
                import io
                def local_transport(request, *, deadline):
                    # Already inside the killable, private-only process tree.
                    # Avoid a second spawn (and opening NUL inside the audit
                    # boundary). The outer parent enforces the total deadline.
                    previous = sys.stdin
                    output = io.StringIO()
                    try:
                        sys.stdin = io.StringIO(json.dumps(request, allow_nan=False))
                        with redirect_stdout(output):
                            forecast_main()
                    finally:
                        sys.stdin = previous
                    return json.loads(output.getvalue())
                client = OrchestratorForecastClient(OrchestratorClientConfig(environment=job["environment"],
                    inventory_path=Path(job["inventory_path"]) if job["inventory_path"] else None,
                    timeout_seconds=max(0.25,job["timeout_seconds"]-0.4)), transport=local_transport)
            try:
                record = client.assess(job["incident"])
            except ImportError:
                print(json.dumps({"ok":False,"reason":"observer_package_missing"})); return
            except Exception:
                print(json.dumps({"ok":False,"reason":"observer_client_failed"})); return
        try:
            validate_contract(record, expected_alert_id=job["alert_id"], expected_environment=job["environment"])
        except Exception:
            print(json.dumps({"ok":False,"reason":"observer_contract_invalid"})); return
        record["request_id"] = job["job_id"]
        try:
            working = private_path(root/"Prognostic_Agent/private/orchestrator-observer-working"/job["job_id"])
            item = ShadowDecisionLog(working,environment=job["environment"]).record(record,job["options"])
            directory.mkdir(parents=True,exist_ok=True)
            os.replace(working/(item["decision_id"]+".json"), directory/(job["job_id"]+".json"))
        except Exception:
            print(json.dumps({"ok":False,"reason":"observer_logging_failed"})); return
        print(json.dumps({"ok":True,"forecast_error":record["response_type"] in {"validation_error","operational_error"}}))
    except ImportError:
        print(json.dumps({"ok":False,"reason":"observer_package_missing"}))
    except Exception:
        print(json.dumps({"ok":False,"reason":"observer_failed"}))


if __name__ == "__main__" and sys.argv[1:] == ["--worker"]:
    _worker_main()

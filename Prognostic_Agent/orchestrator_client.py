"""Local, deadline-bounded standalone client. No backend imports or pipeline hooks."""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

from .analyst_adapter import adapt_analyst_incident
from .config import AGENT_DIR, ForecastConfig
from .contracts import AnalystAlert, RequestValidationError, canonical_json, parse_time, utc_text
from .migrations import validate_environment
from .inventory_publication import collected_inventory
from .orchestrator_contract import ContractError, empty_record, serialize_forecast, validate_contract
from .private_paths import PRIVATE_DIR, private_path


@dataclass(frozen=True)
class OrchestratorClientConfig:
    environment: str = "test"
    timeout_seconds: float = 3.0
    inventory_path: Path | None = None
    history_path: Path = PRIVATE_DIR / "orchestrator" / "forecast_history.db"
    rules_path: Path = AGENT_DIR / "rules" / "attack_transitions.json"
    weights_path: Path = AGENT_DIR / "rules" / "scoring_weights.json"

    def __post_init__(self):
        validate_environment(self.environment)
        if type(self.timeout_seconds) not in (int, float) or not math.isfinite(self.timeout_seconds) or not 0 < self.timeout_seconds <= 30:
            raise ValueError("Client timeout must be positive and at most 30 seconds")
        private_path(self.history_path)
        if Path(self.history_path).name.casefold() == "soc_agents.db":
            raise ValueError("Backend storage is not a client history")


class _WindowsJob:
    """Kill the isolated worker AND descendants on close. No backend PID assigned."""
    def __init__(self, process):
        import ctypes as c
        from ctypes import wintypes as w
        class Basic(c.Structure):
            _fields_ = [("process_time",c.c_longlong),("job_time",c.c_longlong),("flags",w.DWORD),
                        ("min_ws",c.c_size_t),("max_ws",c.c_size_t),("active",w.DWORD),
                        ("affinity",c.c_size_t),("priority",w.DWORD),("scheduling",w.DWORD)]
        class IO(c.Structure):
            _fields_ = [(name,c.c_ulonglong) for name in ("read_ops","write_ops","other_ops","read_bytes","write_bytes","other_bytes")]
        class Extended(c.Structure):
            _fields_ = [("basic",Basic),("io",IO),("process_memory",c.c_size_t),("job_memory",c.c_size_t),
                        ("peak_process_memory",c.c_size_t),("peak_job_memory",c.c_size_t)]
        self.kernel = c.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [c.c_void_p,w.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = w.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [w.HANDLE,c.c_int,c.c_void_p,w.DWORD]
        self.kernel.AssignProcessToJobObject.argtypes = [w.HANDLE,w.HANDLE]
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError("worker_isolation_unavailable")
        info = Extended(); info.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.kernel.SetInformationJobObject(self.handle, 9, c.byref(info), c.sizeof(info)) or not self.kernel.AssignProcessToJobObject(self.handle, int(process._handle)):
            self.close()
            raise OSError("worker_isolation_unavailable")

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


@dataclass
class _SnapshotInventoryProvider:
    records: dict
    name = "orchestrator_inventory_snapshot"

    def lookup(self, entity, *, deadline):
        return self.records.get(entity["entity_id"])


class OrchestratorForecastClient:
    def __init__(self, config=None, *, transport=None):
        self.config = config or OrchestratorClientConfig()
        self.transport = transport  # Trusted offline test injection, not network.

    def _command(self):
        return [sys.executable, "-B", "-m", "Prognostic_Agent.orchestrator_client", "--worker"]

    def _run_worker(self, request, *, deadline):
        process = job = None
        try:
            # Worker blocks reading stdin until assigned to its isolated job.
            process = subprocess.Popen(self._command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, encoding="utf-8", cwd=AGENT_DIR.parent,
                env={**os.environ,"PYTHONIOENCODING":"utf-8","PYTHONDONTWRITEBYTECODE":"1"},
                start_new_session=os.name != "nt", creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)
            if os.name == "nt":
                job = _WindowsJob(process)
            remaining = deadline - time.monotonic() - 0.2
            if remaining <= 0:
                raise TimeoutError()
            try:
                output, _ = process.communicate(canonical_json(request), timeout=remaining)
            except subprocess.TimeoutExpired:
                raise TimeoutError() from None
            if process.returncode != 0 or len(output.encode("utf-8")) > 2 * 1024 * 1024:
                raise ValueError("worker_failed")
            return json.loads(output)
        finally:
            if job is not None:
                job.close()
            if process is not None:
                if os.name != "nt":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if process.poll() is None:
                    try:
                        process.kill()
                    except OSError:
                        pass
                try:
                    process.wait(timeout=max(0.01, min(0.15, deadline-time.monotonic())))
                except subprocess.TimeoutExpired:
                    process.kill()
                for stream in (process.stdin, process.stdout):
                    if stream:
                        stream.close()

    def assess(self, incident, *, forecast_as_of=None):
        started = time.monotonic()
        request_id = uuid.uuid4().hex
        alert_id = incident.get("incident_id") if isinstance(incident, dict) and isinstance(incident.get("incident_id"), str) and incident["incident_id"].strip() else None
        context = {"request_id":request_id, "alert_id":alert_id, "environment":self.config.environment}
        def fail(kind, reason):
            record = empty_record(kind, reason, **context)
            record["issues"] = [{"code":reason,"detail":"No usable forecast; the baseline proposal remains available and no action is authorized."}]
            return validate_contract(record)
        analysis = incident.get("risk_analysis") if isinstance(incident, dict) else None
        # Before adapter, inventory access, worker creation, history or engine.
        if isinstance(analysis, dict) and analysis.get("verdict") == "benign":
            return validate_contract(empty_record("skipped_benign", "skipped_benign", **context))
        try:
            payload = AnalystAlert.from_dict(adapt_analyst_incident(incident))
            context.update(alert_id=payload.data["alert_id"], analyst_revision=payload.data["analyst_revision"], input_fingerprint=payload.input_fingerprint)
            as_of = forecast_as_of or datetime.now(timezone.utc)
            as_of = parse_time(as_of) if isinstance(as_of, str) else as_of
            if as_of.tzinfo is None or as_of.utcoffset() is None:
                raise ValueError()
        except (RequestValidationError, ValueError, TypeError, AttributeError, KeyError):
            return fail("validation_error", "invalid_analyst_input")
        if self.config.environment == "production" and forecast_as_of is not None and abs((datetime.now(timezone.utc)-as_of).total_seconds()) > 300:
            return fail("validation_error", "production_historical_cutoff_refused")
        try:
            # Wall-clock freshness even for a historical evidence cutoff. Never
            # substitute file mtime, overlay approval time or forecast horizon.
            collected_inventory(Path(self.config.inventory_path).read_bytes())
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return fail("operational_error", "inventory_stale")
        request = {"alert":payload.data, "request_id":request_id, "as_of":utc_text(as_of), "environment":self.config.environment,
                   "inventory_path":str(self.config.inventory_path) if self.config.inventory_path is not None else None,
                   "history_path":str(private_path(self.config.history_path)), "rules_path":str(self.config.rules_path),
                   "weights_path":str(self.config.weights_path), "timeout_seconds":self.config.timeout_seconds}
        deadline = started + self.config.timeout_seconds
        try:
            if len(canonical_json(request).encode("utf-8")) > 1024 * 1024:
                return fail("validation_error", "request_too_large")
            if time.monotonic() >= deadline - 0.2:
                return fail("operational_error", "forecast_timeout")
            record = self.transport(request, deadline=deadline) if self.transport is not None else self._run_worker(request, deadline=deadline)
            if time.monotonic() >= deadline:
                return fail("operational_error", "forecast_timeout")
            validate_contract(record, expected_alert_id=payload.data["alert_id"], expected_revision=payload.data["analyst_revision"],
                              expected_fingerprint=payload.input_fingerprint, expected_environment=self.config.environment, now=as_of)
            if record["request_id"] != request_id or record["response_type"] == "skipped_benign":
                raise ContractError("request_binding_mismatch")
            if record["response_type"] == "risk_forecast" and record["forecast_as_of"] != utc_text(as_of):
                raise ContractError("cutoff_mismatch")
            return record
        except TimeoutError:
            return fail("operational_error", "forecast_timeout")
        except ContractError:
            return fail("validation_error", "forecast_contract_invalid")
        except Exception:
            return fail("operational_error", "forecast_unavailable")

    def assess_and_log(self, incident, baseline_options, *, shadow_log, forecast_as_of=None):
        """Explicit opt-in utility only; nothing is wired to backend ingestion."""
        record = self.assess(incident, forecast_as_of=forecast_as_of)
        now = parse_time(forecast_as_of) if isinstance(forecast_as_of, str) else forecast_as_of
        try:
            decision = shadow_log.record(record, baseline_options, now=now)
            return {"assessment":record, "decision":decision, "log_error":None}
        except (OSError, ValueError, TypeError, KeyError):
            return {"assessment":record, "decision":None, "log_error":"shadow_log_unavailable"}


def _worker_main():
    # No backend imports, external provider, action integrations or explanation SDK.
    from .contracts import content_hash
    from .service import ForecastService
    from .storage import ForecastHistory
    request = json.loads(sys.stdin.read(1024*1024 + 1))
    alert = request["alert"]
    def failure(reason):
        record = empty_record("operational_error", reason, environment=request["environment"], request_id=request["request_id"],
                              alert_id=alert["alert_id"], analyst_revision=alert["analyst_revision"], input_fingerprint=AnalystAlert.from_dict(alert).input_fingerprint)
        record["issues"] = [{"code":reason, "detail":"Standalone forecast unavailable; no action is authorized."}]
        return record
    try:
        path = Path(request["inventory_path"]) if request["inventory_path"] else None
        if path is None or not path.is_file():
            record = failure("inventory_stale")
        else:
            raw_inventory = path.read_bytes()
            digest = hashlib.sha256(raw_inventory).hexdigest()
            try:
                inventory = collected_inventory(raw_inventory)
            except (ValueError, KeyError, TypeError, AttributeError):
                print(canonical_json(validate_contract(failure("inventory_stale"))))
                return
            if inventory.get("schema_version") != 1 or not isinstance(inventory.get("entities"),list):
                raise ValueError("Invalid inventory")
            records = {r["entity_id"]:r for r in inventory["entities"]}
            if len(records) != len(inventory["entities"]):
                raise ValueError("Duplicate inventory identities")
            config = ForecastConfig(environment=request["environment"], rules_path=Path(request["rules_path"]), weights_path=Path(request["weights_path"]),
                                    asset_provider_timeout_seconds=min(2.0, request["timeout_seconds"]),
                                    enrichment_timeout_seconds=min(5.0, request["timeout_seconds"]), sqlite_busy_timeout_ms=500)
            with ForecastHistory(private_path(request["history_path"]), environment=config.environment, busy_timeout_ms=500) as history:
                # explanation_config intentionally omitted: forced deterministic.
                response = ForecastService(history, config=config).assess(alert, asset_provider=_SnapshotInventoryProvider(records),
                    forecast_as_of=request["as_of"], evaluation_id="orchestrator:"+content_hash({"inventory":digest,"as_of":request["as_of"]}),
                    shadow_context={"source":"orchestrator_shadow","source_incident_id":alert["alert_id"],"analyst_verdict":alert["verdict"]})
            record = serialize_forecast(response, request_id=request["request_id"])
            # Error envelopes still bind to this assessed request, never zeros.
            if record["response_type"] != "risk_forecast":
                record.update(alert_id=alert["alert_id"], analyst_revision=alert["analyst_revision"], input_fingerprint=AnalystAlert.from_dict(alert).input_fingerprint)
    except Exception:
        record = failure("forecast_worker_error")
    print(canonical_json(validate_contract(record)))


if __name__ == "__main__":
    if sys.argv[1:] != ["--worker"]:
        raise SystemExit("Internal client worker only; use OrchestratorForecastClient from Python.")
    _worker_main()

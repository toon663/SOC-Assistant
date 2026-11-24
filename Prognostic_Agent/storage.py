"""Agent-owned SQLite history. WAL, bounded lock waiting, versioned migrations.

Input identity is canonical; reassessment identity also includes engine/config
versions, explicit replay cutoff, and caller evaluation_id. No backend storage.
"""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import threading
import uuid

from .contracts import canonical_json
from .migrations import migrate_v2, accumulate_unsupported, validate_environment

DEFAULT_HISTORY_PATH = Path(__file__).resolve().parent / "storage" / "forecast_history.db"


def storage_time(value):
    # Fixed precision makes SQLite TEXT ordering correct at second boundaries.
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class ForecastHistory:
    def __init__(self, path=DEFAULT_HISTORY_PATH, *, busy_timeout_ms=5000, retention_days=90, store_full_evidence=False, environment="demo"):
        self.environment = validate_environment(environment)
        if type(busy_timeout_ms) is not int or busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms must be a nonnegative integer")
        if type(retention_days) is not int or retention_days < 1:
            raise ValueError("retention_days must be a positive integer")
        self.path = Path(path).resolve()
        if self.path.name.casefold() == "soc_agents.db":
            raise ValueError("soc_agents.db is reserved for the backend; use an agent-owned history file")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.retention_days = retention_days
        self.busy_timeout_ms = busy_timeout_ms
        self.store_full_evidence = store_full_evidence
        self._lock = threading.RLock()
        self.connection = sqlite3.connect(str(self.path), timeout=busy_timeout_ms / 1000, check_same_thread=False, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        try:
            self._initialize()
        except BaseException:
            self.connection.close()
            raise

    def _initialize(self):
        tables = {row[0] for row in self.connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if tables and not {"schema_migrations", "forecasts"} <= tables:
            raise ValueError("Refusing to migrate a database not owned by Prognostic_Agent")
        self.connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
        mode = self.connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        if mode.lower() != "wal":
            raise RuntimeError("Forecast history requires SQLite WAL mode")
        self.connection.execute("PRAGMA foreign_keys=ON")
        with self._transaction():
            self.connection.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
            current = self.connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] or 0
            if current > 2:
                raise ValueError("Forecast history schema is newer than this agent")
            if current < 1:
                # No executescript: it can implicitly commit an active migration.
                for statement in (
                    "CREATE TABLE alert_revisions(alert_id TEXT PRIMARY KEY, last_revision INTEGER NOT NULL)",
                    "CREATE TABLE forecasts(forecast_id TEXT PRIMARY KEY, alert_id TEXT NOT NULL, revision INTEGER NOT NULL, idempotency_key TEXT NOT NULL UNIQUE, input_fingerprint TEXT NOT NULL, created_at TEXT NOT NULL, response_json TEXT NOT NULL, input_json TEXT NOT NULL, UNIQUE(alert_id,revision))",
                    "CREATE INDEX forecasts_alert_time ON forecasts(alert_id,created_at)",
                    "CREATE TABLE attempts(attempt_id TEXT PRIMARY KEY, forecast_id TEXT REFERENCES forecasts(forecast_id) ON DELETE CASCADE, created_at TEXT NOT NULL, metrics_json TEXT NOT NULL)",
                    "CREATE INDEX attempts_time ON attempts(created_at)",
                    "CREATE TABLE unsupported(forecast_id TEXT NOT NULL REFERENCES forecasts(forecast_id) ON DELETE CASCADE, technique_id TEXT NOT NULL, reason TEXT NOT NULL, details_json TEXT NOT NULL, PRIMARY KEY(forecast_id,technique_id,reason))",
                ):
                    self.connection.execute(statement)
                self.connection.execute("INSERT INTO schema_migrations VALUES(1,?)", (storage_time(datetime.now(timezone.utc)),))
            if current < 2:
                migrate_v2(self.connection, self.environment, storage_time(datetime.now(timezone.utc)))
                if current == 0:
                    self.connection.execute("UPDATE schema_migrations SET environment=? WHERE version=1", (self.environment,))

    @contextmanager
    def _transaction(self):
        with self._lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.connection.execute("COMMIT")
            except BaseException:
                self.connection.execute("ROLLBACK")
                raise

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def find(self, idempotency_key):
        with self._lock:
            row = self.connection.execute("SELECT response_json FROM forecasts WHERE idempotency_key=? AND environment=?", (idempotency_key, self.environment)).fetchone()
        return json.loads(row[0]) if row else None

    def save(self, response, normalized_input, idempotency_key):
        """Atomic cross-connection idempotency and per-alert revision allocation."""
        if response.get("environment") != self.environment:
            raise ValueError("Response environment and history environment must agree")
        with self._transaction():
            row = self.connection.execute("SELECT response_json FROM forecasts WHERE idempotency_key=? AND environment=?", (idempotency_key, self.environment)).fetchone()
            if row:
                return json.loads(row[0]), True
            alert_id = response["alert_id"]
            row = self.connection.execute("SELECT last_revision FROM alert_revisions WHERE environment=? AND alert_id=?", (self.environment, alert_id)).fetchone()
            revision = row[0] + 1 if row else 1
            self.connection.execute("INSERT INTO alert_revisions VALUES(?,?,?) ON CONFLICT(environment,alert_id) DO UPDATE SET last_revision=excluded.last_revision", (self.environment, alert_id, revision))
            saved = json.loads(canonical_json(response))
            saved["history"] = {"forecast_id": uuid.uuid4().hex, "revision": revision, "persisted": True,
                                "evidence_storage": "full" if self.store_full_evidence else "references_and_hashes"}
            stored_input = {**normalized_input, "environment": self.environment} if self.store_full_evidence else {
                "environment": self.environment,
                "alert_id": alert_id, "analyst_revision": response["analyst_revision"],
                "input_fingerprint": response["input_fingerprint"], "evidence_references": response["evidence_references"]}
            created_at = storage_time(datetime.now(timezone.utc))
            self.connection.execute("INSERT INTO forecasts VALUES(?,?,?,?,?,?,?,?,?)", (
                saved["history"]["forecast_id"], self.environment, alert_id, revision, idempotency_key,
                response["input_fingerprint"], created_at, canonical_json(saved), canonical_json(stored_input)))
            for item in saved["unsupported_starting_techniques"]:
                self.connection.execute("INSERT OR IGNORE INTO unsupported VALUES(?,?,?,?,?)", (saved["history"]["forecast_id"], self.environment, item["technique_id"], item["reason"], canonical_json(item)))
            accumulate_unsupported(self.connection, saved, self.environment, created_at, idempotency_key)
            return saved, False

    def record_attempt(self, metrics, forecast_id=None):
        if metrics.get("environment") != self.environment:
            raise ValueError("Attempt environment and history environment must agree")
        with self._transaction():
            if forecast_id is not None and not self.connection.execute("SELECT 1 FROM forecasts WHERE forecast_id=? AND environment=?", (forecast_id, self.environment)).fetchone():
                raise ValueError("Attempt cannot refer to a forecast in another environment")
            self.connection.execute("INSERT INTO attempts VALUES(?,?,?,?,?)", (uuid.uuid4().hex, self.environment, forecast_id, storage_time(datetime.now(timezone.utc)), canonical_json(metrics)))

    def get(self, forecast_id):
        with self._lock:
            row = self.connection.execute("SELECT response_json FROM forecasts WHERE forecast_id=? AND environment=?", (forecast_id, self.environment)).fetchone()
        return json.loads(row[0]) if row else None

    def history(self, alert_id, *, limit=100, environment=None):
        if type(limit) is not int or limit < 1:
            raise ValueError("limit must be a positive integer")
        environment = validate_environment(environment or self.environment, allow_all=True)
        with self._lock:
            rows = self.connection.execute("SELECT response_json FROM forecasts WHERE alert_id=? AND (?='all' OR environment=?) ORDER BY created_at DESC,revision DESC LIMIT ?", (alert_id, environment, environment, limit)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def unsupported_report(self, *, metadata=None, environment=None):
        from .provenance import provenance
        from .config import ForecastConfig
        environment = validate_environment(environment or self.environment, allow_all=True)
        with self._lock:
            rows = self.connection.execute("SELECT u.*,f.alert_id,f.created_at,f.response_json FROM unsupported u JOIN forecasts f USING(forecast_id) WHERE (?='all' OR u.environment=?) ORDER BY u.environment,u.technique_id,u.reason,f.created_at", (environment, environment)).fetchall()
            aggregates = self.connection.execute("SELECT a.*,(SELECT COUNT(*) FROM unsupported_alerts d WHERE d.environment=a.environment AND d.technique_id=a.technique_id AND d.reason=a.reason) AS alert_count FROM unsupported_aggregates a WHERE (?='all' OR a.environment=?) ORDER BY a.environment,a.technique_id,a.reason", (environment, environment)).fetchall()
        groups = {}
        for row in rows:
            key = row["environment"], row["technique_id"], row["reason"]
            details, response = json.loads(row["details_json"]), json.loads(row["response_json"])
            group = groups.setdefault(key, {"environment": key[0], "technique_id": key[1], "reason": key[2], "forecast_count": 0,
                                           "alert_ids": set(), "first_seen": row["created_at"], "last_seen": row["created_at"],
                                           "evidence_refs": set(), "rule_versions": set(), "analyst_confidences": []})
            for name in ("agent", "config", "weights"):
                group.setdefault(name + "_versions", set()).add(response["versions"][name])
            group["forecast_count"] += 1
            group["alert_ids"].add(row["alert_id"])
            group["last_seen"] = row["created_at"]
            group["evidence_refs"].update(details.get("evidence_refs", []))
            group["rule_versions"].add(response["versions"]["rules"])
            confidence = response.get("analyst_confidence")
            if confidence is not None:
                group["analyst_confidences"].append(confidence)
        output = []
        for aggregate in aggregates:
            key = aggregate["environment"], aggregate["technique_id"], aggregate["reason"]
            group = groups.get(key, {"environment": key[0], "technique_id": key[1], "reason": key[2], "alert_ids": set(), "evidence_refs": set(), "analyst_confidences": []})
            group["retained_forecast_count"] = group.get("forecast_count", 0)
            group.update(forecast_count=aggregate["forecast_count"], alert_count=aggregate["alert_count"], first_seen=aggregate["first_seen"], last_seen=aggregate["last_seen"])
            versions = json.loads(aggregate["versions_json"])
            for name, values in versions.items():
                group[("rule" if name == "rules" else name) + "_versions"] = values
            group["analyst_confidence_summary"] = {"count": aggregate["confidence_count"], "mean": aggregate["confidence_sum"] / aggregate["confidence_count"] if aggregate["confidence_count"] else None}
            for key in ("alert_ids", "evidence_refs", "rule_versions", "agent_versions", "config_versions", "weights_versions"):
                group[key] = sorted(group[key])
            output.append(group)
        return {**(metadata or provenance(ForecastConfig(environment=self.environment))), "response_type": "unsupported_report", "report_type": "unsupported_techniques", "items": output, "environment_filter": environment,
                "counting_basis": "durable unique-assessment aggregates survive purge; redeliveries do not inflate counts; raw references expire"}

    def purge(self, *, now=None):
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            raise ValueError("purge now must be timezone-aware")
        cutoff = storage_time(now - timedelta(days=self.retention_days))
        with self._transaction():
            # FK cascade also removes attempts/unsupported records for old forecasts.
            attempts = self.connection.execute("DELETE FROM attempts WHERE created_at < ? AND environment=?", (cutoff, self.environment)).rowcount
            forecasts = self.connection.execute("DELETE FROM forecasts WHERE created_at < ? AND environment=?", (cutoff, self.environment)).rowcount
        return {"cutoff": cutoff, "forecasts_deleted": forecasts, "standalone_or_old_attempts_deleted": attempts,
                "revision_counters_retained": True, "unsupported_aggregates_retained": True, "environment": self.environment}

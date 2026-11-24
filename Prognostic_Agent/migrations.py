"""Transactional v2 migration and durable unsupported-technique aggregates."""

import json

from .contracts import canonical_json, content_hash

ENVIRONMENTS = ("test", "demo", "production")


def validate_environment(environment, *, allow_all=False):
    if environment not in ENVIRONMENTS and not (allow_all and environment == "all"):
        raise ValueError("environment must be test, demo, or production" + (", or all for report scope" if allow_all else ""))
    return environment


def accumulate_unsupported(connection, response, environment, created_at, assessment_key):
    """Call once for a newly inserted forecast, in the SAME transaction."""
    if not response.get("unsupported_starting_techniques"):
        return
    inserted = connection.execute("INSERT OR IGNORE INTO unsupported_assessment_keys VALUES(?,?)", (environment, content_hash(assessment_key))).rowcount
    if not inserted:
        return
    for item in response.get("unsupported_starting_techniques", []):
        key = environment, item["technique_id"], item["reason"]
        old = connection.execute("SELECT * FROM unsupported_aggregates WHERE environment=? AND technique_id=? AND reason=?", key).fetchone()
        versions = json.loads(old["versions_json"]) if old else {name: [] for name in ("agent", "config", "rules", "weights")}
        for name in versions:
            version = response.get("versions", {}).get(name)
            if version is not None:
                versions[name] = sorted(set(versions[name]) | {str(version)})
        confidence = response.get("analyst_confidence")
        count = (old["confidence_count"] if old else 0) + int(confidence is not None)
        total = (old["confidence_sum"] if old else 0) + (confidence or 0)
        values = (*key, (old["forecast_count"] if old else 0) + 1,
                  min(old["first_seen"], created_at) if old else created_at,
                  max(old["last_seen"], created_at) if old else created_at,
                  canonical_json(versions), total, count)
        connection.execute("INSERT INTO unsupported_aggregates VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(environment,technique_id,reason) DO UPDATE SET forecast_count=excluded.forecast_count,first_seen=excluded.first_seen,last_seen=excluded.last_seen,versions_json=excluded.versions_json,confidence_sum=excluded.confidence_sum,confidence_count=excluded.confidence_count", values)
        connection.execute("INSERT OR IGNORE INTO unsupported_alerts VALUES(?,?,?,?)", (*key, content_hash(response["alert_id"])))


def migrate_v2(connection, environment, applied_at):
    """Rebuild FK-linked v1 tables; all legacy records are conservatively demo."""
    connection.execute("ALTER TABLE schema_migrations ADD COLUMN environment TEXT NOT NULL DEFAULT 'demo' CHECK(environment IN ('test','demo','production'))")
    connection.execute("ALTER TABLE forecasts RENAME TO forecasts_v1")
    connection.execute("CREATE TABLE forecasts(forecast_id TEXT PRIMARY KEY, environment TEXT NOT NULL CHECK(environment IN ('test','demo','production')), alert_id TEXT NOT NULL, revision INTEGER NOT NULL, idempotency_key TEXT NOT NULL, input_fingerprint TEXT NOT NULL, created_at TEXT NOT NULL, response_json TEXT NOT NULL, input_json TEXT NOT NULL, UNIQUE(environment,alert_id,revision),UNIQUE(environment,idempotency_key))")
    for row in connection.execute("SELECT * FROM forecasts_v1").fetchall():
        response, stored_input = json.loads(row["response_json"]), json.loads(row["input_json"])
        response.update(environment="demo", behavioral_score_source="unknown", risk_score_may_include_asset_impact=response.get("risk_score") is not None)
        if "impact_assessment" in response:
            response["impact_assessment"].update(behavioral_score_source="unknown", risk_score_may_include_asset_impact=response["impact_assessment"].get("risk_score") is not None)
        stored_input["environment"] = "demo"
        connection.execute("INSERT INTO forecasts VALUES(?,?,?,?,?,?,?,?,?)", (row["forecast_id"], "demo", row["alert_id"], row["revision"], row["idempotency_key"], row["input_fingerprint"], row["created_at"], canonical_json(response), canonical_json(stored_input)))
    connection.execute("CREATE TABLE attempts_v2(attempt_id TEXT PRIMARY KEY, environment TEXT NOT NULL CHECK(environment IN ('test','demo','production')), forecast_id TEXT REFERENCES forecasts(forecast_id) ON DELETE CASCADE, created_at TEXT NOT NULL, metrics_json TEXT NOT NULL)")
    for row in connection.execute("SELECT * FROM attempts").fetchall():
        metrics = json.loads(row["metrics_json"])
        metrics.update(environment="demo", behavioral_score_source="unknown", risk_score_may_include_asset_impact=metrics.get("risk_score") is not None)
        connection.execute("INSERT INTO attempts_v2 VALUES(?,?,?,?,?)", (row["attempt_id"], "demo", row["forecast_id"], row["created_at"], canonical_json(metrics)))
    connection.execute("CREATE TABLE unsupported_v2(forecast_id TEXT NOT NULL REFERENCES forecasts(forecast_id) ON DELETE CASCADE, environment TEXT NOT NULL CHECK(environment IN ('test','demo','production')), technique_id TEXT NOT NULL, reason TEXT NOT NULL, details_json TEXT NOT NULL, PRIMARY KEY(forecast_id,technique_id,reason))")
    connection.execute("INSERT INTO unsupported_v2 SELECT forecast_id,'demo',technique_id,reason,details_json FROM unsupported")
    for name in ("attempts", "unsupported"):
        connection.execute(f"DROP TABLE {name}")
        connection.execute(f"ALTER TABLE {name}_v2 RENAME TO {name}")
    connection.execute("DROP TABLE forecasts_v1")
    connection.execute("CREATE INDEX forecasts_alert_time ON forecasts(environment,alert_id,created_at)")
    connection.execute("CREATE INDEX attempts_time ON attempts(environment,created_at)")
    connection.execute("CREATE TABLE alert_revisions_v2(environment TEXT NOT NULL CHECK(environment IN ('test','demo','production')),alert_id TEXT NOT NULL,last_revision INTEGER NOT NULL,PRIMARY KEY(environment,alert_id))")
    connection.execute("INSERT INTO alert_revisions_v2 SELECT 'demo',alert_id,last_revision FROM alert_revisions")
    connection.execute("DROP TABLE alert_revisions")
    connection.execute("ALTER TABLE alert_revisions_v2 RENAME TO alert_revisions")
    connection.execute("CREATE TABLE unsupported_aggregates(environment TEXT NOT NULL CHECK(environment IN ('test','demo','production')),technique_id TEXT NOT NULL,reason TEXT NOT NULL,forecast_count INTEGER NOT NULL,first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,versions_json TEXT NOT NULL,confidence_sum REAL NOT NULL,confidence_count INTEGER NOT NULL,PRIMARY KEY(environment,technique_id,reason))")
    connection.execute("CREATE TABLE unsupported_alerts(environment TEXT NOT NULL CHECK(environment IN ('test','demo','production')),technique_id TEXT NOT NULL,reason TEXT NOT NULL,alert_hash TEXT NOT NULL,PRIMARY KEY(environment,technique_id,reason,alert_hash))")
    connection.execute("CREATE TABLE unsupported_assessment_keys(environment TEXT NOT NULL CHECK(environment IN ('test','demo','production')),assessment_hash TEXT NOT NULL,PRIMARY KEY(environment,assessment_hash))")
    for row in connection.execute("SELECT environment,created_at,response_json,idempotency_key FROM forecasts").fetchall():
        accumulate_unsupported(connection, json.loads(row["response_json"]), row["environment"], row["created_at"], row["idempotency_key"])
    connection.execute("INSERT INTO schema_migrations VALUES(2,?,?)", (applied_at, environment))

"""Explicit JSON/CSV exports and descriptive shadow summaries (no outcome claims)."""

import csv
import json
from pathlib import Path


def export_unsupported(history, path, *, format="json", metadata=None, environment=None):
    if format not in {"json", "csv"}:
        raise ValueError("format must be json or csv")
    report = history.unsupported_report(metadata=metadata, environment=environment)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation avoids silently overwriting a previous export.
    with open(path, "x", encoding="utf-8", newline="") as stream:
        if format == "json":
            json.dump(report, stream, indent=2, allow_nan=False)
            stream.write("\n")
        elif format == "csv":
            fields = ["environment", "technique_id", "reason", "forecast_count", "retained_forecast_count", "alert_count", "first_seen", "last_seen", "alert_ids", "evidence_refs", "rule_versions", "agent_versions", "config_versions", "weights_versions", "analyst_confidences", "analyst_confidence_summary"]
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            for item in report["items"]:
                writer.writerow({key: json.dumps(value) if isinstance(value, (list, dict)) else value for key, value in item.items()})
        else:
            raise ValueError("format must be json or csv")
    return report


def shadow_summary(history, *, environment=None):
    from collections import Counter
    from .migrations import validate_environment
    environment = validate_environment(environment or history.environment, allow_all=True)
    with history._lock:
        rows = history.connection.execute("SELECT metrics_json FROM attempts WHERE (?='all' OR environment=?)", (environment, environment)).fetchall()
    metrics = [json.loads(row[0]) for row in rows]
    latencies = sorted(item["total_ms"] for item in metrics)

    def percentile(p):
        import math
        return latencies[max(0, math.ceil(p * len(latencies)) - 1)] if latencies else None

    return {"schema_version": 1, "attempt_count": len(metrics), "environment_filter": environment,
            "statuses": dict(Counter(item.get("status") or item["response_type"] for item in metrics)),
            "reasons": dict(Counter(item.get("reason") or "validation_error" for item in metrics)),
            "idempotent_replays": sum(item["idempotent_replay"] for item in metrics),
            "invalid_technique_inputs": sum(item["invalid_technique_count"] for item in metrics),
            "latency_ms": {"p50": percentile(.50), "p95": percentile(.95), "p99": percentile(.99)},
            "outcome_metrics": None, "outcome_note": "No inferred negatives or outcome metrics before observed follow-up."}

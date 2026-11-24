"""Read stable backend snapshots; persist ONLY demo assessments in this package.

SQLite immutable read mode cannot create backend journal/WAL/SHM files. An
uncheckpointed WAL or active rollback journal is refused, not silently ignored.
"""

from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import heapq
import json
from pathlib import Path
import sqlite3
import uuid

from .analyst_adapter import adapt_analyst_incident
from .config import AGENT_DIR, ForecastConfig
from .contracts import parse_time, validation_error
from .provenance import provenance
from .service import ForecastService, shadow_metrics
from .storage import DEFAULT_HISTORY_PATH, ForecastHistory

DEFAULT_SOURCE_PATH = AGENT_DIR.parent / "backend" / "soc_agents.db"
PRIORITY = {"suspicious": 0, "malicious": 1, "benign": 2, "unknown": 3}


def _owned_path(path):
    resolved = Path(path).resolve()
    if not resolved.is_relative_to(AGENT_DIR.resolve()):
        raise ValueError("Batch replay outputs must stay inside Prognostic_Agent")
    return resolved


def _file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_stable_snapshot(path):
    if not path.is_file():
        raise ValueError("Backend source database must already exist")
    for suffix in ("-wal", "-journal"):
        companion = Path(str(path) + suffix)
        if companion.exists() and companion.stat().st_size:
            raise ValueError("Backend has an uncheckpointed WAL or rollback journal; provide a stable checkpointed snapshot. Replay never checkpoints or writes the backend.")


def _verdict(incident):
    analysis = incident.get("risk_analysis") if isinstance(incident, dict) else None
    value = analysis.get("verdict") if isinstance(analysis, dict) else None
    return value if isinstance(value, str) and value in PRIORITY else "unknown"


def select_incidents(source_db, limit, *, eligible=None):
    """Select at most N rows, prioritizing suspicious; retain only N payloads."""
    if type(limit) is not int or not 1 <= limit <= 10000:
        raise ValueError("limit must be an integer in [1, 10000]")
    source = Path(source_db).resolve()
    _require_stable_snapshot(source)
    before = _file_hash(source)
    heap, verdicts, total, eligible_count = [], Counter(), 0, 0
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro&immutable=1", uri=True)) as connection:
        connection.execute("PRAGMA query_only=ON")
        columns = {row[1] for row in connection.execute("PRAGMA table_info(incidents)")}
        if not {"incident_id", "detected_at", "payload"} <= columns:
            raise ValueError("Source must contain incidents(incident_id, detected_at, payload)")
        cursor = connection.execute("SELECT incident_id,payload FROM incidents ORDER BY detected_at DESC,incident_id")
        for index, (identity, raw) in enumerate(cursor):
            total += 1
            try:
                incident = json.loads(raw)
            except (ValueError, TypeError):
                incident = None
            verdict = _verdict(incident)
            verdicts[verdict] += 1
            selected = {"source_incident_id": identity, "incident": incident, "analyst_verdict": verdict,
                        "source_payload_sha256": hashlib.sha256(str(raw).encode("utf-8")).hexdigest()}
            if eligible is not None and not eligible(selected):
                continue
            eligible_count += 1
            entry = (-PRIORITY[verdict], -index, selected)
            if len(heap) < limit:
                heapq.heappush(heap, entry)
            elif entry[:2] > heap[0][:2]:
                heapq.heapreplace(heap, entry)
    _require_stable_snapshot(source)
    if before != _file_hash(source):
        raise ValueError("Backend changed during reading; use a stable snapshot. No replay results were written.")
    selected = [item[2] for item in sorted(heap, key=lambda item: (-item[0], -item[1]))]
    return selected, {"source_database": str(source), "source_sha256": before, "source_incident_count": total,
                      "eligible_incident_count": eligible_count,
                      "available_analyst_verdict_counts": dict(sorted(verdicts.items())),
                      "selection": "suspicious, malicious, benign, unknown; newest detected_at first within each category",
                      "source_access": "immutable read-only; nonempty WAL/journal refused; SHA-256 verified before/after selection"}


def replay_batch(source_db=DEFAULT_SOURCE_PATH, *, limit=20, history_path=DEFAULT_HISTORY_PATH,
                 config=None, forecast_as_of=None, asset_provider=None, evaluation_id=None, output_dir=None):
    """Persist forecast/attempt records as demo and return a per-run summary.

    Unknown/untriaged legacy rows are NOT relabeled benign or silently skipped.
    They go through the adapter and appear as validation errors when incomplete.
    """
    config = config or ForecastConfig(environment="demo")
    if config.environment != "demo":
        raise ValueError("Batch replay always writes environment=demo")
    destination = _owned_path(history_path)
    export_dir = _owned_path(output_dir) if output_dir is not None else None
    if destination == Path(source_db).resolve():
        raise ValueError("Source database and replay history must be different files")
    override = parse_time(forecast_as_of) if isinstance(forecast_as_of, str) else forecast_as_of
    if override is not None and (override.tzinfo is None or override.utcoffset() is None):
        raise ValueError("Replay cutoff must be timezone-aware")
    selected, source_metadata = select_incidents(source_db, limit)
    metadata = provenance(config)
    statuses, reasons, verdicts, issue_counts = Counter(), Counter(), Counter(), Counter()
    techniques, technique_reasons = Counter(), defaultdict(Counter)
    results, new_count, replay_count = [], 0, 0
    with ForecastHistory(destination, environment="demo", retention_days=config.history_retention_days,
                         busy_timeout_ms=config.sqlite_busy_timeout_ms, store_full_evidence=config.store_full_evidence) as history:
        service = ForecastService(history, config=config)
        for row in selected:
            request = None
            try:
                request = adapt_analyst_incident(row["incident"])
                cutoff = override
                if cutoff is None:
                    try:
                        cutoff = parse_time(request["timestamp"])
                    except (ValueError, TypeError, AttributeError):
                        # Invalid input remains invalid; do not invent a triage time.
                        cutoff = None
                response = service.assess(request, forecast_as_of=cutoff, asset_provider=asset_provider, evaluation_id=evaluation_id)
            except (ValueError, TypeError, AttributeError, KeyError) as exc:
                response = validation_error({"alert_id": row["source_incident_id"]},
                                            [{"field": "$incident", "code": "invalid_analyst_incident", "message": type(exc).__name__}], metadata=metadata)
                history.record_attempt(shadow_metrics(response, {}, elapsed_ms=0))
            status = response.get("status") or response["response_type"]
            reason = response.get("reason") or response["response_type"]
            statuses[status] += 1
            reasons[reason] += 1
            verdicts[row["analyst_verdict"]] += 1
            issues = (request or {}).get("adapter_issues", []) + response.get("issues", [])
            issue_counts.update({item["code"] for item in issues})
            seen = set()
            for item in response.get("unsupported_starting_techniques", []):
                identity = item["technique_id"]
                technique_reasons[identity][item["reason"]] += 1
                seen.add(identity)
            techniques.update(seen)
            stored = response.get("history", {})
            if stored.get("persisted"):
                if stored.get("idempotent_replay"):
                    replay_count += 1
                else:
                    new_count += 1
            results.append({key: value for key, value in row.items() if key != "incident"} |
                           {"adapter_issues": (request or {}).get("adapter_issues", []), "result": response})
    summary = {
        **metadata, "response_type": "batch_replay_result", "batch_id": uuid.uuid4().hex,
        **source_metadata, "requested_limit": limit, "processed_count": len(results),
        "selected_analyst_verdict_counts": dict(sorted(verdicts.items())),
        "status_counts": dict(sorted(statuses.items())), "reason_counts": dict(sorted(reasons.items())),
        "issue_counts": dict(sorted(issue_counts.items())),
        "top_unsupported_techniques": [{"technique_id": identity, "incident_count": count,
                                        "reasons": dict(sorted(technique_reasons[identity].items()))}
                                       for identity, count in sorted(techniques.items(), key=lambda item: (-item[1], item[0]))[:10]],
        "cutoff_mode": "explicit_override" if override is not None else "stored_analyst_triage_time; missing/invalid times stay validation errors",
        "new_forecasts": new_count, "replayed_forecasts": replay_count,
        "history_database": str(destination),
        "summary_basis": "selected incidents in this run, including replay deliveries; not lifetime history aggregates",
        "results": [{"source_incident_id": item["source_incident_id"], "analyst_verdict": item["analyst_verdict"],
                     "response_type": item["result"]["response_type"], "status": item["result"].get("status"),
                     "reason": item["result"].get("reason"), "history": item["result"].get("history")} for item in results],
    }
    if export_dir is not None:
        export_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        path = export_dir / f"batch_replay_{stamp}_{summary['batch_id']}.json"
        summary["results_file"] = str(path)
        with path.open("x", encoding="utf-8") as stream:
            json.dump({**summary, "results": results}, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
    return summary

"""File-only source snapshot: never open the backend with writable SQLite access.

Copy a stable DB/WAL pair, then recover/checkpoint only the private copy. Refuse
active rollback journals and changing sources; never checkpoint the source DB.
"""

import hashlib
from contextlib import closing
import json
from pathlib import Path
import shutil
import sqlite3
from datetime import datetime, timezone

from .config import AGENT_DIR
from .contracts import utc_text
from .private_paths import private_path, write_private


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_manifest(source):
    if not source.is_file():
        raise ValueError("Backend source database must exist")
    journal = Path(str(source) + "-journal")
    if journal.exists() and journal.stat().st_size:
        raise ValueError("Active rollback journal: retry after ingestion commits; source is never recovered or written")
    result = {"database": sha256_file(source)}
    wal = Path(str(source) + "-wal")
    if wal.exists() and wal.stat().st_size:
        result["wal"] = sha256_file(wal)
    return result


def snapshot_source(source, destination):
    source, destination = Path(source).resolve(), private_path(destination)
    if destination.exists():
        raise ValueError("Snapshot destination must be new")
    destination.mkdir(parents=True)
    last_error = None
    for attempt in range(1, 4):
        copied = destination / ("capture_" + str(attempt) + ".db")
        try:
            before = source_manifest(source)
            shutil.copyfile(source, copied)
            if "wal" in before:
                shutil.copyfile(Path(str(source) + "-wal"), Path(str(copied) + "-wal"))
            after = source_manifest(source)
            copied_hashes = {"database": sha256_file(copied)}
            if "wal" in before:
                copied_hashes["wal"] = sha256_file(str(copied) + "-wal")
            if before != after or copied_hashes != before:
                raise ValueError("Source changed while copying")
            with closing(sqlite3.connect(copied, timeout=5)) as connection:
                connection.execute("PRAGMA busy_timeout=5000")
                checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                if checkpoint[0]:
                    raise ValueError("Private snapshot checkpoint was busy")
                connection.execute("PRAGMA journal_mode=DELETE")
                if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise ValueError("Private snapshot failed SQLite quick_check")
            result = {"schema_version": 1, "environment": "test", "source_database": str(source),
                      "source_identity": hashlib.sha256(str(source).casefold().encode()).hexdigest(),
                      "captured_at": utc_text(datetime.now(timezone.utc)), "source_hashes": before,
                      "snapshot_path": str(copied), "snapshot_sha256": sha256_file(copied),
                      "source_access": "file reads only; stable DB/WAL copy; recovery/checkpoint on private copy only"}
            write_private(destination / "source_snapshot.json", result)
            return result
        except (OSError, ValueError, sqlite3.Error) as exc:
            last_error = exc
    raise ValueError("No stable read-only source snapshot after three attempts: " + str(last_error))


def inspect_snapshot(snapshot, *, now=None):
    now = now or datetime.now(timezone.utc)
    from .contracts import parse_time
    connection = sqlite3.connect(Path(snapshot["snapshot_path"]).as_uri() + "?mode=ro&immutable=1", uri=True)
    counts = {"total": 0, "behavioral_score_present": 0, "technique_evidence_present": 0, "triaged_in_last_24h": 0,
              "recent_incidents_with_both_fields": 0}
    latest = []
    try:
        connection.execute("PRAGMA query_only=ON")
        for identity, detected, raw in connection.execute("SELECT incident_id,detected_at,payload FROM incidents ORDER BY detected_at DESC,incident_id"):
            counts["total"] += 1
            try:
                incident = json.loads(raw)
                analysis = incident.get("risk_analysis") or {}
                if not isinstance(analysis, dict):
                    analysis = {}
            except (TypeError, ValueError, AttributeError):
                analysis = {}
            has_score, has_attribution = "behavioral_score" in analysis, "technique_evidence" in analysis
            counts["behavioral_score_present"] += has_score
            counts["technique_evidence_present"] += has_attribution
            try:
                recent = 0 <= (now - parse_time(analysis.get("triaged_at"))).total_seconds() <= 86400
                counts["triaged_in_last_24h"] += recent
                counts["recent_incidents_with_both_fields"] += recent and has_score and has_attribution
            except (ValueError, TypeError, AttributeError):
                pass
            if len(latest) < 5:
                latest.append({"incident_id": identity, "detected_at": detected, "triaged_at": analysis.get("triaged_at"),
                               "verdict": analysis.get("verdict"), "behavioral_score_present": has_score,
                               "behavioral_score": analysis.get("behavioral_score"), "behavioral_score_stale": analysis.get("behavioral_score_stale"),
                               "technique_evidence_present": has_attribution, "technique_evidence": analysis.get("technique_evidence")})
    finally:
        connection.close()
    return {"schema_version": 1, "environment": "test", "checked_at": utc_text(now), **counts, "latest_incidents": latest,
            "recent_incident_available": bool(counts["triaged_in_last_24h"]),
            "fresh_additive_fields_confirmed": bool(counts["recent_incidents_with_both_fields"]),
            "note": "Read-only inspection; no ingestion, re-triage, or field backfill was performed.",
            "analyst_source_mtime_utc": utc_text(datetime.fromtimestamp((AGENT_DIR.parent / "backend" / "analyst.py").stat().st_mtime, timezone.utc))}

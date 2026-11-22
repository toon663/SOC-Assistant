"""SQLite persistence for events, incidents, and audit records."""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any, Iterable, Optional

from agents import Incident, incident_from_dict, incident_to_dict


class IncidentRepository:
    def __init__(self, path: str = "soc_agents.db"):
        self.path = path
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.RLock()
        self.connection.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self) -> None:
        with self._lock:
            self.connection.executescript(
                """
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                detected_at TEXT NOT NULL,
                status TEXT NOT NULL,
                risk_score REAL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                agent TEXT NOT NULL,
                action TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ingested_events (
                event_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS incident_groups (
                group_key TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL
            );
                """
            )
            self.connection.commit()

    def is_event_ingested(self, event_id: str) -> bool:
        with self._lock:
            row = self.connection.execute("SELECT 1 FROM ingested_events WHERE event_id = ?", (event_id,)).fetchone()
        return row is not None

    def count_events_in_resolved(self, event_ids: Iterable[str]) -> int:
        """How many of these already-processed events belong to resolved incidents."""
        ids = list(event_ids)
        total = 0
        with self._lock:
            # Chunked to stay under SQLite's bound-parameter limit.
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                placeholders = ",".join("?" * len(chunk))
                total += self.connection.execute(
                    f"""SELECT COUNT(*) FROM ingested_events e
                        JOIN incidents i ON i.incident_id = e.incident_id
                        WHERE i.status = 'resolved' AND e.event_id IN ({placeholders})""",
                    chunk,
                ).fetchone()[0]
        return total

    def find_open_incident(self, group_key: str) -> Optional[dict[str, Any]]:
        """Return the unresolved incident for a group; acted-on incidents are not reopened."""
        with self._lock:
            row = self.connection.execute(
                """SELECT i.payload FROM incident_groups g
                   JOIN incidents i ON i.incident_id = g.incident_id
                   WHERE g.group_key = ? AND i.status IN ('open', 'approval_required')""",
                (group_key,),
            ).fetchone()
        return json.loads(row["payload"]) if row else None

    def save_incident(
        self,
        incident: Incident,
        *,
        ingested_event_ids: Iterable[str] = (),
        group_key: Optional[str] = None,
    ) -> None:
        """Persist an incident, its processed event IDs, and its repeat-event group."""
        payload = incident_to_dict(incident)
        with self._lock:
            self.connection.execute(
                "INSERT OR REPLACE INTO incidents VALUES (?, ?, ?, ?, ?)",
                (incident.incident_id, incident.detected_at, incident.action_result.get("status", "open"), incident.forecast.get("forecast_score", 0), json.dumps(payload)),
            )
            self.connection.execute("DELETE FROM audit_log WHERE incident_id = ?", (incident.incident_id,))
            self.connection.executemany(
                "INSERT INTO audit_log (incident_id, timestamp, agent, action, payload) VALUES (?, ?, ?, ?, ?)",
                [(incident.incident_id, item.get("timestamp", ""), item.get("agent", ""), item.get("action", ""), json.dumps(item)) for item in incident.audit_log],
            )
            self.connection.executemany(
                "INSERT OR IGNORE INTO ingested_events (event_id, incident_id) VALUES (?, ?)",
                [(event_id, incident.incident_id) for event_id in ingested_event_ids],
            )
            if group_key is not None:
                self.connection.execute(
                    "INSERT OR REPLACE INTO incident_groups (group_key, incident_id) VALUES (?, ?)",
                    (group_key, incident.incident_id),
                )
            self.connection.commit()

    def get_incident(self, incident_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self.connection.execute("SELECT payload FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        return json.loads(row["payload"]) if row else None

    def resolve_incident(self, incident_id: str, *, resolved_at: str, note: str = "") -> Optional[dict[str, Any]]:
        """Mark an incident resolved; a later repeat of its events opens a new incident."""
        with self._lock:
            row = self.connection.execute("SELECT payload FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
            if row is None:
                return None
            payload = json.loads(row["payload"])
            previous = payload.get("action_result", {}).get("status", "open")
            payload["action_result"] = {**payload.get("action_result", {}), "status": "resolved", "previous_status": previous, "resolved_at": resolved_at, "resolution_note": note}
            entry = {"timestamp": resolved_at, "agent": "analyst", "action": "resolve_incident", "previous_status": previous, "note": note}
            payload.setdefault("audit_log", []).append(entry)
            self.connection.execute(
                "UPDATE incidents SET status = 'resolved', payload = ? WHERE incident_id = ?",
                (json.dumps(payload), incident_id),
            )
            self.connection.execute(
                "INSERT INTO audit_log (incident_id, timestamp, agent, action, payload) VALUES (?, ?, ?, ?, ?)",
                (incident_id, resolved_at, "analyst", "resolve_incident", json.dumps(entry)),
            )
            self.connection.commit()
        return payload

    def forget_processed_events(self) -> int:
        """Dev mode: let the next collection treat already-seen log records as new.

        Incidents are kept; group links are cleared so replayed records open fresh
        incidents instead of merging into existing ones.
        """
        with self._lock:
            count = self.connection.execute("SELECT COUNT(*) FROM ingested_events").fetchone()[0]
            self.connection.execute("DELETE FROM ingested_events")
            self.connection.execute("DELETE FROM incident_groups")
            self.connection.commit()
        return count

    def wipe_all(self) -> int:
        """Dev mode: delete every incident, audit record, and processed-event record."""
        with self._lock:
            count = self.connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            for table in ("incidents", "audit_log", "ingested_events", "incident_groups"):
                self.connection.execute(f"DELETE FROM {table}")
            self.connection.commit()
        return count

    def recent_incidents_on_host(self, host: Optional[str], limit: int = 200) -> list[dict[str, Any]]:
        """Newest incidents whose primary event is on this host, for Analyst correlation."""
        return [item for item in self.list_incidents(limit) if item.get("events") and item["events"][0].get("host") == host]

    def list_incidents(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.connection.execute("SELECT payload FROM incidents ORDER BY detected_at DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def close(self) -> None:
        self.connection.close()

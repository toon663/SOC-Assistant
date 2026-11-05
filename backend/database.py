"""SQLite persistence for events, incidents, and audit records."""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any, Callable, Optional

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
                """
            )
            self.connection.commit()

    def save_incident(self, incident: Incident) -> dict[str, Any]:
        """Persist a new incident; repeated ingestion preserves existing decisions."""
        with self._lock, self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            existing = self.get_incident(incident.incident_id)
            if existing is not None:
                return existing
            self._write_incident(incident)
            return incident_to_dict(incident)

    def update_pending_incident(
        self, incident_id: str, update: Callable[[Incident], None]
    ) -> dict[str, Any]:
        """Serialize decisions across connections and reject repeated decisions."""
        with self._lock, self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            payload = self.get_incident(incident_id)
            if payload is None:
                raise LookupError("incident not found")
            if payload.get("action_result", {}).get("status") != "approval_required":
                raise ValueError("This incident is no longer awaiting approval")
            incident = incident_from_dict(payload)
            update(incident)
            self._write_incident(incident)
            return incident_to_dict(incident)

    def _write_incident(self, incident: Incident) -> None:
        """Write incident and audit rows inside the caller's transaction."""
        payload = incident_to_dict(incident)
        self.connection.execute(
            "INSERT OR REPLACE INTO incidents VALUES (?, ?, ?, ?, ?)",
            (incident.incident_id, incident.detected_at, incident.action_result.get("status", "open"), incident.forecast.get("forecast_score", 0), json.dumps(payload)),
        )
        self.connection.execute("DELETE FROM audit_log WHERE incident_id = ?", (incident.incident_id,))
        self.connection.executemany(
            "INSERT INTO audit_log (incident_id, timestamp, agent, action, payload) VALUES (?, ?, ?, ?, ?)",
            [(incident.incident_id, item.get("timestamp", ""), item.get("agent", ""), item.get("action", ""), json.dumps(item)) for item in incident.audit_log],
        )

    def get_incident(self, incident_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self.connection.execute("SELECT payload FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        return json.loads(row["payload"]) if row else None

    def list_incidents(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.connection.execute("SELECT payload FROM incidents ORDER BY detected_at DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def close(self) -> None:
        self.connection.close()

"""SQLite persistence for events, incidents, and audit records."""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Optional

from agents import Incident, incident_to_dict


class IncidentRepository:
    def __init__(self, path: str = "soc_agents.db"):
        self.path = path
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self) -> None:
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

    def save_incident(self, incident: Incident) -> None:
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
        self.connection.commit()

    def get_incident(self, incident_id: str) -> Optional[dict[str, Any]]:
        row = self.connection.execute("SELECT payload FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        return json.loads(row["payload"]) if row else None

    def list_incidents(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT payload FROM incidents ORDER BY detected_at DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def close(self) -> None:
        self.connection.close()

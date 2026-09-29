""""Optional FastAPI interface for submitting and reviewing incidents."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from agents import SecurityEvent, SecurityOperationsPipeline, Severity, incident_to_dict, utc_now
from config import settings
from database import IncidentRepository
from integrations import IntegrationHub

try:
    from fastapi import FastAPI, HTTPException
except ImportError:  # pragma: no cover - exercised only without optional dependencies
    FastAPI = None
    HTTPException = RuntimeError


def create_app():
    if FastAPI is None:
        raise RuntimeError("FastAPI is not installed; run: pip install -r requirements.txt")

    app = FastAPI(title=settings.app_name)
    systems = IntegrationHub()
    repository = IncidentRepository(settings.database_path)
    pipeline = SecurityOperationsPipeline(systems=systems, require_approval=settings.require_human_approval)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "environment": settings.environment}

    @app.post("/events")
    def submit_events(payload: dict[str, Any]) -> dict[str, Any]:
        raw_events = payload.get("events", [])
        if not raw_events:
            raise HTTPException(status_code=400, detail="events must contain at least one event")
        try:
            events = [
                SecurityEvent(
                    event_id=str(item["event_id"]),
                    timestamp=item.get("timestamp", utc_now()),
                    source=str(item.get("source", "api")),
                    event_type=str(item["event_type"]),
                    user=item.get("user"),
                    host=item.get("host"),
                    source_ip=item.get("source_ip"),
                    destination=item.get("destination"),
                    message=item.get("message", ""),
                    severity=Severity(item.get("severity", "low")),
                    metadata=item.get("metadata", {}),
                )
                for item in raw_events
            ]
            incident = pipeline.run(events, approved=False)
            repository.save_incident(incident)
            return incident_to_dict(incident)
        except (KeyError, ValueError, TypeError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/incidents")
    def list_incidents(limit: int = 100) -> list[dict[str, Any]]:
        return repository.list_incidents(max(1, min(limit, 500)))

    @app.get("/incidents/{incident_id}")
    def get_incident(incident_id: str) -> dict[str, Any]:
        incident = repository.get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        return incident

    return app


app = create_app() if FastAPI is not None else None

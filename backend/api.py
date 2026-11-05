""""Optional FastAPI interface for submitting and reviewing incidents."""
from __future__ import annotations

from pathlib import Path
import logging
from fastapi.staticfiles import StaticFiles



from dataclasses import asdict
from typing import Any

from agents import SecurityEvent, SecurityOperationsPipeline, Severity, utc_now
from config import settings
from database import IncidentRepository
from integrations import IntegrationHub
from gatherer import gather_security_events

try:
    from fastapi import FastAPI, HTTPException
except ImportError:  # pragma: no cover - exercised only without optional dependencies
    FastAPI = None
    HTTPException = RuntimeError


def create_app():
    if FastAPI is None:
        raise RuntimeError("FastAPI is not installed; run: pip install -r requirements.txt")

    app = FastAPI(title=settings.app_name)

    @app.get("/")
    def root():
        return {
            "name": "SOC Multi-Agent Platform",
            "status": "running",
            "frontend": "/app/",
            "docs": "/docs",
        }


    systems = IntegrationHub()
    repository = IncidentRepository(settings.database_path)
    pipeline = SecurityOperationsPipeline(systems=systems, require_approval=settings.require_human_approval)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "environment": settings.environment}

    @app.post("/scan")
    def scan_computer() -> dict[str, Any]:
        """Scan the backend host on demand; persist an incident only for findings."""
        try:
            batch = gather_security_events()
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except (RuntimeError, OSError) as exc:
            logging.getLogger(__name__).exception("Computer scan failed")
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        events = pipeline.sentinel.inspect_computer(batch)
        incident = None
        if events:
            incident = pipeline.run(events, approved=False)
            incident = repository.save_incident(incident)
        return {
            "snapshot": asdict(batch),
            "anomalies": [event.metadata for event in events],
            "incident": incident,
        }



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
            return repository.save_incident(incident)
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

    @app.post("/incidents/{incident_id}/decision")
    def decide_incident(incident_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        decision = payload.get("decision")
        reviewer = payload.get("reviewer")
        reason = payload.get("reason")
        if not isinstance(decision, str) or decision not in {"approve", "deny"}:
            raise HTTPException(status_code=422, detail="decision must be approve or deny")
        if not isinstance(reviewer, str) or not reviewer.strip() or len(reviewer) > 200:
            raise HTTPException(status_code=422, detail="reviewer must contain 1 to 200 characters")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
            raise HTTPException(status_code=422, detail="reason must contain 1 to 2000 characters")
        try:
            return repository.update_pending_incident(
                incident_id,
                lambda incident: pipeline.orchestrator.review_response(incident, decision, reviewer, reason),
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc



    frontend_dir = Path(__file__).resolve().parent / "frontend"

    app.mount(
        "/app",
        StaticFiles(directory=frontend_dir, html=True),
        name="frontend",
    )


    
    return app

    



app = create_app() if FastAPI is not None else None

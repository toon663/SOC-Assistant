""""Optional FastAPI interface for submitting and reviewing incidents."""
from __future__ import annotations

from pathlib import Path
from fastapi.staticfiles import StaticFiles



from dataclasses import asdict
from typing import Any

from agents import SecurityEvent, SecurityOperationsPipeline, Severity, incident_to_dict, utc_now
from config import settings
from database import IncidentRepository
from file_scan import ScanUnavailable
from integrations import IntegrationHub
from live_detection import LiveDetector
from windows_ingest import DEFAULT_THRESHOLD, IngestUnavailable, WindowsIngestService

try:
    from fastapi import FastAPI, HTTPException, Query, Request
    from pydantic import BaseModel, Field
except ImportError:  # pragma: no cover - exercised only without optional dependencies
    FastAPI = None
    HTTPException = RuntimeError
    BaseModel = object
    Request = None
    Query = Field = lambda *args, **kwargs: None

MAX_UPLOAD_BYTES = 128 * 1024 * 1024


class WindowsCollectionRequest(BaseModel):
    logs: list[str] = Field(default=["Security", "System", "Application"], min_length=1, max_length=10)
    hours: int = Field(default=24, ge=1, le=720)
    max_events_per_log: int = Field(default=500, ge=1, le=5000)
    threshold: float = Field(default=DEFAULT_THRESHOLD, gt=0, le=1)


class ScanPathRequest(BaseModel):
    path: str = Field(min_length=1, max_length=1024)
    host: str = Field(default="localhost", min_length=1, max_length=255)


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
    windows_ingest = WindowsIngestService(pipeline, repository)
    live = LiveDetector(windows_ingest)

    @app.get("/live/status")
    def live_status() -> dict[str, Any]:
        """Live detection state: running, last/next poll, and running totals."""
        return live.status()

    @app.post("/live/start")
    def live_start() -> dict[str, Any]:
        """Poll this host's Event Viewer every 30 seconds until stopped."""
        try:
            return live.start()
        except IngestUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.post("/live/stop")
    def live_stop() -> dict[str, Any]:
        return live.stop()

    @app.post("/ingest/windows")
    def ingest_windows(request: WindowsCollectionRequest) -> dict[str, Any]:
        """Collect from this host's Event Viewer, detect anomalies, and open incidents."""
        try:
            return windows_ingest.collect_and_ingest(
                logs=request.logs,
                hours=request.hours,
                max_events_per_log=request.max_events_per_log,
                threshold=request.threshold,
            )
        except IngestUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.post("/ingest/document")
    def ingest_document(
        document: dict[str, Any],
        threshold: float = Query(default=DEFAULT_THRESHOLD, gt=0, le=1),
    ) -> dict[str, Any]:
        """Process a saved gatherer JSON export, for example from another machine."""
        try:
            return windows_ingest.ingest_document(document, threshold=threshold)
        except IngestUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/scan/status")
    def scan_status() -> dict[str, Any]:
        """Whether the Sentinel malware scanner and its models are loaded."""
        return windows_ingest.file_scan.status()

    @app.post("/scan/path")
    def scan_path(request: ScanPathRequest) -> dict[str, Any]:
        """Statically scan a file on this server; a flagged file opens an incident."""
        try:
            result = windows_ingest.file_scan.scan_path(request.path)
        except ScanUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except (FileNotFoundError, PermissionError) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return windows_ingest.ingest_scan_result(result, host=request.host, origin="api-path")

    @app.post("/scan/upload")
    async def scan_upload(
        request: Request,
        filename: str = Query(default="upload.bin", min_length=1, max_length=255),
        host: str = Query(default="uploaded-sample", min_length=1, max_length=255),
    ) -> dict[str, Any]:
        """Scan a file sent as the raw request body (application/octet-stream). It is never executed."""
        declared = int(request.headers.get("content-length") or 0)
        if declared > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="file too large")
        data = await request.body()
        if not data:
            raise HTTPException(status_code=400, detail="request body is empty")
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="file too large")
        try:
            result = windows_ingest.file_scan.scan_bytes(data, filename)
        except ScanUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return windows_ingest.ingest_scan_result(result, host=host, origin="api-upload")

    @app.get("/dev/status")
    def dev_status() -> dict[str, Any]:
        """Whether dev mode (SOC_DEV_MODE=1) is on, and which test scenarios it offers."""
        if not settings.dev_mode:
            return {"enabled": False}
        import dev_tools

        return {"enabled": True, "scenarios": dev_tools.list_scenarios(), "malware_samples": dev_tools.malware_samples()}

    if settings.dev_mode:
        # Registered only in dev mode, so these test hooks do not exist otherwise.
        import dev_tools

        @app.post("/dev/scenarios/{name}")
        def run_scenario(name: str, host: str = Query(default=dev_tools.DEFAULT_HOST, min_length=1, max_length=255)) -> dict[str, Any]:
            """Inject a synthetic attack scenario through the full ingest pipeline."""
            try:
                document = dev_tools.build_scenario(name, host)
            except KeyError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            try:
                return windows_ingest.ingest_document(document, source=f"dev-scenario:{name}")
            except IngestUnavailable as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc

        @app.post("/dev/malware-demo")
        def malware_demo(
            sample: str = Query(default="", max_length=64),
            host: str = Query(default=dev_tools.DEFAULT_HOST, min_length=1, max_length=255),
        ) -> dict[str, Any]:
            """Score a stored EMBER2024 test-set malware vector and open the resulting incident."""
            try:
                result = dev_tools.malware_demo_result(windows_ingest.file_scan.scanner, sample or None)
            except ScanUnavailable as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            except FileNotFoundError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            return windows_ingest.ingest_scan_result(result, host=host, origin="dev-demo")

        @app.post("/dev/reset")
        def dev_reset(scope: str = Query(pattern="^(events|all)$")) -> dict[str, Any]:
            """events: forget processed log records so they can be replayed. all: also delete every incident."""
            if scope == "all":
                return {"scope": scope, "incidents_deleted": repository.wipe_all()}
            return {"scope": scope, "events_forgotten": repository.forget_processed_events()}

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

    @app.post("/incidents/{incident_id}/resolve")
    def resolve_incident(incident_id: str) -> dict[str, Any]:
        """Close an incident from the analyst console; it leaves the active queue."""
        incident = repository.resolve_incident(incident_id, resolved_at=utc_now())
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        return incident



    frontend_dir = Path(__file__).resolve().parent / "frontend"

    app.mount(
        "/app",
        StaticFiles(directory=frontend_dir, html=True),
        name="frontend",
    )


    
    return app

    



app = create_app() if FastAPI is not None else None

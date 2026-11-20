"""Live detection: poll this host's Event Viewer every 30 seconds and ingest new events.

A background thread asks each log for events newer than its checkpoint and sends
them through WindowsIngestService.ingest_document, so live events get the same
Random Forest scoring, malware scanning, grouping, and resolve handling as a
manual "Collect and investigate". Detection starts from the moment it is turned
on; it does not re-read older history.
"""

from __future__ import annotations

import platform
import re
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional, Sequence

from windows_ingest import DEFAULT_THRESHOLD, IngestUnavailable, WindowsIngestService


POLL_INTERVAL_SECONDS = 30
MAX_EVENTS_PER_POLL = 2000
# Records seen at the checkpoint time are remembered so the next poll can query
# ">= checkpoint" without double-counting them.
_FRACTION = re.compile(r"(\.\d{6})\d+")

Collector = Callable[[str, datetime, int], list[dict[str, Any]]]


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        # Event Viewer emits 7 fractional digits; Python accepts at most 6.
        return datetime.fromisoformat(_FRACTION.sub(r"\1", value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _default_collector(log_name: str, cutoff: datetime, max_events: int) -> list[dict[str, Any]]:
    import gatherer

    return gatherer.collect_log(log_name, cutoff, max_events, include_raw_xml=False)


class LiveDetector:
    """Start/stop wrapper around a polling thread; one instance per API process."""

    def __init__(
        self,
        service: WindowsIngestService,
        *,
        logs: Optional[Sequence[str]] = None,
        interval: float = POLL_INTERVAL_SECONDS,
        collector: Collector = _default_collector,
        threshold: float = DEFAULT_THRESHOLD,
        require_windows: bool = True,
    ):
        self.service = service
        self.logs = list(logs or ("Security", "System", "Application"))
        self.interval = interval
        self.collector = collector
        self.threshold = threshold
        self.require_windows = require_windows
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._reset_state()

    def _reset_state(self) -> None:
        self.started_at: Optional[datetime] = None
        self.last_poll_at: Optional[datetime] = None
        self.next_poll_at: Optional[datetime] = None
        self.polls = 0
        self.totals = {"events": 0, "anomalies": 0, "malware": 0, "incidents_opened": 0, "incidents_updated": 0}
        self.last_summary: dict[str, Any] = {}
        self.log_errors: list[dict[str, str]] = []
        self.last_error: Optional[str] = None
        self._checkpoint: dict[str, datetime] = {}
        self._seen_at_checkpoint: dict[str, set[tuple[Any, Any]]] = {}

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> dict[str, Any]:
        with self._lock:
            if self.running:
                return self.status()
            if self.require_windows and platform.system() != "Windows":
                raise IngestUnavailable("Live detection needs Windows Event Viewer.")
            self._reset_state()
            self.started_at = datetime.now(timezone.utc)
            self._checkpoint = {log: self.started_at for log in self.logs}
            self._seen_at_checkpoint = {log: set() for log in self.logs}
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="live-detection", daemon=True)
            self._thread.start()
        return self.status()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            thread = self._thread
            self._stop.set()
        if thread is not None:
            # A poll in progress finishes its ingest before the thread exits.
            thread.join(timeout=120)
        with self._lock:
            self._thread = None
            self.next_poll_at = None
        return self.status()

    def status(self) -> dict[str, Any]:
        iso = lambda value: value.isoformat() if value else None
        return {
            "running": self.running,
            "interval_seconds": self.interval,
            "logs": self.logs,
            "started_at": iso(self.started_at),
            "last_poll_at": iso(self.last_poll_at),
            "next_poll_at": iso(self.next_poll_at) if self.running else None,
            "polls": self.polls,
            "totals": dict(self.totals),
            "last_summary": self.last_summary,
            "log_errors": self.log_errors,
            "last_error": self.last_error,
        }

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
                self.last_error = None
            except Exception as error:  # keep polling; surface the problem in status
                self.last_error = f"{type(error).__name__}: {error}"
            self.next_poll_at = datetime.now(timezone.utc) + timedelta(seconds=self.interval)
            self._stop.wait(self.interval)

    def _new_events(self, log: str) -> list[dict[str, Any]]:
        cutoff = self._checkpoint[log]
        events = self.collector(log, cutoff, MAX_EVENTS_PER_POLL)
        seen = self._seen_at_checkpoint[log]
        fresh = []
        for event in events:
            created = _parse_time(event.get("timeCreatedUtc"))
            if created is None or created < cutoff:
                continue
            key = (event.get("recordId"), event.get("timeCreatedUtc"))
            if key in seen:
                continue
            fresh.append((created, key, event))
        if fresh:
            newest = max(created for created, _, _ in fresh)
            self._checkpoint[log] = newest
            self._seen_at_checkpoint[log] = {key for created, key, _ in fresh if created == newest} | (
                seen if newest == cutoff else set()
            )
        return [event for _, _, event in fresh]

    def poll_once(self) -> dict[str, Any]:
        events: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        for log in self.logs:
            try:
                events.extend(self._new_events(log))
            except (OSError, RuntimeError) as error:
                errors.append({"logName": log, "message": str(error)})
        events.sort(key=lambda event: event.get("timeCreatedUtc") or "")
        self.log_errors = errors
        self.last_poll_at = datetime.now(timezone.utc)
        self.polls += 1
        summary: dict[str, Any] = {"events_scanned": len(events), "incidents": []}
        if events:
            document = {
                "schemaVersion": 1,
                "collectedAtUtc": self.last_poll_at.isoformat(),
                "computerName": platform.node(),
                "logs": self.logs,
                "eventCount": len(events),
                "events": events,
                "errors": errors,
            }
            summary = self.service.ingest_document(document, threshold=self.threshold, source="live-detection")
            self.totals["events"] += summary["events_scanned"]
            self.totals["anomalies"] += summary["anomalies_detected"]
            self.totals["malware"] += summary.get("malware_detected", 0)
            self.totals["incidents_opened"] += sum(1 for item in summary["incidents"] if not item["merged"])
            self.totals["incidents_updated"] += sum(1 for item in summary["incidents"] if item["merged"])
        self.last_summary = {
            "events": summary["events_scanned"],
            "anomalies": summary.get("anomalies_detected", 0),
            "malware": summary.get("malware_detected", 0),
            "incidents": len(summary["incidents"]),
        }
        return summary

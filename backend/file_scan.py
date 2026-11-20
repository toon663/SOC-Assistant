"""Static malware scanning of executables for the Sentinel agent.

Flow: process-creation event (Security 4688 / Sysmon 1) or an API request
-> Sentinel_Agent/malware_classifier (LightGBM on EMBER2024 features)
-> malware_detected SecurityEvent -> the usual agent pipeline.

The scanner and its ML packages load lazily, so the rest of the backend still
runs on the standard library alone. Files are read, never executed.
"""

from __future__ import annotations

import re
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from agents import SecurityEvent, Severity, utc_now


REPO_ROOT = Path(__file__).resolve().parent.parent
_SENTINEL_DIR = str(REPO_ROOT / "Sentinel_Agent")
if _SENTINEL_DIR not in sys.path:
    sys.path.append(_SENTINEL_DIR)

# Upper bound per ingest so a noisy log cannot stall a request on file reads.
MAX_FILES_PER_INGEST = 200
MALWARE_EVENT_TYPE = "malware_detected"
MALWARE_LOG_NAME = "malware-scan"
SEVERITY_BY_VERDICT = {"malicious": Severity.CRITICAL, "suspicious": Severity.HIGH}

PROCESS_PATH_PATTERNS = {
    # Security 4688 "A new process has been created."
    4688: re.compile(r"New Process Name:\s*([^\r\n]+)"),
    # Sysmon 1 "Process Create" (only from the Sysmon provider; ID 1 collides elsewhere)
    1: re.compile(r"^\s*Image:\s*([^\r\n]+)", re.M),
}


class ScanUnavailable(RuntimeError):
    """The malware scanner models or packages are not installed."""


def extract_executable_paths(raw_events: Iterable[dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    """Return unique (path, first source event) pairs from process-creation events."""
    found: dict[str, dict[str, Any]] = {}
    for event in raw_events:
        event_id = event.get("eventId")
        pattern = PROCESS_PATH_PATTERNS.get(event_id)
        if pattern is None:
            continue
        if event_id == 1 and "sysmon" not in str(event.get("provider") or "").lower():
            continue
        match = pattern.search(str(event.get("message") or ""))
        if not match:
            continue
        path = match.group(1).strip().strip('"')
        if path and path != "-":
            found.setdefault(path.lower(), {"path": path, "event": event})
    return [(item["path"], item["event"]) for item in found.values()]


def _load_default_scanner() -> Any:
    try:
        from malware_classifier.malware_scanner import ScannerUnavailable, get_scanner
    except ImportError as error:
        raise ScanUnavailable(f"Malware scanner not importable ({error})") from error
    try:
        return get_scanner()
    except ScannerUnavailable as error:
        raise ScanUnavailable(str(error)) from error


def scan_reasons(result: dict[str, Any]) -> list[str]:
    reasons = [
        f"Static ML score {result['score']:.3f} ({result['verdict']}; "
        f"suspicious >= {result['suspicious_threshold']}, malicious >= {result['malicious_threshold']})"
    ]
    if result.get("family"):
        reasons.append(f"Family: {result['family']} (p={result['family_probability']:.2f})")
    elif result.get("family_candidates"):
        best = result["family_candidates"][0]
        reasons.append(f"Family uncertain; closest: {best['family']} (p={best['probability']:.2f})")
    for item in (result.get("explanation") or {}).get("toward_malicious", []):
        reasons.append(f"Indicator: {item['feature_group']}")
    return reasons


def result_to_event(
    result: dict[str, Any],
    *,
    host: Optional[str],
    timestamp: Optional[str] = None,
    user: Optional[str] = None,
    origin: str = "on-demand",
) -> Optional[SecurityEvent]:
    """Convert a flagged scan result into a SecurityEvent; clean files return None."""
    severity = SEVERITY_BY_VERDICT.get(result.get("verdict"))
    if severity is None or not result.get("sha256"):
        return None
    profile = result.get("family_profile") or {}
    file_label = result.get("file_path") or result.get("file_name") or result["sha256"][:12]
    family = result.get("family")
    return SecurityEvent(
        # One event per file and host: rescans of the same file are recognized as already seen.
        event_id=f"{host}:{MALWARE_LOG_NAME}:{result['sha256']}",
        timestamp=timestamp or utc_now(),
        source=f"sentinel-malware-scanner:{origin}",
        event_type=MALWARE_EVENT_TYPE,
        user=user,
        host=host,
        destination=result.get("file_name") or None,
        message=(
            f"{result['verdict'].capitalize()} executable {file_label}"
            f"{f' classified as {family}' if family else ''} (score {result['score']:.3f})."
        ),
        severity=severity,
        detector_score=result.get("score"),
        metadata={
            "log_name": MALWARE_LOG_NAME,
            "windows_event_id": None,
            "sha256": result["sha256"],
            "file_path": result.get("file_path"),
            "file_name": result.get("file_name"),
            "verdict": result["verdict"],
            "malware_family": family,
            "family_probability": result.get("family_probability"),
            "family_candidates": result.get("family_candidates") or [],
            "mitre_techniques": [t["id"] for t in profile.get("techniques", [])],
            "attack_tactics": profile.get("tactics", []),
            "explanation": result.get("explanation") or {},
            "reasons": scan_reasons(result),
            "detector": "lightgbm-ember2024",
        },
    )


class FileScanService:
    """Scan executables and turn flagged ones into Sentinel events."""

    def __init__(self, scanner_factory: Callable[[], Any] = _load_default_scanner):
        self._factory = scanner_factory
        self._scanner: Any = None
        self._error: Optional[str] = None
        self._lock = threading.Lock()
        # (path, mtime, size) -> result, so repeated process launches are not re-read.
        self._path_cache: dict[tuple[str, float, int], dict[str, Any]] = {}

    @property
    def scanner(self) -> Any:
        with self._lock:
            if self._scanner is None:
                try:
                    self._scanner = self._factory()
                except ScanUnavailable as error:
                    self._error = str(error)
                    raise
            return self._scanner

    def status(self) -> dict[str, Any]:
        try:
            return {"available": True, **self.scanner.info()}
        except ScanUnavailable as error:
            return {"available": False, "detail": str(error)}

    def scan_path(self, path: str) -> dict[str, Any]:
        file = Path(path)
        if not file.is_file():
            raise FileNotFoundError(f"not a file: {path}")
        stat = file.stat()
        key = (str(file.resolve()).lower(), stat.st_mtime, stat.st_size)
        cached = self._path_cache.get(key)
        if cached is not None:
            return cached
        result = self.scanner.scan_file(file)
        self._path_cache[key] = result
        return result

    def scan_bytes(self, data: bytes, name: str = "") -> dict[str, Any]:
        return self.scanner.scan_bytes(data, name)

    def scan_process_events(
        self,
        raw_events: Iterable[dict[str, Any]],
        *,
        host: Optional[str],
        user_for: Callable[[dict[str, Any]], Optional[str]] = lambda event: None,
    ) -> tuple[list[SecurityEvent], dict[str, Any]]:
        """Scan executables named in process-creation events."""
        paths = extract_executable_paths(raw_events)
        stats: dict[str, Any] = {"executables_found": len(paths), "files_scanned": 0, "flagged": 0, "errors": []}
        events: list[SecurityEvent] = []
        if not paths:
            return events, stats
        try:
            self.scanner
        except ScanUnavailable as error:
            stats["errors"].append(str(error))
            return events, stats
        for path, source in paths[:MAX_FILES_PER_INGEST]:
            try:
                result = self.scan_path(path)
            except (OSError, ValueError) as error:
                # Short-lived or protected binaries are expected; report and continue.
                stats["errors"].append(f"{path}: {error}")
                continue
            stats["files_scanned"] += 1
            event = result_to_event(
                result,
                host=host,
                timestamp=source.get("timeCreatedUtc"),
                user=user_for(source),
                origin=f"process-creation:{source.get('eventId')}",
            )
            if event is not None:
                stats["flagged"] += 1
                events.append(event)
        if len(paths) > MAX_FILES_PER_INGEST:
            stats["errors"].append(f"only the first {MAX_FILES_PER_INGEST} of {len(paths)} executables were scanned")
        return events, stats

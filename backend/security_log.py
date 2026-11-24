"""Read Event Viewer > Windows Logs > Security on the backend's Windows host."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
import socket
import subprocess
import xml.etree.ElementTree as ET


@dataclass(frozen=True)
class WindowsSecurityRecord:
    record_id: int
    event_id: int
    timestamp: str
    host: str
    provider: str
    data: dict[str, str]

    @property
    def identity(self) -> str:
        # Record IDs can be reused after clearing the log; include the timestamp.
        return f"{self.host}:Security:{self.record_id}:{self.timestamp}"


@dataclass(frozen=True)
class SecurityLogBatch:
    host: str
    queried_at: str
    log_name: str
    limit: int
    truncated: bool
    events: list[WindowsSecurityRecord]


def parse_security_record(xml: str) -> WindowsSecurityRecord:
    """Use XML field names rather than localized Event Viewer message text."""
    root = ET.fromstring(xml)
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    system = root.find("e:System", ns)
    if system is None or system.findtext("e:Channel", namespaces=ns) != "Security":
        raise ValueError("Expected a Windows Security log record")
    data = {node.attrib["Name"]: node.text or ""
            for node in root.findall("e:EventData/e:Data", ns) if "Name" in node.attrib}
    # Event 1102 uses UserData with a separate namespace instead of EventData.
    user_data = root.find("e:UserData", ns)
    if user_data is not None:
        for node in user_data.iter():
            if len(node) == 0:
                data[node.tag.rsplit("}", 1)[-1]] = node.text or ""
    return WindowsSecurityRecord(
        record_id=int(system.findtext("e:EventRecordID", namespaces=ns)),
        event_id=int(system.findtext("e:EventID", namespaces=ns)),
        timestamp=system.find("e:TimeCreated", ns).attrib["SystemTime"],
        host=system.findtext("e:Computer", namespaces=ns) or socket.gethostname(),
        provider=system.find("e:Provider", ns).attrib.get("Name", ""),
        data=data,
    )


def gather_security_events(limit: int = 200) -> SecurityLogBatch:
    """Read the newest records; never modify logs or audit settings."""
    if os.name != "nt":
        raise RuntimeError("Windows Security log collection requires a Windows backend")
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("limit must be between 1 and 1000")
    queried_at = datetime.now(timezone.utc).isoformat()
    # Only bounded integers enter the script. No shell, profiles, or policy bypass.
    script = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
try {
    $records = @(Get-WinEvent -LogName Security -MaxEvents MAX_RECORDS -ErrorAction Stop)
    $xmlRecords = @($records | ForEach-Object { $_.ToXml() })
    ConvertTo-Json -InputObject $xmlRecords -Compress
} catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
        Write-Output '[]'
        exit 0
    }
    if ($_.Exception -is [System.UnauthorizedAccessException] -or $_.FullyQualifiedErrorId -like '*UnauthorizedAccess*') {
        exit 5
    }
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
""".replace("MAX_RECORDS", str(limit + 1))
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True, encoding="utf-8", timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Reading the Windows Security log timed out; retry the scan") from exc
    if result.returncode == 5:
        raise PermissionError("Access to Windows Logs > Security was denied. Run the backend from an Administrator PowerShell, or use an account authorized to read the Security log.")
    if result.returncode:
        raise RuntimeError("Unable to read Windows Logs > Security; check Windows Event Log service and Security log access")
    try:
        xml_records = json.loads(result.stdout.lstrip("\ufeff"))
        if not isinstance(xml_records, list) or not all(isinstance(xml, str) for xml in xml_records):
            raise ValueError("Expected an array of XML records")
        events = [parse_security_record(xml) for xml in xml_records[:limit]]
    except (ValueError, TypeError, AttributeError, KeyError, ET.ParseError) as exc:
        raise RuntimeError("Windows Security log returned an invalid record") from exc
    return SecurityLogBatch(socket.gethostname(), queried_at, "Security", limit, len(xml_records) > limit, events)

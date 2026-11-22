"""Read Windows Event Logs. Requires Windows; run VS Code as Administrator for best coverage."""
import json, subprocess, platform
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd

SECURITY_IDS = [4624, 4625, 4672, 4688, 4720, 4732, 4740, 1102, 4697, 7045]

def _parse_event_xml(xml_text):
    """Extracts standard EventData fields from an event XML document."""
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_text)
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    sysnode = root.find("e:System", ns)
    provider = sysnode.find("e:Provider", ns).attrib.get("Name", "") if sysnode is not None and sysnode.find("e:Provider", ns) is not None else ""
    eid = int(sysnode.find("e:EventID", ns).text) if sysnode is not None and sysnode.find("e:EventID", ns) is not None else 0
    time_node = sysnode.find("e:TimeCreated", ns) if sysnode is not None else None
    timestamp = time_node.attrib.get("SystemTime") if time_node is not None else None
    computer_node = sysnode.find("e:Computer", ns) if sysnode is not None else None
    computer = computer_node.text if computer_node is not None else ""
    data = {}
    for item in root.findall(".//e:EventData/e:Data", ns):
        key = item.attrib.get("Name", f"Data{len(data)}")
        data[key] = item.text or ""
    return {
        "timestamp": timestamp, "event_id": eid, "provider": provider,
        "computer": computer, "channel": "Security", "event_data": data,
        "message": " | ".join(f"{k}={v}" for k, v in data.items())
    }

def collect_with_pywin32(max_events=1000, event_ids=None):
    if platform.system() != "Windows":
        raise RuntimeError("Windows Event Log collection must be run on Windows.")
    try:
        import win32evtlog
    except ImportError as exc:
        raise RuntimeError("pywin32 is missing. Run: pip install pywin32") from exc
    event_ids = set(event_ids or SECURITY_IDS)
    handle = win32evtlog.OpenEventLog(None, "Security")
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    rows = []
    try:
        while len(rows) < max_events:
            batch = win32evtlog.ReadEventLog(handle, flags, 0)
            if not batch:
                break
            for ev in batch:
                if ev.EventID & 0xFFFF not in event_ids:
                    continue
                inserts = list(ev.StringInserts or [])
                rows.append({
                    "timestamp": ev.TimeGenerated.Format(),
                    "event_id": ev.EventID & 0xFFFF,
                    "provider": getattr(ev, "SourceName", "Microsoft-Windows-Security-Auditing"),
                    "computer": getattr(ev, "ComputerName", ""),
                    "channel": "Security",
                    "event_data": json.dumps({f"Data{i}": v for i, v in enumerate(inserts)}),
                    "message": " | ".join(str(v) for v in inserts)
                })
                if len(rows) >= max_events:
                    break
    finally:
        win32evtlog.CloseEventLog(handle)
    return pd.DataFrame(rows)

def collect_with_powershell(max_events=1000, event_ids=None):
    """Alternative collector using Get-WinEvent; suitable for a Windows PowerShell host."""
    if platform.system() != "Windows":
        raise RuntimeError("PowerShell Event Log collection must be run on Windows.")
    ids = event_ids or SECURITY_IDS
    id_filter = ",".join(str(int(x)) for x in ids)
    ps = (
        f"$events = Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=@({id_filter})}} "
        f"-MaxEvents {int(max_events)} -ErrorAction Stop; "
        "$events | ForEach-Object { $_.ToXml() }"
    )
    result = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                            capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Get-WinEvent failed.")
    # PowerShell emits concatenated XML; split at event boundaries.
    import re
    chunks = re.findall(r"<Event[\s\S]*?</Event>", result.stdout)
    rows = [_parse_event_xml(x) for x in chunks]
    for row in rows:
        row["event_data"] = json.dumps(row["event_data"])
    return pd.DataFrame(rows)

def collect_security_events(max_events=1000, method="pywin32"):
    if method == "powershell":
        return collect_with_powershell(max_events=max_events)
    return collect_with_pywin32(max_events=max_events)

def save_events(df, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        old = pd.read_csv(path)
        df = pd.concat([old, df], ignore_index=True).drop_duplicates(
            subset=["timestamp", "event_id", "computer", "message"], keep="last")
    df.to_csv(path, index=False)
    return path

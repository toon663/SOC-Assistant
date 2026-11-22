"""Dev-mode test data: synthetic Windows attack scenarios and a malware demo.

Only used when SOC_DEV_MODE=1. Scenarios produce gatherer-format documents with
fresh record IDs and timestamps, so each run opens new incidents through the real
pipeline (Random Forest, grouping, all agents) without touching this machine.
The malware demo scores real EMBER2024 test-set feature vectors with the real
models, so no malware file is ever needed.
"""

from __future__ import annotations

import hashlib
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from file_scan import REPO_ROOT


DEFAULT_HOST = "LAB-WS-01"
DEMO_VECTORS = REPO_ROOT / "Sentinel_Agent" / "malware_classifier" / "models" / "demo_vectors.npz"
SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


class _EventFactory:
    def __init__(self, host: str):
        self.host = host
        # Random high record IDs so synthetic records never collide with real ones or earlier runs.
        self.next_record = random.randint(10**9, 2 * 10**9)
        self.now = datetime.now(timezone.utc)

    def event(
        self,
        event_id: int,
        message: str,
        *,
        seconds_ago: float = 0,
        log: str = "Security",
        provider: str = SECURITY_PROVIDER,
        keywords: Optional[list[str]] = None,
        level: int = 0,
        level_name: str = "Information",
        task: str = "",
    ) -> dict[str, Any]:
        self.next_record += 1
        return {
            "recordId": self.next_record,
            "timeCreatedUtc": _iso(self.now - timedelta(seconds=seconds_ago)),
            "eventId": event_id,
            "provider": provider,
            "level": level,
            "levelName": level_name,
            "keywords": keywords or ["Audit Success"],
            "logName": log,
            "machineName": self.host,
            "userId": None,
            "processId": 724,
            "threadId": random.randint(1000, 9000),
            "task": task,
            "opcode": "Info",
            "activityId": None,
            "message": message,
            "eventData": [],
        }


def _failed_logon(user: str, host: str, ip: str) -> str:
    return (
        "An account failed to log on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-0-0\r\n\tAccount Name:\t\t-\r\n\r\n"
        "Logon Type:\t\t\t3\r\n\r\nAccount For Which Logon Failed:\r\n\tSecurity ID:\t\tS-1-0-0\r\n"
        f"\tAccount Name:\t\t{user}\r\n\tAccount Domain:\t\t{host}\r\n\r\nFailure Information:\r\n"
        "\tFailure Reason:\t\tUnknown user name or bad password.\r\n\tStatus:\t\t\t0xC000006D\r\n\r\n"
        f"Network Information:\r\n\tWorkstation Name:\t-\r\n\tSource Network Address:\t{ip}\r\n\tSource Port:\t\t0\r\n"
    )


def brute_force(f: _EventFactory) -> list[dict[str, Any]]:
    user, ip = "jsmith", "203.0.113.77"
    events = [
        f.event(4625, _failed_logon(user, f.host, ip), seconds_ago=120 - i * 5, keywords=["Audit Failure"], task="Logon")
        for i in range(20)
    ]
    events.append(f.event(4624, (
        "An account was successfully logged on.\r\n\r\nLogon Type:\t\t\t3\r\n\r\nNew Logon:\r\n"
        f"\tSecurity ID:\t\tS-1-5-21-1004\r\n\tAccount Name:\t\t{user}\r\n\tAccount Domain:\t\t{f.host}\r\n\r\n"
        f"Network Information:\r\n\tSource Network Address:\t{ip}\r\n"
    ), seconds_ago=10, task="Logon"))
    return events


def log_cleared(f: _EventFactory) -> list[dict[str, Any]]:
    return [f.event(1102, (
        "The audit log was cleared.\r\nSubject:\r\n\tSecurity ID:\tS-1-5-21-1004\r\n"
        f"\tAccount Name:\tjsmith\r\n\tDomain Name:\t{f.host}\r\n\tLogon ID:\t0x3E7\r\n"
    ), provider="Microsoft-Windows-Eventlog", task="Log clear")]


def new_admin(f: _EventFactory) -> list[dict[str, Any]]:
    subject = f"Subject:\r\n\tSecurity ID:\t\tS-1-5-21-1004\r\n\tAccount Name:\t\tjsmith\r\n\tAccount Domain:\t\t{f.host}\r\n\r\n"
    return [
        f.event(4720, (
            f"A user account was created.\r\n\r\n{subject}New Account:\r\n\tSecurity ID:\t\tS-1-5-21-1337\r\n"
            f"\tAccount Name:\t\tsupport_svc\r\n\tAccount Domain:\t\t{f.host}\r\n"
        ), seconds_ago=30, task="User Account Management"),
        f.event(4732, (
            f"A member was added to a security-enabled local group.\r\n\r\n{subject}Member:\r\n"
            "\tSecurity ID:\t\tS-1-5-21-1337\r\n\tAccount Name:\t\t-\r\n\r\nGroup:\r\n"
            f"\tSecurity ID:\t\tS-1-5-32-544\r\n\tGroup Name:\t\tAdministrators\r\n\tGroup Domain:\t\tBuiltin\r\n"
        ), seconds_ago=25, task="Security Group Management"),
    ]


def service_install(f: _EventFactory) -> list[dict[str, Any]]:
    return [f.event(7045, (
        "A service was installed in the system.\r\n\r\nService Name:  WinUpdateHelper\r\n"
        "Service File Name:  C:\\Users\\Public\\Libraries\\updhelper.exe\r\nService Type:  user mode service\r\n"
        "Service Start Type:  auto start\r\nService Account:  LocalSystem"
    ), log="System", provider="Service Control Manager", keywords=["Classic"], task="None")]


def encoded_powershell(f: _EventFactory) -> list[dict[str, Any]]:
    return [f.event(4688, (
        "A new process has been created.\r\n\r\nCreator Subject:\r\n\tSecurity ID:\t\tS-1-5-21-1004\r\n"
        f"\tAccount Name:\t\tjsmith\r\n\tAccount Domain:\t\t{f.host}\r\n\r\nProcess Information:\r\n"
        "\tNew Process ID:\t\t0x1a2c\r\n\tNew Process Name:\tC:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\n"
        "\tCreator Process Name:\tC:\\Windows\\System32\\cmd.exe\r\n"
        "\tProcess Command Line:\tpowershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA\r\n"
    ), task="Process Creation")]


SCENARIOS: dict[str, tuple[str, str, Callable[[_EventFactory], list[dict[str, Any]]]]] = {
    "brute_force": ("Brute force", "20 failed logons from one IP, then a successful logon (4625 x20, 4624)", brute_force),
    "log_cleared": ("Log cleared", "Security audit log cleared (1102)", log_cleared),
    "new_admin": ("New admin account", "Account created and added to Administrators (4720, 4732)", new_admin),
    "service_install": ("Service install", "Unknown auto-start service from a public folder (7045)", service_install),
    "encoded_powershell": ("Encoded PowerShell", "powershell -enc launched from cmd.exe (4688)", encoded_powershell),
}


def list_scenarios() -> list[dict[str, str]]:
    return [{"name": name, "title": title, "description": text} for name, (title, text, _) in SCENARIOS.items()]


def build_scenario(name: str, host: str = DEFAULT_HOST) -> dict[str, Any]:
    if name not in SCENARIOS:
        raise KeyError(f"unknown scenario: {name}")
    factory = _EventFactory(host)
    events = SCENARIOS[name][2](factory)
    return {
        "schemaVersion": 1,
        "collectedAtUtc": datetime.now(timezone.utc).isoformat(),
        "computerName": host,
        "logs": sorted({event["logName"] for event in events}),
        "eventCount": len(events),
        "errors": [],
        "synthetic": True,
        "events": events,
    }


def malware_samples() -> list[str]:
    if not DEMO_VECTORS.exists():
        return []
    import numpy as np

    return [str(label) for label in np.load(DEMO_VECTORS)["label"]]


def malware_demo_result(scanner: Any, sample: Optional[str] = None) -> dict[str, Any]:
    """Score one stored test-set malware vector with the real detector and family models."""
    import numpy as np

    if not DEMO_VECTORS.exists():
        raise FileNotFoundError(f"{DEMO_VECTORS} not found; run build_demo_vectors.py")
    data = np.load(DEMO_VECTORS)
    labels = [str(label) for label in data["label"]]
    index = labels.index(sample) if sample in labels else random.randrange(len(labels))
    vector = data["X"][index]
    # A fresh pseudo-hash per run, so every demo opens a new incident. It is not a real file hash.
    sha256 = hashlib.sha256(vector.tobytes() + uuid.uuid4().bytes).hexdigest()
    name = f"demo_{labels[index].replace(' ', '_')}.exe"
    result = scanner.scan_features(vector, sha256, name, 0)
    result.update(
        file_path=f"C:\\Users\\jsmith\\Downloads\\{name}",
        demo=True,
        true_family=str(data["true_family"][index]),
        note="Dev-mode demo: EMBER2024 test-set feature vector, no file on disk",
    )
    return result

"""Analyst agent triage: decide what a Sentinel incident actually is.

The Sentinel says that something is unusual. The Analyst reads the evidence and
decides what it is:

1. parse the Windows message fields (accounts, logon type, command line,
   service path, group name, ...),
2. apply the triage rule for that kind of event,
3. correlate with related activity on the same host, such as other incidents and
   other events from the same collection (failed logons followed by a success,
   an account created and then added to Administrators),
4. return a verdict, a priority, the ATT&CK techniques the evidence supports,
   the reasoning, links to related incidents, and next steps.

Every score contribution is listed in ``findings``, so the risk score is the sum
of the findings and a verdict can always be traced back to evidence.

Rules are keyed by log name and event ID, not event ID alone: other channels
reuse Security event IDs (Application event 4625 from EventSystem is not a
failed logon). Standard library only. Events are duck-typed
``agents.SecurityEvent`` objects, so this module does not import agents.py.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Optional, Sequence


MALICIOUS = "malicious"
SUSPICIOUS = "suspicious"
BENIGN = "benign"

# Benign incidents never rank above low priority, whatever their findings add up to.
BENIGN_RISK_CAP = 30.0
LOGON_WINDOW = timedelta(hours=1)
ACCOUNT_WINDOW = timedelta(hours=24)
BRUTE_FORCE_COUNT = 10
REPEATED_FAILURE_COUNT = 5

SECURITY = "security"
SYSMON = "microsoft-windows-sysmon/operational"
DEFENDER = "microsoft-windows-windows defender/operational"
FAILED_LOGON_IDS = {4625, 4771}
SUCCESSFUL_LOGON_IDS = {4624}
GROUP_ADD_IDS = {4728, 4732, 4756}
ACCOUNT_CREATED_IDS = {4720}

DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network(net) for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
]
LOGON_TYPES = {
    "2": "interactive", "3": "network", "4": "batch", "5": "service", "7": "unlock",
    "8": "network cleartext", "9": "new credentials", "10": "remote interactive (RDP)",
    "11": "cached interactive",
}
PRIVILEGED_GROUPS = {
    "administrators", "domain admins", "enterprise admins", "schema admins",
    "backup operators", "account operators", "server operators", "print operators",
    "remote desktop users", "dnsadmins", "group policy creator owners", "hyper-v administrators",
}
TRUSTED_PATH = re.compile(
    r'^"?(?:[a-z]:\\(?:windows\\(?:system32|syswow64|winsxs|microsoft\.net)|program files(?: \(x86\))?'
    r'|programdata\\microsoft\\windows defender)\\|\\systemroot\\|system32\\|\\\?\?\\c:\\windows\\)',
    re.I,
)
USER_WRITABLE_PATH = re.compile(
    r"\\(?:users\\public|users\\[^\\]+\\(?:appdata|downloads|desktop|documents)|windows\\temp|temp|tmp"
    r"|perflogs|programdata|\$recycle\.bin)\\",
    re.I,
)
# Processes that enumerate group membership as part of normal Windows operation.
ROUTINE_ENUMERATORS = {
    "explorer.exe", "svchost.exe", "mmc.exe", "systemsettings.exe", "lsass.exe", "consent.exe",
    "services.exe", "wininit.exe", "winlogon.exe", "lsm.exe", "taskhostw.exe", "searchindexer.exe",
}
TIME_SERVICES = {"svchost.exe", "w32tm.exe", "vmtoolsd.exe", "vboxservice.exe"}


@dataclass(frozen=True)
class Indicator:
    pattern: re.Pattern[str]
    points: float
    text: str
    techniques: tuple[str, ...]


def _indicator(pattern: str, points: float, text: str, *techniques: str) -> Indicator:
    return Indicator(re.compile(pattern, re.I), points, text, techniques)


# Command-line indicators for process creation and scheduled task actions.
COMMAND_INDICATORS = [
    _indicator(r"\s-(?:e|en|enc|enco|encodedcommand)\s+[a-z0-9+/=]{16,}", 45, "Encoded PowerShell command", "T1059.001", "T1027"),
    _indicator(r"\b(?:iex|invoke-expression)\b", 25, "Executes a string as code (Invoke-Expression)", "T1059.001"),
    _indicator(r"downloadstring|downloadfile|net\.webclient|invoke-webrequest|\biwr\b|start-bitstransfer", 30, "Downloads content from the network", "T1105"),
    _indicator(r"-(?:w|windowstyle)\s+h(?:idden)?\b", 15, "Hidden PowerShell window", "T1564.003"),
    _indicator(r"-(?:ep|exec|executionpolicy)\s+bypass", 15, "Bypasses the PowerShell execution policy", "T1059.001"),
    _indicator(r"certutil(?:\.exe)?\s+.*-(?:urlcache|decode|decodehex)", 40, "certutil used to download or decode a file", "T1105", "T1140"),
    _indicator(r"mshta(?:\.exe)?\s+(?:https?:|javascript:|vbscript:)", 40, "mshta runs remote or inline script", "T1218.005"),
    _indicator(r"regsvr32(?:\.exe)?\s+.*/i:\s*https?:", 40, "regsvr32 loads a remote scriptlet", "T1218.010"),
    _indicator(r"rundll32(?:\.exe)?\s+.*(?:javascript:|https?:)", 40, "rundll32 runs script or remote content", "T1218.011"),
    _indicator(r"vssadmin(?:\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|wbadmin\s+delete|bcdedit.*recoveryenabled\s+no", 60, "Deletes backups or shadow copies (ransomware precursor)", "T1490"),
    _indicator(r"(?:procdump|comsvcs\.dll.*minidump|sekurlsa|mimikatz)", 60, "Credential dumping tool or technique", "T1003.001"),
    _indicator(r"\bnet1?\s+(?:user|localgroup)\b.*\s/add\b", 35, "Creates an account or adds it to a group from the command line", "T1136.001", "T1098"),
    _indicator(r"\bschtasks(?:\.exe)?\s+/create\b", 20, "Creates a scheduled task from the command line", "T1053.005"),
    _indicator(r"\breg(?:\.exe)?\s+add\s+.*\\currentversion\\run", 30, "Adds a Run-key autostart entry", "T1547.001"),
    _indicator(r"\b(?:whoami|nltest|net1?\s+(?:user|group|localgroup)|quser|systeminfo)\b", 10, "Account or system discovery command", "T1087", "T1082"),
]
ENCODED_PAYLOAD = re.compile(r"\s-(?:e|en|enc|enco|encodedcommand)\s+([a-z0-9+/=]{16,})", re.I)
SERVICE_INTERPRETER = re.compile(r"(?:cmd(?:\.exe)?\s*/c|%comspec%|powershell|pwsh|mshta|rundll32|wscript|cscript)", re.I)
OFFICE_PARENT = re.compile(r"\\(?:winword|excel|powerpnt|outlook|msaccess|onenote)\.exe$", re.I)
SHELL_CHILD = re.compile(r"\\(?:cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)\.exe$", re.I)


@dataclass
class RelatedEvent:
    """An event outside the incident being triaged, with the incident that holds it.

    ``group_key`` names an incident from the same collection that is not saved
    yet; the ingest service fills in its ID once it is.
    """

    event: Any
    incident_id: Optional[str] = None
    title: Optional[str] = None
    group_key: Optional[str] = None


@dataclass
class Outcome:
    verdict: str
    category: str
    summary: str
    confidence: float
    # For benign outcomes: why the activity is harmless or safe to ignore.
    explanation: str = ""


def message_field(message: Optional[str], label: str, section: Optional[str] = None) -> Optional[str]:
    """Read ``Label: value`` from a Windows event message, optionally inside a section."""
    text = message or ""
    if section:
        start = re.search(rf"^[ \t]*{re.escape(section)}:[ \t]*\r?$", text, re.M)
        if not start:
            return None
        text = text[start.end():]
    match = re.search(rf"^[ \t]*{re.escape(label)}:[ \t]*(.*)$", text, re.M)
    value = match.group(1).strip() if match else ""
    return value if value and value != "-" else None


def parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    # Windows writes 7 fractional digits; older Pythons accept at most 6.
    text = re.sub(r"(\.\d{6})\d+", r"\1", value.strip()).replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def is_external(ip: Optional[str]) -> bool:
    try:
        address = ipaddress.ip_address(ip or "")
    except ValueError:
        return False
    # Python calls the documentation ranges private, but no network uses them
    # internally; test data (dev scenarios) uses them for internet addresses.
    return address.is_global or any(address in network for network in DOCUMENTATION_NETWORKS)


def _basename(path: Optional[str]) -> str:
    return re.split(r"[\\/]", (path or "").strip().strip('"'))[-1].lower()


def _log(event: Any) -> str:
    return str(event.metadata.get("log_name") or "").lower()


def _event_id(event: Any) -> Optional[int]:
    value = event.metadata.get("windows_event_id")
    return value if isinstance(value, int) else None


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def _duration(start: Optional[datetime], end: Optional[datetime]) -> str:
    if not start or not end:
        return ""
    seconds = int((end - start).total_seconds())
    if seconds < 1:
        return ""
    if seconds < 120:
        return f" within {seconds} seconds"
    if seconds < 7200:
        return f" within {seconds // 60} minutes"
    return f" within {seconds // 3600} hours"


class TriageContext:
    """Evidence, related activity, and the findings a rule accumulates."""

    def __init__(self, incident: Any, related: Iterable[RelatedEvent]):
        self.incident = incident
        self.events = list(incident.events)
        self.primary = self.events[0]
        own = {event.event_id for event in self.events}
        self.related = [
            item for item in related
            if item.event.event_id not in own and item.event.host == self.primary.host
        ]
        self.occurrences = int(incident.alert.get("occurrence_count") or len(self.events))
        times = [t for t in (parse_time(event.timestamp) for event in self.events) if t]
        self.first = min(times) if times else None
        self.last = max(times) if times else None
        self.findings: list[dict[str, Any]] = []
        self.techniques: list[str] = []
        self.actions: list[str] = []
        self._links: dict[str, dict[str, Any]] = {}

    @property
    def message(self) -> str:
        return self.primary.message or ""

    def add(self, points: float, text: str) -> None:
        self.findings.append({"points": round(points, 2), "text": text})

    def technique(self, *ids: str) -> None:
        for technique_id in ids:
            if technique_id not in self.techniques:
                self.techniques.append(technique_id)

    def action(self, text: str) -> None:
        if text not in self.actions:
            self.actions.append(text)

    def span(self) -> str:
        return _duration(self.first, self.last)

    def find(
        self,
        event_ids: set[int],
        *,
        log: str = SECURITY,
        window: timedelta = LOGON_WINDOW,
        before: Optional[datetime] = None,
        after: Optional[datetime] = None,
        match: Callable[[Any], bool] = lambda event: True,
    ) -> list[RelatedEvent]:
        """Related events of these IDs within ``window`` of this incident's own events."""
        low = (self.first - window) if self.first else None
        high = (self.last + window) if self.last else None
        found = []
        for item in self.related:
            event = item.event
            if _event_id(event) not in event_ids or _log(event) != log:
                continue
            moment = parse_time(event.timestamp)
            if moment and ((low and moment < low) or (high and moment > high)):
                continue
            if moment and ((before and moment > before) or (after and moment < after)):
                continue
            if match(event):
                found.append(item)
        return found

    def link(self, items: Sequence[RelatedEvent], relation: str) -> None:
        """Record related incidents, one entry per incident and relation."""
        for item in items:
            key = f"{item.incident_id or item.group_key}|{relation}"
            entry = self._links.get(key)
            if entry is None:
                entry = self._links[key] = {
                    "incident_id": item.incident_id,
                    "title": item.title,
                    "relation": relation,
                    "event_type": item.event.event_type,
                    "event_count": 0,
                    "first_seen": item.event.timestamp,
                    "last_seen": item.event.timestamp,
                }
                if item.incident_id is None and item.group_key:
                    entry["group_key"] = item.group_key
            entry["event_count"] += 1
            entry["first_seen"] = min(entry["first_seen"], item.event.timestamp)
            entry["last_seen"] = max(entry["last_seen"], item.event.timestamp)

    @property
    def correlations(self) -> list[dict[str, Any]]:
        return list(self._links.values())


def _distinct(values: Iterable[Optional[str]]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


# Rules ----------------------------------------------------------------------


def triage_failed_logons(ctx: TriageContext) -> Outcome:
    user = ctx.primary.user
    who = user or "an unnamed account"
    ips = _distinct(event.source_ip for event in ctx.events)
    count = ctx.occurrences
    verdict = BENIGN

    if count >= BRUTE_FORCE_COUNT:
        ctx.add(55, f"{count} failed logons for {who}{ctx.span()}: brute-force volume")
        ctx.technique("T1110.001")
        verdict = SUSPICIOUS
    elif count >= REPEATED_FAILURE_COUNT:
        ctx.add(40, f"{count} failed logons for {who}{ctx.span()}: repeated guessing")
        ctx.technique("T1110.001")
        verdict = SUSPICIOUS
    else:
        ctx.add(15, f"{_plural(count, 'failed logon')} for {who}: consistent with a mistyped password")
    reason = message_field(ctx.message, "Failure Reason")
    if reason:
        ctx.add(0, f"Windows failure reason: {reason}")
    external = [ip for ip in ips if is_external(ip)]
    if external:
        ctx.add(10, f"Source address {', '.join(external)} is on the public internet")
        verdict = SUSPICIOUS if verdict == BENIGN and count >= 3 else verdict

    if ips:
        spray = ctx.find(FAILED_LOGON_IDS, match=lambda e: e.source_ip in ips and e.user != user)
        targets = _distinct(item.event.user for item in spray)
        if len(targets) >= 2:
            ctx.add(15, f"The same source also failed against {len(targets)} other accounts ({', '.join(targets[:5])}): password spraying")
            ctx.technique("T1110.003")
            ctx.link(spray, "same source failing against other accounts")
            verdict = SUSPICIOUS if verdict == BENIGN else verdict

    successes = ctx.find(
        SUCCESSFUL_LOGON_IDS,
        after=ctx.first,
        match=lambda e: bool((user and e.user == user) or (e.source_ip and e.source_ip in ips)),
    )
    if successes and count >= REPEATED_FAILURE_COUNT:
        hit = successes[0].event
        ctx.add(30, f"Followed by a successful logon for {hit.user or who} from {hit.source_ip or 'the same host'}: the guessing likely succeeded")
        ctx.technique("T1078")
        ctx.link(successes, "successful logon after these failures")
        ctx.action(f"Reset the password for {hit.user or who} and end its active sessions")
        ctx.action("Review what the account did after the successful logon")
        verdict = MALICIOUS

    if verdict != BENIGN:
        if external:
            ctx.action(f"Block {', '.join(external)} at the firewall or VPN edge")
        ctx.action(f"Check whether {who} logged on successfully from {', '.join(ips) or 'this source'}")
        ctx.action("Confirm an account lockout policy is enforced")
    summary = {
        MALICIOUS: f"Password guessing against {who} followed by a successful logon.",
        SUSPICIOUS: f"Repeated failed logons against {who}; no successful logon seen yet.",
        BENIGN: f"A few failed logons for {who}, typical of a mistyped password.",
    }[verdict]
    explanation = ""
    if verdict == BENIGN:
        source = f" The source {', '.join(external)} is on the public internet, but {_plural(count, 'attempt')} is too few to be guessing." if external else ""
        explanation = (
            f"Only {_plural(count, 'failed logon')} for {who}, below the {REPEATED_FAILURE_COUNT} attempts that would suggest password guessing. "
            f"No successful logon followed the failures and the source did not try other accounts.{source} "
            "This is what a mistyped, expired or cached old password produces."
        )
    return Outcome(verdict, "credential_access" if verdict != BENIGN else "routine_activity", summary, 0.9 if verdict == MALICIOUS else 0.75, explanation)


def triage_successful_logon(ctx: TriageContext) -> Outcome:
    user = ctx.primary.user
    logon_type = message_field(ctx.message, "Logon Type")
    kind = LOGON_TYPES.get(logon_type or "", f"type {logon_type}" if logon_type else "unknown type")
    if not user:
        ctx.add(5, f"{kind.capitalize()} logon by a service or machine account")
        return Outcome(
            BENIGN, "routine_activity", "Routine logon by a Windows service or machine account.", 0.85,
            "The logon names no user account. Windows services (SYSTEM, LOCAL SERVICE, NETWORK SERVICE) and the computer's own "
            "account log on like this constantly as part of normal operation.",
        )

    ips = _distinct(event.source_ip for event in ctx.events)
    external = [ip for ip in ips if is_external(ip)]
    failures = ctx.find(
        FAILED_LOGON_IDS,
        before=ctx.last,
        match=lambda e: e.user == user or bool(e.source_ip and e.source_ip in ips),
    )
    if len(failures) >= REPEATED_FAILURE_COUNT:
        ctx.add(75, f"{len(failures)} failed logons for {user} came before this {kind} logon: likely compromised credentials")
        ctx.technique("T1110", "T1078")
        ctx.link(failures, "failed logons before this success")
        if external:
            ctx.add(10, f"Logon came from public address {', '.join(external)}")
            ctx.action(f"Block {', '.join(external)} at the firewall or VPN edge")
        ctx.action(f"Reset the password for {user} and end its active sessions")
        ctx.action(f"Review processes, file access, and logons by {user} after this logon")
        return Outcome(MALICIOUS, "credential_access", f"{user} logged on after a run of failed attempts: likely a successful brute force.", 0.9)

    if external:
        rdp = logon_type == "10"
        ctx.add(55 if rdp else 45, f"{kind.capitalize()} logon by {user} from public address {', '.join(external)}")
        ctx.technique("T1021.001" if rdp else "T1078", "T1133")
        ctx.action(f"Confirm with {user} that the logon from {', '.join(external)} was theirs")
        ctx.action("Check whether the address belongs to a known VPN or partner range")
        return Outcome(SUSPICIOUS, "initial_access", f"{user} logged on from the public internet.", 0.6)

    ctx.add(15, f"{kind.capitalize()} logon by {user} with no failed attempts before it")
    if logon_type == "10":
        ctx.action(f"Confirm {user} is expected to use RDP on {ctx.primary.host}")
    origin = f"from internal address {', '.join(ips)}" if ips else "on this host"
    return Outcome(
        BENIGN, "routine_activity", f"Normal {kind} logon by {user}.", 0.75,
        f"{user} signed in ({kind}) {origin}. No failed logons for this account or address came before it, "
        "and the logon did not come from the public internet, so there is no sign of guessed or stolen credentials.",
    )


def triage_special_privileges(ctx: TriageContext) -> Outcome:
    user = ctx.primary.user
    if not user:
        ctx.add(5, "Privileges assigned to a Windows service account at logon")
        return Outcome(
            BENIGN, "routine_activity", "Windows assigns these privileges to service accounts on every logon.", 0.85,
            "Event 4672 is written every time a privileged account logs on. With no named user, this is a Windows service "
            "receiving the privileges it always gets.",
        )
    failures = ctx.find(FAILED_LOGON_IDS, before=ctx.last, match=lambda e: e.user == user)
    if len(failures) >= REPEATED_FAILURE_COUNT:
        ctx.add(65, f"Administrative logon for {user} after {len(failures)} failed logons")
        ctx.technique("T1078.003")
        ctx.link(failures, "failed logons before this privileged logon")
        ctx.action(f"Treat {user} as compromised: reset its password and review its recent activity")
        return Outcome(SUSPICIOUS, "privilege_escalation", f"{user} received admin privileges shortly after repeated failed logons.", 0.75)
    ctx.add(20, f"Administrative logon by {user}")
    ctx.action(f"Confirm {user} is expected to hold administrative rights on {ctx.primary.host}")
    return Outcome(
        BENIGN, "routine_activity", f"{user} logged on with administrative privileges.", 0.65,
        f"{user} received administrative privileges at logon with no failed logons before it. That is expected when {user} "
        f"is an administrator on {ctx.primary.host}. If {user} should not have admin rights, treat this as suspicious instead.",
    )


def triage_log_cleared(ctx: TriageContext) -> Outcome:
    actor = message_field(ctx.message, "Account Name") or ctx.primary.user or "an unknown account"
    channel = "Security audit" if _event_id(ctx.primary) == 1102 else "System"
    ctx.add(85, f"{channel} log cleared by {actor}")
    ctx.technique("T1070.001")
    earlier = ctx.find(
        FAILED_LOGON_IDS | SUCCESSFUL_LOGON_IDS | ACCOUNT_CREATED_IDS | GROUP_ADD_IDS | {4688, 4697, 4698},
        before=ctx.first,
        window=ACCOUNT_WINDOW,
        match=lambda e: e.user is not None,
    )
    if earlier:
        ctx.add(5, f"{_plural(len(earlier), 'security event')} on this host earlier that the attacker may have wanted hidden")
        ctx.link(earlier, "activity before the log was cleared")
    ctx.action("Pull the cleared log's records from the SIEM or event forwarding, if collected")
    ctx.action(f"Confirm whether {actor} cleared the log as part of approved maintenance")
    ctx.action(f"Review all activity by {actor} on {ctx.primary.host} in the preceding hours")
    return Outcome(MALICIOUS, "defense_evasion", f"The {channel} log was cleared, a common step to hide an intrusion.", 0.85)


def triage_account_created(ctx: TriageContext) -> Outcome:
    new_name = message_field(ctx.message, "Account Name", "New Account") or ctx.primary.user or "a new account"
    new_sid = message_field(ctx.message, "Security ID", "New Account")
    creator = message_field(ctx.message, "Account Name", "Subject") or "an unknown account"
    ctx.add(45, f"Local account {new_name} created by {creator}")
    ctx.technique("T1136.001")
    ctx.action(f"Confirm with {creator} or IT that {new_name} was requested")

    def into_privileged_group(event: Any) -> bool:
        group = (message_field(event.message, "Group Name", "Group") or "").lower()
        member = message_field(event.message, "Security ID", "Member")
        return group in PRIVILEGED_GROUPS and (not new_sid or not member or member == new_sid)

    adds = ctx.find(GROUP_ADD_IDS, window=ACCOUNT_WINDOW, after=ctx.first, match=into_privileged_group)
    if adds:
        group = message_field(adds[0].event.message, "Group Name", "Group")
        ctx.add(40, f"{new_name} was then added to the privileged group {group}")
        ctx.technique("T1098")
        ctx.link(adds, "new account added to a privileged group")
        ctx.action(f"Disable {new_name} until the request is verified")
        return Outcome(MALICIOUS, "persistence", f"A new account {new_name} was created and given admin rights: a backdoor account pattern.", 0.85)
    return Outcome(SUSPICIOUS, "persistence", f"A new local account {new_name} was created.", 0.6)


def triage_group_member_added(ctx: TriageContext) -> Outcome:
    group = message_field(ctx.message, "Group Name", "Group") or "a group"
    member_sid = message_field(ctx.message, "Security ID", "Member")
    member = message_field(ctx.message, "Account Name", "Member") or member_sid or "an account"
    actor = message_field(ctx.message, "Account Name", "Subject") or ctx.primary.user or "an unknown account"
    if group.lower() not in PRIVILEGED_GROUPS:
        ctx.add(20, f"{member} added to non-privileged group {group} by {actor}")
        return Outcome(
            BENIGN, "routine_activity", f"Membership change in non-privileged group {group}.", 0.7,
            f"{group} is not an administrative group (such as Administrators or Domain Admins), so joining it grants "
            "no elevated rights. Group changes like this are normal account administration.",
        )

    ctx.add(65, f"{member} added to privileged group {group} by {actor}")
    ctx.technique("T1098")
    ctx.action(f"Confirm the change with {actor}; remove {member} from {group} if it was not approved")
    created = ctx.find(
        ACCOUNT_CREATED_IDS,
        window=ACCOUNT_WINDOW,
        before=ctx.last,
        match=lambda e: not member_sid or message_field(e.message, "Security ID", "New Account") == member_sid,
    )
    if created:
        name = message_field(created[0].event.message, "Account Name", "New Account") or member
        ctx.add(20, f"The member is {name}, an account created shortly before")
        ctx.technique("T1136.001")
        ctx.link(created, "account created before being made privileged")
        ctx.action(f"Disable {name} until the request is verified")
        return Outcome(MALICIOUS, "persistence", f"A freshly created account was added to {group}: a backdoor account pattern.", 0.85)
    return Outcome(SUSPICIOUS, "privilege_escalation", f"An account was added to the privileged group {group}.", 0.7)


def triage_service_installed(ctx: TriageContext) -> Outcome:
    name = message_field(ctx.message, "Service Name") or "unnamed service"
    path = message_field(ctx.message, "Service File Name") or ""
    start = (message_field(ctx.message, "Service Start Type") or "").lower()
    account = message_field(ctx.message, "Service Account") or ""
    ctx.technique("T1543.003")
    verdict = SUSPICIOUS
    if not path:
        ctx.add(40, f"Service {name} installed; the message names no binary")
    elif SERVICE_INTERPRETER.search(path):
        ctx.add(80, f"Service {name} runs a command or script interpreter: {path}")
        ctx.technique("T1569.002", "T1059")
        verdict = MALICIOUS
    elif USER_WRITABLE_PATH.search(path) and not TRUSTED_PATH.search(path):
        ctx.add(70, f"Service {name} runs from a user-writable folder: {path}")
    elif TRUSTED_PATH.search(path):
        ctx.add(20, f"Service {name} runs from a standard install location: {path}")
        verdict = BENIGN
    else:
        ctx.add(45, f"Service {name} runs from an unusual location: {path}")
    if verdict != BENIGN:
        if "auto" in start:
            ctx.add(5, "Starts automatically at boot (persistence)")
        if account.lower() in {"localsystem", "nt authority\\system"}:
            ctx.add(5, "Runs as LocalSystem")
        ctx.action(f"Scan {path or 'the service binary'} with the malware scanner and check its signature")
        ctx.action(f"Identify who installed {name}; stop and disable it if unexpected")
    else:
        ctx.techniques.clear()
        ctx.action(f"Confirm the install of {name} was expected (software update or deployment)")
    summary = {
        MALICIOUS: f"Service {name} launches a script interpreter, a common persistence and execution trick.",
        SUSPICIOUS: f"A new service {name} was installed from an unexpected location.",
        BENIGN: f"Service {name} was installed from a standard program location.",
    }[verdict]
    explanation = (
        f"{path} is in a standard install folder (Program Files or Windows) that only administrators and installers can "
        "write to, and it is not a command or script interpreter. Software installs and updates create services like this routinely."
    ) if verdict == BENIGN else ""
    return Outcome(verdict, "persistence" if verdict != BENIGN else "routine_activity", summary, 0.8 if verdict != SUSPICIOUS else 0.65, explanation)


def decode_powershell(command: str) -> Optional[str]:
    """Decode the payload of ``powershell -enc`` (base64 of UTF-16LE text)."""
    match = ENCODED_PAYLOAD.search(command)
    if not match:
        return None
    payload = match.group(1)
    try:
        text = base64.b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError):
        return None
    return text if text.isprintable() else None


def _score_command(ctx: TriageContext, command: str) -> float:
    """Score command-line indicators, including those inside an encoded payload."""
    decoded = decode_powershell(command)
    if decoded:
        command = f"{command}\n{decoded}"
    total = 0.0
    for indicator in COMMAND_INDICATORS:
        if indicator.pattern.search(command):
            ctx.add(indicator.points, indicator.text)
            ctx.technique(*indicator.techniques)
            total += indicator.points
    if decoded:
        ctx.add(0, f"Decoded PowerShell payload: {decoded[:200]}")
    return total


def triage_process_creation(ctx: TriageContext) -> Outcome:
    sysmon = _log(ctx.primary) == SYSMON
    image = message_field(ctx.message, "Image" if sysmon else "New Process Name") or ""
    parent = message_field(ctx.message, "ParentImage" if sysmon else "Creator Process Name") or ""
    command = message_field(ctx.message, "CommandLine" if sysmon else "Process Command Line") or ""
    label = _basename(image) or "a process"
    total = _score_command(ctx, f"{image} {command}")
    if OFFICE_PARENT.search(parent) and SHELL_CHILD.search(image):
        ctx.add(40, f"{_basename(parent)} started {label}: Office macro behaviour")
        ctx.technique("T1566.001", "T1204.002")
        total += 40
    if image and USER_WRITABLE_PATH.search(image) and not TRUSTED_PATH.search(image):
        ctx.add(15, f"{label} runs from a user-writable folder")
        total += 15
    if not total:
        ctx.add(10, f"{label} started by {_basename(parent) or 'an unknown parent'} with no suspicious command-line indicators")
        return Outcome(
            BENIGN, "routine_activity", f"Ordinary launch of {label}.", 0.6,
            f"{label} started with none of the command-line signs of attacker tooling (encoded or hidden PowerShell, download "
            "commands, credential dumping), it does not run from a user-writable folder, and it was not started by an Office application.",
        )
    ctx.add(10, "Base score for a flagged process launch")
    ctx.action(f"Review the full command line and the parent chain of {label}")
    ctx.action(f"Scan {image or label} and any files it wrote with the malware scanner")
    if total >= 60:
        ctx.action(f"If unexpected, isolate {ctx.primary.host} and collect memory before rebooting")
        return Outcome(MALICIOUS, "execution", f"{label} ran with clear attacker tradecraft on its command line.", 0.85)
    return Outcome(SUSPICIOUS, "execution", f"{label} ran with suspicious command-line options.", 0.65)


def triage_scheduled_task(ctx: TriageContext) -> Outcome:
    task = message_field(ctx.message, "Task Name") or "an unnamed task"
    command = " ".join(re.findall(r"<(?:Command|Arguments)>(.*?)</(?:Command|Arguments)>", ctx.message, re.S | re.I))
    ctx.technique("T1053.005")
    if task.lower().startswith("\\microsoft\\") and not command:
        ctx.add(10, f"Built-in Windows task {task} registered")
        ctx.techniques.clear()
        return Outcome(
            BENIGN, "routine_activity", f"Windows registered its own task {task}.", 0.7,
            "Tasks under \\Microsoft\\ are created by Windows and its updates, and this one carries no custom command to run.",
        )
    total = 30 + _score_command(ctx, command)
    ctx.add(30, f"Scheduled task {task} created{f' to run {command.strip()[:200]}' if command else ''}")
    if command and USER_WRITABLE_PATH.search(command) and not TRUSTED_PATH.search(command):
        ctx.add(20, "The task runs a file from a user-writable folder")
        total += 20
    ctx.action(f"Inspect {task} in Task Scheduler and confirm who created it")
    if total >= 70:
        return Outcome(MALICIOUS, "persistence", f"Scheduled task {task} runs attacker-style commands.", 0.8)
    return Outcome(SUSPICIOUS, "persistence", f"A new scheduled task {task} was created.", 0.6)


def triage_group_enumeration(ctx: TriageContext) -> Outcome:
    caller = message_field(ctx.message, "Process Name") or ""
    subject = (message_field(ctx.message, "Account Name", "Subject") or "").lower()
    target = (message_field(ctx.message, "Account Name", "User") or message_field(ctx.message, "Group Name", "Group") or "").lower()
    process = _basename(caller) or "an unknown process"
    if _basename(caller) in ROUTINE_ENUMERATORS:
        ctx.add(5, f"Group membership read by {process}, which Windows does routinely")
        return Outcome(
            BENIGN, "routine_activity", f"Routine group lookup by {process}.", 0.8,
            f"{process} is a Windows component that reads group membership during normal sign-in, policy and permission checks.",
        )
    if subject and subject == target:
        ctx.add(10, f"{process} looked up the groups of its own account ({subject})")
        return Outcome(
            BENIGN, "routine_activity", f"{process} read its own account's group membership.", 0.7,
            "A program reading the groups of the account it runs as is how Windows checks permissions; it reveals "
            "nothing about other accounts, so it is not reconnaissance.",
        )
    ctx.add(40, f"{process} enumerated the membership of {target or 'another account or group'}")
    ctx.technique("T1087.001", "T1069.001")
    ctx.action(f"Check what {process} is and why it is enumerating accounts")
    return Outcome(SUSPICIOUS, "discovery", f"{process} enumerated local accounts or groups.", 0.55)


def triage_time_change(ctx: TriageContext) -> Outcome:
    caller = message_field(ctx.message, "Process Name") or ""
    process = _basename(caller) or "an unknown process"
    if process in TIME_SERVICES:
        ctx.add(5, f"Clock adjusted by {process} (time synchronisation)")
        return Outcome(
            BENIGN, "routine_activity", "Routine clock synchronisation.", 0.8,
            f"{process} is the Windows time service, which adjusts the clock regularly to stay in sync with a time server.",
        )
    ctx.add(40, f"System time changed by {process}")
    ctx.technique("T1070.006")
    ctx.action("Check whether events around the change have misleading timestamps")
    return Outcome(SUSPICIOUS, "defense_evasion", f"{process} changed the system clock.", 0.55)


def triage_malware(ctx: TriageContext) -> Outcome:
    meta = ctx.primary.metadata
    verdict = meta.get("verdict")
    family = meta.get("malware_family")
    probability = meta.get("family_probability") or 0
    label = meta.get("file_path") or meta.get("file_name") or str(meta.get("sha256", ""))[:12]
    if verdict == "malicious":
        ctx.add(85, f"Static scanner rates {label} malicious (score {ctx.primary.detector_score or 0:.3f})")
    else:
        ctx.add(65, f"Static scanner rates {label} suspicious (score {ctx.primary.detector_score or 0:.3f})")
    if family:
        ctx.add(5, f"Classified as the {family} family ({probability:.0%} confidence)")
    ctx.technique(*(meta.get("mitre_techniques") or [])[:8])
    ctx.action(f"Quarantine {label} and block its SHA-256 on other endpoints")
    ctx.action(f"Check whether the file ran on {ctx.primary.host}; isolate the host if it did")
    ctx.action("Search other hosts for the same hash")
    outcome = MALICIOUS if verdict == "malicious" else SUSPICIOUS
    family_text = f" ({family})" if family else ""
    return Outcome(outcome, "malware", f"Malware{family_text} found on {ctx.primary.host}.", 0.85 if outcome == MALICIOUS else 0.6)


def triage_defender_detection(ctx: TriageContext) -> Outcome:
    threat = message_field(ctx.message, "Name") or "an unnamed threat"
    path = message_field(ctx.message, "Path") or "an unknown path"
    action = message_field(ctx.message, "Action") or ""
    blocked = _event_id(ctx.primary) == 1117 or any(word in action.lower() for word in ("quarantine", "remove", "block"))
    ctx.add(70 if blocked else 85, f"Microsoft Defender detected {threat} at {path}{f' (action: {action})' if action else ''}")
    ctx.technique("T1204.002")
    ctx.action(f"Confirm Defender quarantined {path}; run a full scan of {ctx.primary.host}")
    ctx.action("Find how the file arrived (download, email, removable media)")
    if blocked:
        return Outcome(SUSPICIOUS, "malware", f"Defender blocked {threat}; confirm nothing else ran.", 0.8)
    return Outcome(MALICIOUS, "malware", f"Defender detected {threat} and has not confirmed removal.", 0.85)


def triage_operational(ctx: TriageContext) -> Outcome:
    """Non-Security channels with no specific rule: usually faults, not attacks."""
    event = ctx.primary
    level = event.metadata.get("level_name") or "event"
    provider = event.destination or "an unknown provider"
    event_id = _event_id(event)
    cves = [m for m in event.metadata.get("cisa_matches") or [] if m.get("type") == "cve"]
    keywords = [m.get("value") for m in event.metadata.get("cisa_matches") or [] if m.get("value")]
    if cves or keywords:
        ctx.add(55, f"Message matches known-exploited-vulnerability terms: {', '.join(keywords[:5])}")
        ctx.technique("T1190" if cves else "T1203")
        ctx.action("Check whether the affected product is patched against the matched CVE")
        return Outcome(SUSPICIOUS, "vulnerability", f"{provider} logged a message tied to a known exploited vulnerability.", 0.5)
    ctx.add(10, f"{level} from {provider} (event {event_id}) in the {event.metadata.get('log_name') or 'unknown'} log, with no security indicators")
    ctx.action(f"If this repeats, tell the Sentinel to ignore {provider} event {event_id} so it stops opening incidents")
    return Outcome(
        BENIGN, "operational", f"An operational {level.lower()} from {provider}, not security activity.", 0.7,
        f"This is a {level.lower()} from {provider} in the {event.metadata.get('log_name') or 'unknown'} log, not a security audit event, "
        "and it mentions no known exploited vulnerability. Messages like this are usually software faults or status updates. "
        "The Sentinel flagged it because it is unusual for this host, not because it shows attack activity.",
    )


def triage_generic(ctx: TriageContext) -> Outcome:
    """No rule applies: carry the Sentinel's score with low confidence."""
    score = float(ctx.incident.anomaly_score)
    ctx.add(score, f"No triage rule for {ctx.primary.event_type}; Sentinel anomaly score carried over")
    if ctx.occurrences > 1:
        ctx.add(min(10.0, ctx.occurrences * 2.0), f"{ctx.occurrences} occurrences")
    ctx.action("Review the raw events manually; no automated triage rule covers this event type")
    return Outcome(SUSPICIOUS, "unclassified", f"{ctx.primary.event_type.replace('_', ' ').capitalize()} needs manual review.", 0.4)


RULES: dict[tuple[str, int], Callable[[TriageContext], Outcome]] = {
    (SECURITY, 4625): triage_failed_logons,
    (SECURITY, 4771): triage_failed_logons,
    (SECURITY, 4624): triage_successful_logon,
    (SECURITY, 4672): triage_special_privileges,
    (SECURITY, 1102): triage_log_cleared,
    ("system", 104): triage_log_cleared,
    (SECURITY, 4720): triage_account_created,
    (SECURITY, 4728): triage_group_member_added,
    (SECURITY, 4732): triage_group_member_added,
    (SECURITY, 4756): triage_group_member_added,
    ("system", 7045): triage_service_installed,
    (SECURITY, 4697): triage_service_installed,
    (SECURITY, 4698): triage_scheduled_task,
    (SECURITY, 4688): triage_process_creation,
    (SYSMON, 1): triage_process_creation,
    (SECURITY, 4798): triage_group_enumeration,
    (SECURITY, 4799): triage_group_enumeration,
    (SECURITY, 4616): triage_time_change,
    (DEFENDER, 1116): triage_defender_detection,
    (DEFENDER, 1117): triage_defender_detection,
}
# Events submitted without Windows metadata (API, demos) are matched by type instead.
TYPE_RULES: dict[str, Callable[[TriageContext], Outcome]] = {
    "failed_logon": triage_failed_logons,
    "successful_logon": triage_successful_logon,
    "audit_log_cleared": triage_log_cleared,
    "event_log_cleared": triage_log_cleared,
    "service_installed": triage_service_installed,
    "process_creation": triage_process_creation,
    "user_account_created": triage_account_created,
    "group_member_added": triage_group_member_added,
    "scheduled_task_created": triage_scheduled_task,
}


def select_rule(event: Any) -> Callable[[TriageContext], Outcome]:
    if event.metadata.get("sha256"):
        return triage_malware
    event_id = _event_id(event)
    log = _log(event)
    if event_id is not None and log:
        rule = RULES.get((log, event_id))
        if rule:
            return rule
        return triage_generic if log == SECURITY else triage_operational
    return TYPE_RULES.get(event.event_type, triage_generic)


def priority_for(score: float) -> str:
    if score >= 85:
        return "P1"
    if score >= 65:
        return "P2"
    if score >= 40:
        return "P3"
    return "P4"


def decision_for(verdict: str, priority: str) -> str:
    if verdict == MALICIOUS or priority in {"P1", "P2"}:
        return "escalate"
    if verdict == SUSPICIOUS:
        return "investigate"
    return "close"


def triage(
    incident: Any,
    related: Iterable[RelatedEvent] = (),
    asset_context: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Triage an incident; returns the analysis stored as ``incident.risk_analysis``."""
    ctx = TriageContext(incident, related)
    rule = select_rule(ctx.primary)
    outcome = rule(ctx)

    if outcome.verdict != BENIGN and (asset_context or {}).get("criticality") == "high":
        ctx.add(10, f"{ctx.primary.host} is a high-criticality asset")
    score = max(0.0, min(100.0, sum(item["points"] for item in ctx.findings)))
    if outcome.verdict == BENIGN:
        score = min(score, BENIGN_RISK_CAP)
    priority = priority_for(score)
    decision = decision_for(outcome.verdict, priority)
    if decision == "close":
        ctx.action("Close as benign once reviewed")

    sentinel_techniques = incident.alert.get("mitre_techniques") or []
    return {
        "verdict": outcome.verdict,
        # The rules' own verdict, kept when a Claude review changes ``verdict``.
        "rule_verdict": outcome.verdict,
        "priority": priority,
        "triage": decision,
        "risk_score": round(score, 2),
        "confidence": outcome.confidence,
        "category": outcome.category,
        "summary": outcome.summary,
        "benign_explanation": outcome.explanation if outcome.verdict == BENIGN else "",
        "rule": rule.__name__.removeprefix("triage_"),
        "findings": ctx.findings,
        "mitre_techniques": ctx.techniques,
        "sentinel_candidate_techniques": len(sentinel_techniques),
        "correlations": ctx.correlations,
        "recommended_actions": ctx.actions,
    }

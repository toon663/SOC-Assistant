"""Plain-language explanations of an incident's codes, for analysts who do not know them by heart.

Built when an incident is served (not stored), so every incident gets the current wording,
including ones saved before this module existed.
"""
from __future__ import annotations

import json
import re
import threading
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

ATTACK_PATH = Path(__file__).resolve().parent.parent / "Sentinel_Agent" / "intel_cache" / "enterprise-attack.json"

TACTICS = {
    "reconnaissance": ("Reconnaissance", "gathering information to plan an attack"),
    "resource-development": ("Resource development", "setting up infrastructure or tools for an attack"),
    "initial-access": ("Initial access", "getting a first foothold on the network"),
    "execution": ("Execution", "running the attacker's code"),
    "persistence": ("Persistence", "making sure access survives reboots and password changes"),
    "privilege-escalation": ("Privilege escalation", "gaining administrator or SYSTEM rights"),
    "defense-evasion": ("Defense evasion", "hiding activity or disabling security tools"),
    "credential-access": ("Credential access", "stealing or guessing passwords and tokens"),
    "discovery": ("Discovery", "looking around to learn about accounts, machines and the network"),
    "lateral-movement": ("Lateral movement", "spreading from this machine to others"),
    "collection": ("Collection", "gathering data the attacker wants"),
    "command-and-control": ("Command and control", "communicating with attacker-controlled servers"),
    "exfiltration": ("Exfiltration", "copying data out of the organisation"),
    "impact": ("Impact", "disrupting, destroying or encrypting systems and data"),
}

VERDICTS = {
    "malicious": "Malicious: the evidence matches attacker activity.",
    "suspicious": "Suspicious: this could be an attack; a person needs to check it.",
    "benign": "Benign: expected system or user activity, or a software fault, not an attack.",
}

PRIORITIES = {
    "P1": "P1 (critical): act immediately.",
    "P2": "P2 (high): act within the hour.",
    "P3": "P3 (medium): look at it today.",
    "P4": "P4 (low): informational; review when convenient.",
}

DECISIONS = {
    "escalate": "Escalate: hand this to an incident responder now.",
    "investigate": "Investigate: an analyst should check the facts before deciding.",
    "close": "Close: no action needed once you have read the explanation.",
}

CATEGORIES = {
    "credential_access": "Password or account attack",
    "initial_access": "Possible outside break-in",
    "privilege_escalation": "Gaining admin rights",
    "defense_evasion": "Hiding tracks",
    "persistence": "Staying on the machine",
    "execution": "Suspicious program run",
    "discovery": "Looking around the system",
    "malware": "Malware",
    "vulnerability": "Known exploited vulnerability",
    "routine_activity": "Routine activity",
    "operational": "Operational (non-security) message",
    "unclassified": "Not classified by any rule",
}

# Event IDs the Sentinel treats as high-risk, with the log where that ID means what it says.
WATCHED_EVENTS = {
    1: ("Microsoft-Windows-Sysmon/Operational", "a program was started (Sysmon process creation)"),
    104: ("System", "the System event log was cleared"),
    1000: ("Application", "an application crashed"),
    1074: ("System", "someone or something shut down or restarted the computer"),
    1102: ("Security", "the Security audit log was cleared"),
    4616: ("Security", "the system clock was changed"),
    4624: ("Security", "an account logged on"),
    4625: ("Security", "an account failed to log on"),
    4648: ("Security", "a logon used explicitly typed credentials (for example runas, or a tool reusing a stolen password)"),
    4672: ("Security", "a logon received administrator-level privileges"),
    4688: ("Security", "a new program was started"),
    4697: ("Security", "a service was installed"),
    4698: ("Security", "a scheduled task was created"),
    4720: ("Security", "a user account was created"),
    4722: ("Security", "a user account was enabled"),
    4728: ("Security", "a member was added to a global security group"),
    4732: ("Security", "a member was added to a local security group"),
    4756: ("Security", "a member was added to a universal security group"),
    4768: ("Security", "a Kerberos logon ticket was requested"),
    4769: ("Security", "a Kerberos service ticket was requested"),
    4771: ("Security", "Kerberos pre-authentication failed (a bad password on a domain account)"),
    4776: ("Security", "the computer checked an account's password (NTLM)"),
    4798: ("Security", "a program listed a user's group memberships"),
    4799: ("Security", "a program listed the members of a group"),
    7040: ("System", "a service's start type was changed"),
    7045: ("System", "a new service was installed"),
}

# Mirrors Sentinel_Agent's SUSPICIOUS_MESSAGE_PATTERNS, with why each one is watched.
MESSAGE_PATTERNS = (
    (re.compile(r"failed\s+logon", re.I), "failed logons are how password guessing shows up"),
    (re.compile(r"audit\s+(log\s+)?cleared", re.I), "attackers clear logs to hide what they did"),
    (re.compile(r"privilege", re.I), "privileges are what attackers need to take over a machine, though the word also appears in many routine logon messages"),
    (re.compile(r"ransomware|mimikatz|cobalt\s*strike|powershell\s+-enc", re.I), "it names a well-known attack tool or technique"),
    (re.compile(r"access\s+is\s+denied", re.I), "repeated access-denied errors can mean someone is probing for things they should not reach"),
)

# The malware scanner's feature groups (as it labels them), and what they say about a file.
MALWARE_INDICATORS = {
    "file size and general structure": "the file's overall size and layout resemble known malware",
    "byte distribution": "the mix of bytes in the file resembles known malware",
    "entropy (packing/encryption)": "parts of the file look compressed or encrypted, a common way to hide malicious code from scanners",
    "embedded strings (URLs, paths, registry keys)": "text inside the file (web addresses, file paths, registry keys) resembles what malware carries",
    "PE header fields": "the program header has values typical of malware",
    "section layout": "the way the program is divided into sections is unusual or typical of packed malware",
    "imported APIs": "the Windows functions it calls (for example to inject code, log keys or reach the network) resemble malware",
    "exported functions": "the functions it offers to other programs resemble malware",
    "data directories": "its internal tables (resources, relocations, debug data) resemble malware",
    "Rich header (build toolchain)": "the compiler fingerprint matches tools used to build known malware",
    "code signature": "its digital signature is missing, invalid or resembles malware signing",
    "PE format anomalies": "the file breaks Windows program-format rules, which malware often does to confuse analysis tools",
}

PLAYBOOKS = {
    "monitor_and_investigate": {
        "title": "Monitor and investigate",
        "what": "No automatic containment. Keep watching {host} and work through the recommended next steps.",
    },
    "contain_endpoint": {
        "title": "Contain the computer",
        "what": "Isolate {host} from the network so an attacker on it cannot reach other machines or send data out. "
                "It stays powered on so evidence in memory is kept for investigation.",
    },
    "contain_and_disable_user": {
        "title": "Contain the computer and disable the account",
        "what": "Isolate {host} from the network and disable the account {user}, so stolen credentials stop working everywhere.",
    },
}

ACTION_STATUSES = {
    "approval_required": "Waiting for approval: nothing has been done to the computer or account yet.",
    "executed": "Carried out (simulated in this demo; no real computer or account was changed).",
    "resolved": "Closed by an analyst.",
    "denied": "Rejected by the reviewer and sent back for re-triage; nothing was changed.",
    "blocked_by_policy": "Approved, but the safety policy blocked every action when it was re-checked.",
    "action_failed": "Some actions did not complete or could not be confirmed; check each action below.",
}

ACTION_NAMES = {
    "isolate_endpoint": "isolate the computer",
    "disable_user": "disable the account",
    "block_ip": "block the source address",
    "quarantine_file": "quarantine the file",
}


def explain_model_plan(incident: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    """The trained Orchestrator's plan: its score for each action, and what policy changed."""
    options = incident.get("response_options") or []
    scored = ", ".join(
        f"{ACTION_NAMES.get(o['action'], o['action'])} {o['probability']:.0%} (needs {o['threshold']:.0%})"
        for o in sorted(options, key=lambda o: -o["probability"])
    )
    chosen = [ACTION_NAMES.get(s["action"], s["action"]) for s in plan.get("steps", []) if s["action"] in ACTION_NAMES]
    parts = [f"The Orchestrator's trained model scored each possible response: {scored}."]
    skipped = [o for o in options if o["probability"] >= o["threshold"] and not o["selected"]]
    if skipped:
        parts.append(" ".join(f"It would {ACTION_NAMES.get(o['action'], o['action'])}, but there is {o['reason']}." for o in skipped))
    for step in plan.get("dropped_steps", []):
        parts.append(f"The safety policy removed \"{ACTION_NAMES.get(step['action'], step['action'])}\": {step['policy']['reason']}.")
    if plan.get("guardrail"):
        parts.append(plan["guardrail"])
    parts.append(f"Proposed: {', '.join(chosen)}." if chosen else "Nothing scored high enough to act on automatically, so the plan is to monitor.")
    analysis = incident.get("risk_analysis") or {}
    if analysis.get("verdict") == "benign" and chosen:
        parts.append("The Analyst rated this benign, so check whether this response is really needed before approving it.")

    result = incident.get("action_result") or {}
    status = result.get("status")
    status_text = ACTION_STATUSES.get(status, status.replace("_", " ") if status else "")
    if status == "approval_required" and not chosen:
        status_text = "No automatic action to approve: this response only monitors. Approve to confirm, or reject to send it back for re-triage."
    what = " ".join(f"{s['description']} ({s['target']})." for s in plan.get("steps", []))
    return {
        "name": plan.get("playbook"),
        "title": plan.get("title"),
        "what": what,
        "why": " ".join(parts),
        "next": "",
        "status": status_text,
        "decided_by": "model",
        "actions": [
            {"action": a.get("action"), "target": a.get("target"), "status": a.get("status"), "validated": a.get("validated"), "reason": a.get("reason")}
            for a in result.get("actions") or []
        ],
    }

_attack_lock = threading.Lock()


@lru_cache(maxsize=1)
def attack_catalog() -> dict[str, dict[str, Any]]:
    """ATT&CK technique ID -> name, tactics and first sentence of its description."""
    with _attack_lock:
        try:
            data = json.loads(ATTACK_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
    # Current entries first; revoked ones only fill in IDs that MITRE has since renumbered,
    # since the rules and older catalogs still use them.
    patterns = sorted(
        (o for o in data.get("objects", []) if o.get("type") == "attack-pattern"),
        key=lambda o: bool(o.get("revoked")),
    )
    entries: dict[str, dict[str, Any]] = {}
    for item in patterns:
        technique_id = next(
            (ref.get("external_id") for ref in item.get("external_references", []) if ref.get("source_name") == "mitre-attack"),
            None,
        )
        if technique_id and technique_id not in entries:
            entries[technique_id] = {
                "name": item.get("name", technique_id),
                "tactics": [phase["phase_name"] for phase in item.get("kill_chain_phases", []) if phase.get("kill_chain_name") == "mitre-attack"],
                "meaning": _first_sentence(item.get("description", "")),
            }
    # Sub-techniques read better with their parent's name: "Brute Force: Password Guessing".
    for technique_id, entry in entries.items():
        parent = entries.get(technique_id.split(".")[0])
        if "." in technique_id and parent:
            entry["name"] = f"{parent['name']}: {entry['name']}"
    return entries


def warm_up() -> None:
    """Load the ATT&CK catalog in the background so the first request is not slow."""
    threading.Thread(target=attack_catalog, name="attack-catalog", daemon=True).start()


def _first_sentence(text: str) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text).replace("\n", " ")
    match = re.match(r"(.+?[.!?])(\s|$)", text.strip())
    return re.sub(r"\s+", " ", (match.group(1) if match else text)).strip()


def technique(technique_id: str) -> dict[str, Any]:
    entry = attack_catalog().get(technique_id)
    if not entry:
        return {"id": technique_id, "name": technique_id, "tactics": [], "meaning": ""}
    return {
        "id": technique_id,
        "name": entry["name"],
        "tactics": [TACTICS.get(t, (t.replace("-", " ").capitalize(), ""))[0] for t in entry["tactics"]],
        "meaning": entry["meaning"],
    }


def _pct(value: Any) -> str:
    try:
        return f"{float(value):.0%}"
    except (TypeError, ValueError):
        return "?"


def explain_event(event: dict[str, Any]) -> str:
    """One sentence on what the Windows event records."""
    meta = event.get("metadata") or {}
    event_id = meta.get("windows_event_id")
    log = meta.get("log_name")
    first_line = (event.get("message") or "").strip().splitlines()[0].strip() if event.get("message") else ""
    if event_id is None:
        return first_line or f"A {str(event.get('event_type', 'security')).replace('_', ' ')} event."
    known = WATCHED_EVENTS.get(int(event_id))
    if not first_line and known and (known[0] == log or not log):
        first_line = f"This records that {known[1]}."
    source = event.get("destination") or "Windows"
    where = f"Event {event_id} from {source} in the {log or 'unknown'} log"
    return f"{where}: {first_line}" if first_line else f"{where}."


def readable_type(event: dict[str, Any]) -> str:
    """'failed_logon' -> 'Failed logon'; 'windows_event_10010' -> the event's own first line, or 'Windows event 10010'."""
    event_type = str(event.get("event_type") or "")
    meta = event.get("metadata") or {}
    event_id, log = meta.get("windows_event_id"), meta.get("log_name")
    known = WATCHED_EVENTS.get(int(event_id)) if event_id is not None else None
    # Sentinel names Windows events by ID alone, so an ID reused in another log gets the wrong name.
    trusted = known is None or not log or known[0] == log
    if event_id is None or (trusted and not re.fullmatch(r"windows_event(_\d+)?", event_type)):
        return event_type.replace("_", " ").capitalize() or "Security event"
    first_line = (event.get("message") or "").strip().splitlines()[0].strip() if event.get("message") else ""
    first_line = re.split(r"(?<=\.)\s", first_line)[0].rstrip(".:")
    if first_line:
        return first_line if len(first_line) <= 70 else first_line[:67].rstrip() + "…"
    if known and trusted:
        return known[1].capitalize()
    return f"Windows event {event_id}"


def readable_title(incident: dict[str, Any]) -> str:
    """Replace the Sentinel's 'Potential <code> incident' title; other titles (malware) are already readable."""
    title = (incident.get("alert") or {}).get("title") or ""
    event = (incident.get("events") or [{}])[0]
    if not title or re.fullmatch(r"Potential \S+ incident", title):
        source = event.get("destination") or ""
        return f"{readable_type(event)}{f' ({source})' if source and 'Security-Auditing' not in source else ''}"
    return title


def explain_reason(reason: str, incident: dict[str, Any]) -> str:
    """Translate one Sentinel or malware-scanner detection reason into plain language."""
    event = (incident.get("events") or [{}])[0]
    meta = event.get("metadata") or {}

    match = re.fullmatch(r"MITRE ATT&CK/CAR mapping \((.*)\)", reason)
    if match:
        candidates = (incident.get("alert") or {}).get("mitre_techniques") or []
        examples = [technique(t)["name"] for t in candidates[:3]] or [match.group(1)]
        count = len(candidates) or len(match.group(1).split(","))
        return (
            f"MITRE ATT&CK, a public catalogue of attacker behaviour, lists this kind of event as one that can appear during "
            f"{count} attacker technique{'s' if count != 1 else ''} (for example {', '.join(examples)}). "
            "That means attackers can cause events like this, not that this particular one was caused by an attacker."
        )

    if reason == "CISA KEV indicator in message":
        matches = [m.get("value") for m in meta.get("cisa_matches") or [] if m.get("value")]
        named = f" ({', '.join(matches[:4])})" if matches else ""
        return (
            f"The message mentions a product or CVE{named} on CISA's Known Exploited Vulnerabilities list: flaws that attackers "
            "are actively using. Check that the affected software is patched."
        )

    match = re.fullmatch(r"high-risk eventId (\d+)", reason)
    if match:
        event_id = int(match.group(1))
        log = meta.get("log_name")
        known = WATCHED_EVENTS.get(event_id)
        if not known:
            return f"Event ID {event_id} is on the Sentinel's list of event types that attackers often generate."
        expected_log, meaning = known
        text = f"Event ID {event_id} is on the Sentinel's watch list because, in the {expected_log} log, it means {meaning}."
        if log and log != expected_log:
            text += (
                f" This event came from the {log} log, where ID {event_id} means something else. Windows reuses event IDs "
                "across logs, so this match is a coincidence and on its own is not a sign of attack."
            )
        return text

    match = re.fullmatch(r"severity level (.*)", reason)
    if match:
        return (
            f"Windows recorded this entry at the \"{match.group(1)}\" level. The Sentinel takes a second look at every Error "
            "and Critical entry, but most of them come from software faults (crashes, timeouts, failed updates) rather than attacks."
        )

    if reason == "suspicious message pattern":
        # Reasons are merged across the group's events, so the phrase may be in any of them.
        messages = " \n".join(item.get("message") or "" for item in incident.get("events") or [])
        for pattern, why in MESSAGE_PATTERNS:
            hit = pattern.search(messages)
            if hit:
                return f"The message contains the phrase \"{hit.group(0)}\", which the Sentinel watches for because {why}."
        return (
            "The Sentinel matched wording it associates with attack activity (failed logons, cleared logs, privileges, "
            "known attack tools or access denied) in the raw event data. That text is not in the stored message, so check the raw event."
        )

    if reason == "random-forest decision boundary":
        return (
            "No specific rule fired: the machine-learning model judged this event unusual compared with the normal activity "
            "it learned from this computer's logs."
        )

    match = re.fullmatch(r"Static ML score ([\d.]+) \((\w+); suspicious >= ([\d.]+), malicious >= ([\d.]+)\)", reason)
    if match:
        score, verdict, suspicious, malicious = match.groups()
        return (
            f"The malware scanner, a machine-learning model that inspects the file's structure without running it, scored it "
            f"{float(score):.2f} on a 0 to 1 scale. Files count as suspicious from {float(suspicious):.2f} and malicious from "
            f"{float(malicious):.2f}, so this one is rated {verdict}."
        )

    match = re.fullmatch(r"Family: (.*) \(p=([\d.]+)\)", reason)
    if match:
        return f"It most closely resembles the {match.group(1)} malware family ({_pct(match.group(2))} match), which says what the file is likely built to do."

    match = re.fullmatch(r"Family uncertain; closest: (.*) \(p=([\d.]+)\)", reason)
    if match:
        return f"It does not clearly match any known malware family; the closest is {match.group(1)} at only {_pct(match.group(2))}, so treat the family as a guess."

    match = re.fullmatch(r"Indicator: (.*)", reason)
    if match:
        why = MALWARE_INDICATORS.get(match.group(1))
        return f"What pushed the score up: {why}." if why else f"What pushed the score up: the file's {match.group(1)}."

    return reason


def explain_detection(incident: dict[str, Any]) -> dict[str, Any]:
    alert = incident.get("alert") or {}
    events = incident.get("events") or [{}]
    event = events[0]
    meta = event.get("metadata") or {}
    count = alert.get("occurrence_count") if isinstance(alert.get("occurrence_count"), int) else len(events)
    if meta.get("sha256"):
        summary = (
            f"The Sentinel's malware scanner flagged the file {meta.get('file_path') or meta.get('file_name') or 'that was scanned'} "
            f"on {event.get('host') or 'an unknown computer'}."
        )
    else:
        summary = (
            f"The Sentinel, the machine-learning detector that watches Windows Event Viewer, flagged "
            f"{count} event{'s' if count != 1 else ''} on {event.get('host') or 'an unknown computer'}."
        )
    score = alert.get("detector_score")
    model_note = ""
    if score and not meta.get("sha256"):
        model_note = (
            f"Model score {float(score):.2f} out of 1. The model learned from rough labels and scores most flagged events close "
            "to 1, so it says \"worth a look\", not \"how dangerous\". The Analyst triage above decides how serious it is."
        )
    return {
        "summary": summary,
        "event": explain_event(event),
        "model_note": model_note,
        "reasons": [{"code": reason, "text": explain_reason(reason, incident)} for reason in alert.get("detection_reasons") or []],
    }


def explain_techniques(incident: dict[str, Any]) -> dict[str, Any]:
    analysis = incident.get("risk_analysis") or {}
    confirmed = [technique(t) for t in analysis.get("mitre_techniques") or []]
    candidates = (incident.get("alert") or {}).get("mitre_techniques") or []
    confirmed_ids = {item["id"] for item in confirmed}
    return {
        "confirmed": confirmed,
        "candidates": [technique(t) for t in candidates if t not in confirmed_ids][:25],
        "candidate_count": len([t for t in candidates if t not in confirmed_ids]),
    }


def explain_triage(analysis: dict[str, Any]) -> dict[str, str]:
    if not analysis.get("verdict"):
        return {}
    return {
        "verdict": VERDICTS.get(analysis["verdict"], analysis["verdict"]),
        "priority": PRIORITIES.get(analysis.get("priority", ""), analysis.get("priority", "")),
        "decision": DECISIONS.get(analysis.get("triage", ""), analysis.get("triage", "")),
        "category": CATEGORIES.get(analysis.get("category", ""), str(analysis.get("category", "")).replace("_", " ")),
        "score": (
            f"{round(float(analysis.get('risk_score', 0)))} out of 100: the sum of the points in the breakdown below. "
            "40 or more needs attention; 65 or more is high priority."
        ),
        "confidence": f"{_pct(analysis.get('confidence'))}: how firmly the evidence supports this verdict.",
    }


def explain_playbook(incident: dict[str, Any]) -> dict[str, Any]:
    name = incident.get("selected_playbook")
    if not name:
        return {}
    plan = incident.get("response_plan") or {}
    if plan.get("decided_by") == "model":
        return explain_model_plan(incident, plan)
    event = (incident.get("events") or [{}])[0]
    host = event.get("host") or "the computer"
    user = event.get("user") or "the user"
    playbook = PLAYBOOKS.get(name, {"title": name.replace("_", " ").capitalize(), "what": ""})
    forecast = incident.get("forecast") or {}
    impact = incident.get("business_impact") or {}
    intel = incident.get("threat_intel") or {}
    analysis = incident.get("risk_analysis") or {}
    forecast_score = float(forecast.get("forecast_score", 0))
    impact_score = float(impact.get("impact_score", 0))
    deciding = max(forecast_score, impact_score)

    reputation = intel.get("reputation")
    ip_part = f"the source address's reputation ({reputation})" if intel.get("ip") else "no source address"
    fallback = ["No trained Orchestrator model is loaded, so fixed score thresholds chose this response."] if plan.get("decided_by") == "rules_fallback" else []
    parts = fallback + [
        f"The response is chosen from the higher of two scores: the risk forecast ({forecast_score:.0f}/100), which combines the "
        f"triage score ({float(analysis.get('risk_score', 0)):.0f}) with {ip_part}, and the business impact ({impact_score:.0f}/100)"
    ]
    if impact.get("criticality") == "high":
        parts[-1] += f", which is raised because {host} is marked as a high-importance machine."
    else:
        parts[-1] += f", which equals the forecast because {host} is a normal-importance machine."
    shown = f"{deciding:.1f}".removesuffix(".0")
    if name == "contain_and_disable_user":
        parts.append(f"At {shown}, it is 85 or more and the activity is tied to the account {user}, so both the machine and the account are contained.")
    elif name == "contain_endpoint":
        parts.append(f"At {shown}, it is 60 or more, the level where the machine is isolated.")
    else:
        parts.append(f"At {shown}, it is below 60, the level where containment would start, so no automatic action is taken.")
    if analysis.get("verdict") == "benign" and name != "monitor_and_investigate":
        parts.append("The Analyst rated this benign, so check whether containment is really needed before approving it.")
    if analysis.get("verdict") == "malicious" and name == "monitor_and_investigate":
        parts.append(
            "The Analyst rated this malicious, but the forecast weighs in the source address's reputation and can pull the "
            "score under the containment line. Do not wait on the automation: follow the recommended next steps and contain "
            f"{host} by hand if they confirm the attack."
        )

    path = [step for step in forecast.get("risk_path") or [] if step != "contained anomaly"]
    next_steps = f"If this is an attack, what could come next: {', '.join(path)}." if path and name != "monitor_and_investigate" else ""
    status = (incident.get("action_result") or {}).get("status")
    status_text = ACTION_STATUSES.get(status, status.replace("_", " ") if status else "")
    if status == "approval_required" and name == "monitor_and_investigate":
        status_text = "No automatic action to approve: this response only monitors. Resolve the incident once you have reviewed it."
    return {
        "name": name,
        "title": playbook["title"],
        "what": playbook["what"].format(host=host, user=user),
        "why": " ".join(parts),
        "next": next_steps,
        "status": status_text,
    }


def explain_risk(analysis: dict[str, Any]) -> list[str]:
    """For suspicious or malicious incidents: the findings that raised the score, biggest first."""
    if analysis.get("verdict") not in {"suspicious", "malicious"}:
        return []
    findings = sorted((f for f in analysis.get("findings") or [] if float(f.get("points", 0)) > 0), key=lambda f: -float(f["points"]))
    return [f["text"] for f in findings[:4]]


def annotate(incident: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """Add an ``explanations`` block to a serialized incident."""
    if not incident:
        return incident
    analysis = incident.get("risk_analysis") or {}
    incident["explanations"] = {
        "title": readable_title(incident),
        "event_type": readable_type((incident.get("events") or [{}])[0]),
        "triage": explain_triage(analysis),
        "risk_reasons": explain_risk(analysis),
        "techniques": explain_techniques(incident),
        "detection": explain_detection(incident),
        "playbook": explain_playbook(incident),
    }
    return incident

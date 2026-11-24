"""Response actions, targets, and policy checks for the Orchestrator agent.

The Orchestrator's trained model (orchestrator_model.py) scores each response
action for an incident. This module turns those scores into a plan:

1. An action is selected when the model's probability reaches its threshold
   and the incident names something for it to act on (a host, a human account,
   a remote source IP, a file that is not a Windows system binary).
2. Every selected action is checked by the deterministic ``PolicyEngine``,
   with the model's probability as its confidence. Denied actions are dropped
   with the reason; with none left, the plan is to monitor.
3. Guardrail: if the Analyst confirms a threat (malicious, confidence >= 0.8)
   and the model proposes no containment, isolating the host is proposed anyway,
   marked ``guardrail``. It still needs policy and human approval.

Without a trained model the plan falls back to the original score thresholds,
marked ``decided_by: rules_fallback`` so it is never mistaken for the model.

Nothing here calls an external system. ``OrchestratorAgent`` in agents.py
executes the stored plan only after the human verification gate.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional

from models import ActionRequest, ActionType, ModelValidationError
from policy_engine import PolicyEngine

# Service identities that must never be the target of a disable-user step.
NON_HUMAN_ACCOUNTS = {
    "s-1-5-18", "s-1-5-19", "s-1-5-20", "system", "local service",
    "network service", "anonymous logon",
}
PROCESS_IMAGE_RE = re.compile(r"^\s*(?:New Process Name|Image):\s*([^\r\n]+)", re.M)
# Analyst verdict confidence at which a malicious incident always gets containment proposed.
CONFIRMED_THREAT_CONFIDENCE = 0.8
SYSTEM_PATH_RE =re.compile(r"^(?:[a-z]:|\\device\\harddiskvolume\d+)?\\windows\\", re.I)


@dataclass(frozen=True)
class ResponseAction:
    action: ActionType
    target: str  # host | user | source_ip | file
    title: str
    description: str


RESPONSE_ACTIONS: Dict[str, ResponseAction] = {
    item.action.value: item
    for item in (
        ResponseAction(ActionType.ISOLATE_ENDPOINT, "host", "Isolate the computer", "Cut the host off the network; it stays powered on so memory evidence is kept"),
        ResponseAction(ActionType.DISABLE_USER, "user", "Disable the account", "Disable the account so its credentials stop working everywhere"),
        ResponseAction(ActionType.BLOCK_IP, "source_ip", "Block the source address", "Block the remote source address at the firewall"),
        ResponseAction(ActionType.QUARANTINE_FILE, "file", "Quarantine the file", "Move the file to quarantine and block its hash"),
    )
}
# Model output order; a trained model stores its own copy and must match.
ACTIONS = tuple(RESPONSE_ACTIONS)

MONITOR_STEP = {
    "action": ActionType.MONITOR.value, "target_field": "host",
    "description": "Keep watching the host and work through the recommended next steps",
}

# Named playbooks for the action sets the dashboard already explains.
NAMED_PLAYBOOKS = {
    frozenset(): ("monitor_and_investigate", "Monitor and investigate"),
    frozenset({"isolate_endpoint"}): ("contain_endpoint", "Contain the computer"),
    frozenset({"isolate_endpoint", "disable_user"}): ("contain_and_disable_user", "Contain the computer and disable the account"),
}
KNOWN_PLAYBOOKS = {name for name, _ in NAMED_PLAYBOOKS.values()} | {"custom_response"}


def is_human_account(user: Optional[str]) -> bool:
    if not user or user == "-" or user.endswith("$"):
        return False
    name = user.split("\\")[-1].strip().lower()
    return name not in NON_HUMAN_ACCOUNTS and user.strip().lower() not in NON_HUMAN_ACCOUNTS


def is_remote_ip(ip: Optional[str]) -> bool:
    """Any address another machine could be blocked by: not loopback, unset, or link-local."""
    try:
        address = ipaddress.ip_address((ip or "").removeprefix("::ffff:"))
    except ValueError:
        return False
    return not (address.is_loopback or address.is_unspecified or address.is_link_local or address.is_multicast)


def is_external_ip(ip: Optional[str]) -> bool:
    return is_remote_ip(ip) and not ipaddress.ip_address((ip or "").removeprefix("::ffff:")).is_private


def file_target(event: Any) -> Optional[str]:
    """A scanned file, else the launched image unless it is a Windows system binary."""
    meta = event.metadata or {}
    if meta.get("file_path") or meta.get("sha256"):
        return meta.get("file_path") or meta.get("sha256")
    match = PROCESS_IMAGE_RE.search(event.message or "")
    if not match:
        return None
    image = match.group(1).strip()
    if not image or image == "-" or SYSTEM_PATH_RE.match(image.replace("/", "\\")):
        return None
    return image


def targets_for(incident: Any) -> Dict[str, Optional[str]]:
    primary = incident.events[0]
    return {
        "host": primary.host,
        "user": primary.user if is_human_account(primary.user) else None,
        "source_ip": primary.source_ip if is_remote_ip(primary.source_ip) else None,
        "file": file_target(primary),
    }


def incident_risk(incident: Any) -> float:
    return round(max(
        float((incident.forecast or {}).get("forecast_score", 0)),
        float((incident.business_impact or {}).get("impact_score", 0)),
        float((incident.risk_analysis or {}).get("risk_score", 0)),
    ), 2)


def playbook_for(actions: Iterable[str]) -> tuple[str, str]:
    chosen = frozenset(actions)
    if chosen in NAMED_PLAYBOOKS:
        return NAMED_PLAYBOOKS[chosen]
    titles = [RESPONSE_ACTIONS[a].title for a in ACTIONS if a in chosen]
    if len(titles) == 1:
        return "custom_response", titles[0]
    return "custom_response", ", ".join(titles[:-1]) + " and " + titles[-1].lower()


def rules_fallback_scores(incident: Any) -> Dict[str, float]:
    """The pre-model thresholds, expressed as 0/1 scores: isolate at 60, also disable at 85."""
    score = max(float((incident.forecast or {}).get("forecast_score", 0)), float((incident.business_impact or {}).get("impact_score", 0)))
    return {
        "isolate_endpoint": 1.0 if score >= 60 else 0.0,
        "disable_user": 1.0 if score >= 85 else 0.0,
        "block_ip": 0.0,
        "quarantine_file": 0.0,
    }


def _policy_step(policy: PolicyEngine, incident: Any, action: str, target: str, risk: float, confidence: float) -> Dict[str, Any]:
    try:
        decision = policy.evaluate(ActionRequest(
            action=action, incident_id=incident.incident_id, target=target,
            risk_score=min(100.0, risk), confidence=min(100.0, max(0.0, confidence)),
        ))
        return {"allowed": decision.allowed, "requires_approval": decision.requires_approval, "reason": decision.reason, "policy_id": PolicyEngine.POLICY_ID}
    except ModelValidationError as exc:
        return {"allowed": False, "requires_approval": False, "reason": str(exc), "policy_id": PolicyEngine.POLICY_ID}


def build_plan(
    incident: Any,
    policy: PolicyEngine,
    scores: Optional[Mapping[str, float]] = None,
    thresholds: Optional[Mapping[str, float]] = None,
    model_info: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Turn per-action scores into a policy-checked plan. Does not execute anything."""
    targets = targets_for(incident)
    decided_by = "model" if scores is not None else "rules_fallback"
    if scores is None:
        scores = rules_fallback_scores(incident)
        thresholds = {action: 0.5 for action in ACTIONS}
    thresholds = thresholds or {action: 0.5 for action in ACTIONS}
    risk = incident_risk(incident)

    options, steps, dropped = [], [], []
    for action in ACTIONS:
        spec = RESPONSE_ACTIONS[action]
        probability = round(float(scores.get(action, 0.0)), 4)
        threshold = float(thresholds.get(action, 0.5))
        target = targets.get(spec.target)
        if probability < threshold:
            selected, reason = False, f"score {probability:.2f} is below the {threshold:.2f} threshold"
        elif not target:
            selected, reason = False, f"no {spec.target.replace('_', ' ')} to act on"
        else:
            selected, reason = True, f"score {probability:.2f} meets the {threshold:.2f} threshold"
        options.append({
            "action": action, "title": spec.title, "probability": probability, "threshold": threshold,
            "target": target, "selected": selected, "reason": reason,
        })
        if not selected:
            continue
        step = {
            "action": action, "target": target, "target_field": spec.target, "description": spec.description,
            "probability": probability,
            "policy": _policy_step(policy, incident, action, target, risk, probability * 100),
        }
        (steps if step["policy"]["allowed"] else dropped).append(step)

    guardrail = None
    analysis = incident.risk_analysis or {}
    confirmed = analysis.get("verdict") == "malicious" and float(analysis.get("confidence", 0)) >= CONFIRMED_THREAT_CONFIDENCE
    if decided_by == "model" and confirmed and not steps and targets["host"]:
        # The model has seen few attacks of some kinds; a confirmed threat is never left at "monitor".
        step = {
            "action": "isolate_endpoint", "target": targets["host"], "target_field": "host",
            "description": RESPONSE_ACTIONS["isolate_endpoint"].description,
            "probability": round(float(scores.get("isolate_endpoint", 0.0)), 4), "guardrail": True,
            "policy": _policy_step(policy, incident, "isolate_endpoint", targets["host"], risk, float(analysis["confidence"]) * 100),
        }
        if step["policy"]["allowed"]:
            steps.append(step)
            guardrail = "The Analyst confirmed this threat but the model proposed no containment, so isolating the host is proposed as a minimum response."

    chosen = [step["action"] for step in steps]
    name, title = playbook_for(chosen)
    if not steps:
        steps = [{
            **MONITOR_STEP, "target": targets["host"] or "unknown", "probability": None,
            "policy": {"allowed": True, "requires_approval": False, "reason": "low-risk action permitted", "policy_id": PolicyEngine.POLICY_ID},
        }]
    return {
        "decided_by": decided_by,
        "model": dict(model_info or {}),
        "risk_score": risk,
        "targets": targets,
        "options": options,
        "playbook": name,
        "title": title,
        "steps": steps,
        "dropped_steps": dropped,
        "guardrail": guardrail,
        "requires_approval": any(s["policy"]["requires_approval"] for s in steps),
    }


def steps_to_actions(steps: List[Dict[str, Any]]) -> List[str]:
    return [step["action"] for step in steps if step["action"] in RESPONSE_ACTIONS]

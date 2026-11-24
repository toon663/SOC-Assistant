"""Approved, exact-match slot permutation. No executors or backend imports."""
from copy import deepcopy
from datetime import datetime, timezone
from types import MappingProxyType

from .contracts import content_hash
from .orchestrator_contract import ContractError, validate_contract

MAPPING_VERSION = "destination-option-priority.v1"
DESTINATION_PRIORITIES = MappingProxyType({
    "T1003.001": ("isolate_endpoint", "disable_user"),
    "T1021.002": ("isolate_endpoint",),
    "T1078": ("disable_user", "isolate_endpoint"),
})
MAPPING_HASH = content_hash({"version": MAPPING_VERSION, "mapping": dict(DESTINATION_PRIORITIES)})


def prioritize_response_options(baseline_options, forecast, *, now=None):
    """Only permute mapped slots; require all mapped options eligible/observed.

    A future backend bridge must supply eligible after independent evidence,
    model/threshold and policy checks. No eligibility is inferred here. Targets
    are canonical observed entity IDs; reachable-only entities are never targets.
    """
    if not isinstance(baseline_options, list) or any(not isinstance(o, dict) for o in baseline_options):
        raise ValueError("Baseline options must be a list of objects")
    result = {"mapping_version": MAPPING_VERSION, "mapping_hash": MAPPING_HASH,
              "baseline_options": deepcopy(baseline_options), "prioritized_options": deepcopy(baseline_options),
              "order_changed": False, "reason": "no_usable_forecast", "limitations": []}
    try:
        validate_contract(forecast, now=now or datetime.now(timezone.utc))
    except (ContractError, TypeError, ValueError, KeyError):
        result["reason"] = "invalid_or_expired_forecast"
        return result
    if forecast["response_type"] != "risk_forecast":
        result["reason"] = forecast["reason"]
        return result
    result["limitations"] = deepcopy(forecast["issues"])
    if forecast["status"] not in {"complete", "partial"}:
        result["reason"] = "abstained_no_forecast_decision"
        return result
    priority = DESTINATION_PRIORITIES.get(forecast["destination_technique"])
    if priority is None:
        result["reason"] = "unmapped_destination"
        return result
    positions = {action: [i for i, option in enumerate(baseline_options) if option.get("action") == action] for action in priority}
    if any(not slots for slots in positions.values()):
        result["reason"] = "mapped_option_missing"
        return result
    if any(len(slots) != 1 for slots in positions.values()):
        result["reason"] = "mapped_option_ambiguous"
        return result
    observed = {e["entity_id"] for e in forecast["blast_radius"]["observed_entities"]}
    for action in priority:
        option = baseline_options[positions[action][0]]
        if (option.get("eligible") is not True or type(option.get("approval_required")) is not bool or
            option.get("selected", True) is not True or
            ("policy" in option and (not isinstance(option["policy"], dict) or option["policy"].get("allowed") is not True))):
            result["reason"] = "mapped_option_not_independently_eligible"
            return result
        if option.get("target_entity_id") not in observed:
            result["reason"] = "mapped_target_not_observed"
            return result
    slots = sorted(p[0] for p in positions.values())
    for slot, action in zip(slots, priority):
        result["prioritized_options"][slot] = deepcopy(baseline_options[positions[action][0]])
    result["order_changed"] = result["prioritized_options"] != baseline_options
    result["reason"] = "mapped_slot_order_changed" if result["order_changed"] else "already_in_priority_order"
    return result

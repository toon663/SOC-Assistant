"""Bounded expansion over explicit local ATT&CK transition hypotheses."""

from collections import deque
import json

from .contracts import content_hash, parse_time
from .scoring import score_candidate
from .rule_schema import validate_rule_document
from .guard_context import normalize_guard_context
from .guard_evaluators import evaluate_guards

PRIVILEGE = {"none": 0, "user": 1, "admin": 2, "system": 3}


def matching_rules(technique_id, rules):
    """A parent covers descendants by default; sub-techniques never cover parents."""
    return [rule for rule in rules if (
        rule["source"] == technique_id or
        ("." not in rule["source"] and technique_id.startswith(rule["source"] + ".")
         and rule.get("include_subtechniques", True))
    ) and technique_id not in rule.get("excluded_subtechniques", [])]


def load_rules(path):
    with open(path, encoding="utf-8") as stream:
        document = json.load(stream)
    validate_rule_document(document)
    document["content_hash"] = content_hash(document)
    return document


def forecast_risk_path(alert, asset_context, impact, config, as_of, rules, weights):
    """Scores are computed here only; no model-generated paths or scores."""
    validate_rule_document({key: value for key, value in rules.items() if key != "content_hash"})
    if "guard_context" in alert:
        alert = {**alert, "guard_context": normalize_guard_context(alert["guard_context"], alert)}
    records = {record["entity_id"]: record for record in asset_context["entities"] if not record["stale"]}
    entity_types = {entity["entity_id"]: entity["entity_type"] for entity in alert["entities"]}
    events = {event["event_id"]: event for event in alert["normalized_events"]}
    cutoff_seconds = config.evidence_freshness_limit_hours * 3600
    usable = {identity: event for identity, event in events.items() if 0 <= (as_of - parse_time(event["timestamp"])).total_seconds() <= cutoff_seconds}
    outgoing = {}
    for rule in rules["rules"]:
        outgoing.setdefault(rule["source"], []).append(rule)
    candidates, rejected, unsupported = [], [], []
    usable_starting = 0
    for starting in alert["observed_techniques"]:
        source = starting["technique_id"]
        refs = sorted(ref for ref in starting["evidence_refs"] if ref in usable)
        if not matching_rules(source, rules["rules"]):
            unsupported.append({"technique_id": source, "reason": "no_outgoing_rule",
                                "catalogue_status": "syntax_valid_identity_unverified",
                                "evidence_refs": starting["evidence_refs"], "rule_version": rules["version"]})
        if not refs or alert["analyst_confidence"] == 0:
            continue
        usable_starting += 1
        if alert["verdict"] == "benign":
            continue
        # Binding is restricted to entities co-occurring in each supporting event.
        for ref in refs:
            event = usable[ref]
            bound_ids = event["entity_ids"]
            bound = [records[identity] for identity in bound_ids if identity in records]
            bound_hosts = {identity for identity in bound_ids if entity_types.get(identity) == "host"}
            bound_hosts.update(record.get("canonical_id", record["entity_id"]) for record in bound if record["entity_type"] == "host")
            age = (as_of - parse_time(event["timestamp"])).total_seconds()
            queue = deque([(source, [], {source})])
            while queue:
                current, steps, visited = queue.popleft()
                if len(steps) >= config.max_path_steps:
                    continue
                for rule in matching_rules(current, rules["rules"]):
                    if rule["target"] in visited:
                        continue
                    guard_result = evaluate_guards(rule, alert, starting, event, current, config, as_of)
                    failures = list(guard_result["failures"])
                    platforms = {record.get("platform") for record in bound if record.get("platform")}
                    privileges = [PRIVILEGE[record["privilege_level"]] for record in bound
                                  if record.get("privilege_level") is not None and
                                  ("privilege_scope_host_ids" not in record or
                                   bool(set(record["privilege_scope_host_ids"]) & bound_hosts))]
                    if not platforms:
                        failures.append("platform_unresolved")
                    elif rule["platform"] not in platforms:
                        failures.append("platform_mismatch")
                    if not privileges and rule["minimum_privilege"] != "none":
                        failures.append("privilege_unresolved")
                    elif privileges and max(privileges) < PRIVILEGE[rule["minimum_privilege"]]:
                        failures.append("privilege_insufficient")
                    relations_known = bool(bound) and all("related_assets" in record for record in bound)
                    targets = [
                        {**relation, "source_entity_id": record["entity_id"], "provider": record["provider"]}
                        for record in bound for relation in record.get("related_assets", [])
                        if relation["reachable"] and relation["relation"] == "can_access"
                        and relation["entity_type"] == "host" and relation["entity_id"] not in bound_ids
                    ]
                    if rule["requires_reachable_target"] and not targets:
                        failures.append("reachability_absent" if relations_known else "reachability_unresolved")
                    if failures:
                        rejection = {"rule_id": rule["rule_id"], "starting_technique": source,
                                     "evidence_ref": ref, "reasons": failures}
                        if guard_result["evaluations"]:
                            rejection["guard_evaluations"] = guard_result["evaluations"]
                        rejected.append(rejection)
                        continue
                    factors = {
                        "evidence_support": alert["analyst_confidence"],
                        "prerequisite_satisfaction": 1.0,
                        "privilege_fit": 1.0,
                        "reachable_target_support": (1.0 if targets else 0.0) if relations_known else None,
                        "recency": max(0.0, 1.0 - age / cutoff_seconds),
                    }
                    step = {"technique_id": rule["target"], "name": rule["target_name"],
                            "rule_id": rule["rule_id"], "factors": factors,
                            **score_candidate(factors, weights), "rationale": rule["rationale"],
                            "references": rule["references"],
                            "potential_targets": targets if rule["requires_reachable_target"] else [],
                            "assumptions": ["Observed privileges and relationships persist during the forecast window; controls may prevent progression."]}
                    if guard_result["evaluations"]:
                        step["guard_evaluations"] = guard_result["evaluations"]
                    extended = steps + [step]
                    score = min(item["likelihood_index"] for item in extended)
                    upper = min(item["uncertainty_range"][1] for item in extended)
                    identity = {"start": source, "event": ref, "rules": [item["rule_id"] for item in extended]}
                    candidates.append({"candidate_id": content_hash(identity)[:24],
                                       "starting_technique": source, "source_entity_ids": bound_ids,
                                       "evidence_refs": sorted({ref} | {identity for item in extended
                                           for evaluation in item.get("guard_evaluations", []) for identity in evaluation["evidence_refs"]}),
                                       "steps": extended,
                                       "likelihood_index": score, "uncertainty_range": [score, upper],
                                       "factor_coverage": min(item["factor_coverage"] for item in extended),
                                       "potential_targets": [target for item in extended for target in item["potential_targets"]]})
                    # A remote transition terminates expansion: we do not assume
                    # privileges or technique execution on the remote host.
                    if not rule["requires_reachable_target"] and not rule.get("terminal", False):
                        queue.append((rule["target"], extended, visited | {rule["target"]}))
    for starting in alert["observed_techniques"]:
        identity = starting["technique_id"]
        failures = [rejection for rejection in rejected if rejection["starting_technique"] == identity]
        if matching_rules(identity, rules["rules"]) and failures and all("platform_mismatch" in failure["reasons"] for failure in failures) and not any(path["starting_technique"] == identity for path in candidates):
            unsupported.append({"technique_id": identity, "reason": "platform_mismatch",
                                "catalogue_status": "known_local_rule_vocabulary",
                                "evidence_refs": starting["evidence_refs"], "rule_version": rules["version"]})
    candidates.sort(key=lambda path: (-path["likelihood_index"], len(path["steps"]), path["candidate_id"]))
    eligible = [path for path in candidates if path["likelihood_index"] >= config.min_candidate_score]
    if not usable:
        reason = "stale_evidence" if events else "insufficient_evidence"
    elif not usable_starting or alert["verdict"] == "benign":
        reason = "insufficient_evidence"
    elif not candidates:
        reason = "prerequisites_unresolved" if any(any("unresolved" in item for item in rejection["reasons"]) for rejection in rejected) else ("prerequisites_failed" if rejected else "unsupported_transition")
    elif not eligible:
        reason = "below_candidate_threshold"
    else:
        reason = None
    return {"candidate_paths": eligible[:config.max_candidates], "all_eligible_paths": eligible,
            "generated_count": len(candidates), "eligible_count": len(eligible),
            "rejected_transitions": rejected, "unsupported_starting_techniques": unsupported,
            "usable_event_count": len(usable), "abstain_reason": reason}

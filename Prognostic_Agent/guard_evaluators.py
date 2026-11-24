"""Deterministic guards: supplied facts only, no correlation or score generation."""

from .contracts import parse_time
from .guard_context import canonical_ip


def _overlap(left, right):
    return left == right or left.startswith(right + ".") or right.startswith(left + ".")


def evaluate_guards(rule, alert, starting, event, current, config, as_of):
    """Return pass/failed/unresolved diagnostics and prerequisite rejection codes."""
    declarations = rule.get("guards", [])
    if not declarations:
        return {"failures": [], "evaluations": []}
    events = {item["event_id"]: item for item in alert["normalized_events"]}
    binding = next((item for item in alert.get("guard_context", {}).get("bindings", [])
                    if item["technique_id"] == starting["technique_id"] and item["seed_event_id"] == event["event_id"]), None)
    max_age = min([config.evidence_freshness_limit_hours] +
                  [item["max_age_hours"] for item in declarations if item["type"] == "evidence_freshness"])

    def fresh(timestamp):
        return 0 <= (as_of - parse_time(timestamp)).total_seconds() <= max_age * 3600

    def same_source(item):
        try:
            return canonical_ip(item.get("source_ip")) == binding["source_ip"]
        except (ValueError, TypeError):
            return False

    def support(name):
        if binding is None:
            return None, "unresolved", "No event-bound subject assertion was supplied."
        if not same_source(event):
            return None, "unresolved", "The source address does not match the bound seed event."
        assertion = binding.get(name)
        if assertion is None:
            return None, "unresolved", "The required upstream assertion is absent."
        refs = assertion["evidence_refs"]
        if not refs:
            return assertion, "unresolved", "The upstream assertion has no supplied evidence."
        if not fresh(assertion["as_of"]) or not all(fresh(events[ref]["timestamp"]) for ref in refs):
            return assertion, "unresolved", "The assertion or its evidence is stale or future-dated."
        if any(parse_time(events[ref]["timestamp"]) > parse_time(assertion["as_of"]) for ref in refs):
            return assertion, "unresolved", "An assertion predates its supporting evidence."
        for ref in refs:
            item = events[ref]
            if binding["host_id"] not in item["entity_ids"]:
                return assertion, "unresolved", "Supporting evidence belongs to a different host."
            if name == "account_authentication" and binding["user_id"] not in item["entity_ids"]:
                return assertion, "unresolved", "Account-control evidence belongs to a different account."
            if item.get("source_ip") is not None and not same_source(item):
                return assertion, "unresolved", "Supporting evidence belongs to a different source address."
        return assertion, None, None

    evaluations = []
    for guard in declarations:
        kind = guard["type"]
        status, detail, refs, source, assertion_as_of = "pass", "Required evidence is supplied.", [], None, None
        if kind == "target_not_observed":
            if any(_overlap(item["technique_id"], rule["target"]) for item in alert["observed_techniques"]):
                status, detail = "failed", "The destination is already asserted as observed, including coarse attribution."
        elif current != starting["technique_id"]:
            status, detail = "unresolved", "An unobserved intermediate technique cannot inherit the seed's guard proof."
        elif kind == "exact_attribution":
            refs = starting["evidence_refs"]
            if starting.get("attribution", "exact") != "exact" or not refs or event["event_id"] not in refs:
                status, detail = "unresolved", "The source technique lacks exact supplied event attribution."
        elif kind == "evidence_freshness":
            refs = starting["evidence_refs"]
            if not refs or any(not fresh(events[ref]["timestamp"]) for ref in refs):
                status, detail = "unresolved", "Source evidence is absent, stale, or future-dated."
        else:
            assertion, status, detail = support(kind)
            if assertion is not None:
                refs, source, assertion_as_of = assertion["evidence_refs"], assertion["source"], assertion["as_of"]
            if status is None:
                status, detail = "pass", "Explicit upstream facts satisfy the guard."
                if kind == "analyst_correlation":
                    start, end = parse_time(assertion["window_start"]), parse_time(assertion["window_end"])
                    if source != "analyst" or event["event_id"] not in refs:
                        status, detail = "unresolved", "An Analyst-established grouping containing the seed is required."
                    elif assertion["activity"] == "unknown":
                        status, detail = "unresolved", "Online authentication activity is unknown."
                    elif assertion["activity"] != "online_authentication_failures":
                        status, detail = "failed", "Offline password cracking is outside this authentication guard."
                    elif assertion["event_count"] != len(refs):
                        status, detail = "unresolved", "The asserted count is not backed by the full supplied event list."
                    elif end > parse_time(assertion["as_of"]):
                        status, detail = "unresolved", "The correlation window ends after its assertion."
                    elif any(not start <= parse_time(events[ref]["timestamp"]) <= end for ref in refs):
                        status, detail = "unresolved", "The supplied records do not support the asserted time bounds."
                    elif any(not same_source(events[ref]) for ref in refs):
                        status, detail = "unresolved", "The asserted grouping has inconsistent source-address evidence."
                    elif assertion["event_count"] < guard["minimum_events"] or (end - start).total_seconds() > guard["window_hours"] * 3600:
                        status, detail = "failed", "The asserted count/window does not meet the declared threshold."
                elif kind == "authentication_reachability":
                    if assertion.get("reachable") is None:
                        status, detail = "unresolved", "Authentication-endpoint reachability is unknown."
                    elif not assertion["reachable"]:
                        status, detail = "failed", "The bound source cannot reach the authentication endpoint."
                elif kind == "account_authentication":
                    states = assertion.get("enabled"), assertion.get("locked"), assertion.get("blocked")
                    if states[0] is False or states[1] is True or states[2] is True:
                        status, detail = "failed", "The bound account is disabled, locked, or blocked by authentication controls."
                    elif any(value is None for value in states):
                        status, detail = "unresolved", "The bound account's authentication/control state is incomplete."
        evaluation = {"type": kind, "status": status, "detail": detail, "evidence_refs": sorted(set(refs))}
        if source is not None:
            evaluation.update(source=source, as_of=assertion_as_of,
                              subject={key: binding[key] for key in ("user_id", "host_id", "source_ip", "endpoint_id")})
        evaluations.append(evaluation)
    return {"evaluations": evaluations,
            "failures": ["guard_" + item["type"] + "_" + item["status"] for item in evaluations if item["status"] != "pass"]}

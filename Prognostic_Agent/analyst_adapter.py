"""Explicit translation of serialized backend Analyst incidents. No backend imports.

Consumes Analyst behavioral_score and technique_evidence when present. Legacy
incidents retain unknown scores/coarse attribution. This module does not
re-triage, correlate, or fetch related events missing from the payload.
"""

from copy import deepcopy

from .contracts import content_hash, parse_time, utc_text


def adapt_analyst_incident(incident, *, behavioral_score=None, technique_evidence=None, guard_context=None):
    if not isinstance(incident, dict):
        raise ValueError("Analyst incident must be a serialized JSON object")
    incident = deepcopy(incident)
    analysis = incident.get("risk_analysis") or {}
    if not isinstance(analysis, dict) or not isinstance(incident.get("events", []), list):
        raise ValueError("Analyst risk_analysis must be an object and events must be an array")
    issues = []
    entities, events = {}, []

    def entity(value, kind):
        if not isinstance(value, str) or not value.strip():
            return None
        raw = value.strip()
        prefix = kind + ":"
        normalized = raw.casefold()
        identity = normalized if normalized.startswith(prefix) else prefix + normalized
        entities.setdefault(identity, {"entity_id": identity, "entity_type": kind, "source_identifier": raw})
        return identity

    for event in incident.get("events", []):
        if not isinstance(event, dict):
            raise ValueError("Analyst events must be objects")
        for field in ("event_id", "event_type", "timestamp"):
            if event.get(field) is None:
                issues.append({"code": "analyst_event_field_missing", "field": field})
        metadata = event.get("metadata") or {}
        refs = [value for value in (entity(event.get("user"), "user"), entity(event.get("host"), "host"),
                                    entity(metadata.get("service_name"), "service")) if value]
        events.append({**event, "entity_ids": sorted(set(refs))})
    primary = incident.get("events", [{}])[0] if incident.get("events") else {}
    user_id = entity(primary.get("user"), "user")
    host_id = entity(primary.get("host"), "host")
    for key, value in (("user_id", user_id), ("host_id", host_id)):
        if value is None:
            issues.append({"code": "analyst_entity_missing", "field": key})
    if not events:
        issues.append({"code": "analyst_events_missing"})
    triaged_at = analysis.get("triaged_at")
    try:
        triaged_at = utc_text(parse_time(triaged_at))
        analysis["triaged_at"] = triaged_at
        revision = "triage:" + triaged_at + ":" + content_hash(analysis)[:16]
    except (TypeError, ValueError, AttributeError):
        revision = None
        issues.append({"code": "analyst_triaged_at_missing_or_invalid"})
    # A stale marker is authoritative even if a numeric upstream value or an
    # explicit override is still present. Malformed markers fail closed too.
    stale_behavior = analysis.get("behavioral_score_stale", False) is not False
    score = None if stale_behavior else (behavioral_score if behavioral_score is not None else analysis.get("behavioral_score"))
    score_source = "explicit_argument" if behavioral_score is not None else ("analyst.behavioral_score" if score is not None else "unavailable")
    if stale_behavior:
        score_source = "stale_after_review"
        issues.append({"code": "behavioral_score_stale", "detail": "Review invalidated the behavioral assessment; no score or override was reused."})
    if score is None:
        issues.append({"code": "behavioral_score_missing", "detail": "Analyst total risk_score may include asset impact; it was not reused or adjusted by text matching."})
    mapping = technique_evidence if technique_evidence is not None else analysis.get("technique_evidence", {})
    mapping_source = "explicit_argument" if technique_evidence is not None else (
        "analyst.technique_evidence" if "technique_evidence" in analysis else "unavailable")
    known_events = {event.get("event_id") for event in events}
    techniques = []
    for technique in analysis.get("mitre_techniques", []):
        refs = mapping.get(technique, []) if isinstance(mapping, dict) else []
        valid = isinstance(refs, list) and bool(refs) and all(isinstance(ref, str) and ref in known_events for ref in refs)
        if not valid:
            issue = {"code": "coarse_technique_attribution", "technique_id": technique,
                     "detail": "Analyst technique has no attribution fully supported by supplied events."}
            if isinstance(refs, list):
                missing = sorted({ref for ref in refs if isinstance(ref, str) and ref not in known_events})
                if missing:
                    issue["unavailable_event_refs"] = missing
            issues.append(issue)
        techniques.append({"technique_id": technique, "attribution": "exact" if valid else "coarse",
                           "evidence_refs": sorted(set(refs)) if valid else []})
    correlated = []
    for item in analysis.get("correlations", []):
        if item.get("incident_id"):
            correlated.append(item["incident_id"])
        else:
            issues.append({"code": "correlated_alert_id_missing", "group_key_hash": content_hash(item.get("group_key"))})
    if analysis.get("correlations"):
        issues.append({"code": "related_evidence_not_supplied", "detail": "Correlation summaries do not establish the full entity/evidence list. No related incidents were fetched."})
    if not analysis.get("confidence"):
        issues.append({"code": "analyst_confidence_missing_or_zero"})
    findings = analysis.get("findings", [])
    for name, value in (("incident_id", incident.get("incident_id")), ("anomaly_score", incident.get("anomaly_score")),
                        ("risk_analysis.verdict", analysis.get("verdict")), ("risk_analysis.confidence", analysis.get("confidence"))):
        if value is None:
            issues.append({"code": "analyst_field_missing", "field": name})
    request = {
        "schema_version": 1, "request_id": incident.get("request_id"),
        "alert_id": incident.get("incident_id"), "analyst_revision": revision,
        "timestamp": triaged_at, "anomaly_score": incident.get("anomaly_score"),
        "triage_score": score, "analyst_confidence": analysis.get("confidence"), "verdict": analysis.get("verdict"),
        "behavioral_score_source": "supplied" if score is not None else "unknown",
        "user_id": user_id, "host_id": host_id, "source_ip": primary.get("source_ip"),
        "entities": sorted(entities.values(), key=lambda item: item["entity_id"]),
        "normalized_events": events, "observed_techniques": techniques,
        "correlated_alert_ids": sorted(set(correlated)),
        "findings": [item.get("text", "") if isinstance(item, dict) else str(item) for item in findings],
        "analyst_finding_contributions": findings,
        "adapter_issues": issues,
        "adapter_metadata": {"version": "1", "behavioral_score_source": "supplied" if score is not None else "unknown", "behavioral_score_provenance": score_source,
                             "behavioral_score_stale": stale_behavior,
                             "technique_evidence_provenance": mapping_source,
                             "upstream_total_risk_score": analysis.get("risk_score"),
                             "upstream_total_risk_score_may_include_asset_impact": True,
                             "entity_normalization": "Windows user/host identifiers casefolded and type-prefixed; no alias discovery",
                             "revision_method": "normalized triaged_at plus hash of full Analyst assessment"},
    }
    supplied_guards = guard_context if guard_context is not None else analysis.get("guard_context")
    if supplied_guards is not None:
        request["guard_context"] = deepcopy(supplied_guards)
        request["adapter_metadata"]["guard_context_provenance"] = "explicit_argument" if guard_context is not None else "analyst.guard_context"
    return request

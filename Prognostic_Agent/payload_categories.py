"""Shadow eligibility categories; no legacy score/attribution reconstruction."""

LEGACY = "legacy_payload_unsupported"
ADDITIVE_FIELDS = ("behavioral_score", "technique_evidence")


def missing_analyst_fields(incident):
    if not isinstance(incident, dict):
        return []  # Malformed source JSON remains a genuine validation failure.
    analysis = incident.get("risk_analysis", {})
    if analysis is None:
        analysis = {}
    if not isinstance(analysis, dict):
        return []
    return [name for name in ADDITIVE_FIELDS if name not in analysis]


def legacy_envelope(alert_id, missing, metadata, context):
    return {**metadata, "response_type": LEGACY, "reason": LEGACY, "alert_id": alert_id,
            "reason_detail": "Analyst payload lacks the required additive contract; no forecast was attempted.",
            "missing_analyst_fields": list(missing), "predicted_path": None, "risk_score": None,
            "shadow_context": context,
            "issues": [{"code": "analyst_field_missing", "field": name} for name in missing]}

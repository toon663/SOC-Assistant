"""Public standalone workflow: Analyst alert -> structured risk forecast."""

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from time import perf_counter

from .asset_context import enrich_asset_context
from .config import ForecastConfig
from .contracts import AnalystAlert, RequestValidationError, content_hash, parse_time, utc_text, validate_response, validation_error
from .scoring import analyze_risk_impact, blast_radius, load_weights
from .transition_rules import forecast_risk_path, load_rules
from .provenance import provenance, operational_error

REASONS = {
    "assessment_complete": "The deterministic numeric assessment and explanation completed.",
    "asset_context_incomplete": "Supported paths exist, but some asset context is missing, stale, or unavailable.",
    "asset_lookup_timeout": "Supported paths exist using completed lookups; an asset provider timed out.",
    "candidate_coverage_incomplete": "Supported paths exist; some starting techniques or mandatory prerequisites are not covered.",
    "behavioral_score_unavailable": "Paths can be assessed, but an asset-independent behavioral score is unavailable for combined risk scoring.",
    "insufficient_evidence": "No fresh evidence-supported starting technique is available for a non-benign forecast.",
    "stale_evidence": "No supplied event falls within the evidence freshness window at or before forecast_as_of.",
    "unsupported_transition": "Starting techniques have no enabled transition rules.",
    "prerequisites_unresolved": "Every generated transition depends on unresolved mandatory prerequisites.",
    "prerequisites_failed": "No path satisfies its mandatory platform, privilege, and reachability prerequisites.",
    "below_candidate_threshold": "All candidate paths fall below the configured heuristic acceptance threshold.",
}

DETERMINISTIC_CAVEATS = (
    "Forecast paths are conditional hypotheses, not observed compromise.",
    "Likelihood indices are heuristic rankings, not probabilities or severity measures.",
    "Host protections may prevent any forecast step.",
)


def _explain(paths, reason):
    caveats = "\n".join(DETERMINISTIC_CAVEATS)
    if reason:
        return {"summary": REASONS[reason] + "\n" + caveats, "candidate_explanations": []}
    return {
        "summary": caveats,
        "candidate_explanations": [
            {"candidate_id": path["candidate_id"], "evidence_refs": path["evidence_refs"],
             "text": " Starting from " + path["starting_technique"] + ": " + " ".join(step["rationale"] for step in path["steps"]) + "\n" + caveats,
             "assumptions": sorted({item for step in path["steps"] for item in step["assumptions"]})}
            for path in paths
        ],
    }


def _build_risk_forecast(payload, *, asset_provider=None, asset_providers=None,
                        config=None, forecast_as_of=None):
    """Return a risk_forecast or validation_error envelope; no persistence/actions.

    For historical replay pass an explicit forecast_as_of. The default is current
    UTC, never the alert timestamp (which could make stale evidence look fresh).
    Providers execute in spawn processes; use a __main__ guard in executable
    Python callers, as with Python's multiprocessing convention on Windows.
    """
    try:
        validated = AnalystAlert.from_dict(payload)
    except RequestValidationError as exc:
        return validate_response(validation_error(payload, exc.errors))
    config = config or ForecastConfig()
    if asset_provider is not None and asset_providers is not None:
        raise ValueError("Supply asset_provider or asset_providers, not both")
    providers = list(asset_providers or ([asset_provider] if asset_provider is not None else []))
    as_of = forecast_as_of or datetime.now(timezone.utc)
    if isinstance(as_of, str):
        as_of = parse_time(as_of)
    if as_of.tzinfo is None or as_of.utcoffset() is None:
        raise ValueError("forecast_as_of must be timezone-aware")
    as_of = as_of.astimezone(timezone.utc)
    alert = validated.data
    rules, weights = load_rules(config.rules_path), load_weights(config.weights_path)
    timings = {}
    start = perf_counter()
    context = enrich_asset_context(alert, providers, config, as_of)
    timings["asset_enrichment_ms"] = round((perf_counter() - start) * 1000, 3)
    start = perf_counter()
    impact = analyze_risk_impact(alert, context, weights)
    timings["impact_ms"] = round((perf_counter() - start) * 1000, 3)
    start = perf_counter()
    result = forecast_risk_path(alert, context, impact, config, as_of, rules, weights)
    timings["candidate_generation_scoring_ms"] = round((perf_counter() - start) * 1000, 3)
    paths = result["candidate_paths"]
    reason = result["abstain_reason"]
    issues = list(context["issues"]) + list(alert.get("adapter_issues", []))
    if alert["triage_score"] is None and not any(item["code"] == "behavioral_score_missing" for item in issues):
        issues.append({"code": "behavioral_score_missing", "detail": "No combined risk score was manufactured from incomplete inputs."})
    if any(technique.get("attribution") == "coarse" for technique in alert["observed_techniques"]):
        issues.append({"code": "coarse_technique_attribution", "detail": "Incident-level technique assertions have no invented event attribution."})
    all_evidence_fresh = result["usable_event_count"] == len(alert["normalized_events"])
    if not all_evidence_fresh:
        issues.append({"code": "evidence_excluded", "detail": "Future or stale evidence was excluded from transition generation."})
    unresolved = any(any("unresolved" in failure for failure in rejection["reasons"]) for rejection in result["rejected_transitions"])
    uncertain_factors = any(path["factor_coverage"] < 1 for path in paths)
    incomplete = bool(issues or result["unsupported_starting_techniques"] or unresolved or uncertain_factors or impact["risk_score"] is None)
    if reason:
        status = "abstained"
    elif incomplete:
        status = "partial"
        reason = "asset_lookup_timeout" if any(issue["code"] == "asset_lookup_timeout" for issue in issues) else ("behavioral_score_unavailable" if alert["triage_score"] is None else ("asset_context_incomplete" if context["issues"] or impact["risk_score"] is None else "candidate_coverage_incomplete"))
    else:
        status, reason = "complete", "assessment_complete"
    numeric_status = "unavailable" if not paths and impact["risk_score"] is None else ("complete" if status == "complete" else "partial")
    radius = blast_radius(alert, context, result["all_eligible_paths"], config.max_related_assets)
    # Confidence is deterministic evidence/context coverage, never likelihood.
    confidence_value = round(alert["analyst_confidence"] * context["fresh_field_coverage"] *
                             min((path["factor_coverage"] for path in paths), default=0.0), 6)
    config_values = {key: str(value) if key.endswith("_path") else value for key, value in asdict(config).items()}
    evidence = [{"event_id": event["event_id"], "sha256": content_hash(event), "timestamp": event["timestamp"]} for event in alert["normalized_events"]]
    return validate_response({
        "schema_version": 1, "response_type": "risk_forecast", "agent": "prognostic_agent",
        "request_id": alert["request_id"], "alert_id": alert["alert_id"],
        "analyst_revision": alert["analyst_revision"], "input_fingerprint": validated.input_fingerprint,
        "analyst_confidence": alert["analyst_confidence"],
        "generated_at": utc_text(datetime.now(timezone.utc)), "forecast_as_of": utc_text(as_of),
        "status": status, "reason": reason, "reason_detail": REASONS[reason],
        "numeric_assessment_status": numeric_status, "explanation_status": "deterministic",
        "risk_score": impact["risk_score"], "impact_assessment": impact,
        "behavioral_score_source": alert["behavioral_score_source"],
        "risk_score_may_include_asset_impact": impact["risk_score"] is not None,
        "risk_score_basis": "impact_assessment_only" if status == "abstained" else "contextual_risk_assessment",
        "predicted_path": paths[0] if paths else None, "candidate_paths": paths,
        "likelihood": {"method": "weighted_heuristic_min_edge", "index": paths[0]["likelihood_index"],
                       "uncertainty_range": paths[0]["uncertainty_range"], "probability": None} if paths else None,
        "time_horizon": {"hours": config.forecast_horizon_hours, "start": utc_text(as_of),
                         "end": utc_text(as_of + timedelta(hours=config.forecast_horizon_hours)), "method": "configured_window_not_time_to_attack"},
        "confidence": {"value": confidence_value, "method": "analyst_confidence_times_fresh_asset_field_coverage_times_factor_coverage", "calibrated": False},
        "blast_radius": radius, "asset_context": context, "evidence_references": evidence,
        "correlated_alert_ids": alert["correlated_alert_ids"], "issues": issues,
        "explanation": _explain(paths, result["abstain_reason"]),
        "unsupported_starting_techniques": result["unsupported_starting_techniques"],
        "diagnostics": {"stage_timings_ms": timings, "generated_candidates": result["generated_count"], "eligible_candidates": result["eligible_count"],
                        "rejected_transitions": result["rejected_transitions"], "usable_events": result["usable_event_count"]},
        "versions": {"rules": rules["version"], "rules_hash": rules["content_hash"],
                     "weights": weights["version"], "weights_hash": weights["content_hash"], "config_hash": content_hash(config_values)},
        "limitations": ["Uncalibrated transition hypotheses; no attack arrival-time prediction.",
                        "Asset relationships bound potential scope, not actual compromise.",
                        "Local rule coverage is intentionally small; ATT&CK tactics are not treated as ordered stages.",
                        "Input triage_score must exclude asset-criticality bonuses to avoid double counting."],
    })


def build_risk_forecast(payload, *, asset_provider=None, asset_providers=None, config=None, forecast_as_of=None,
                        explanation_config=None, explanation_provider=None):
    """Every response, including errors, carries explicit version provenance."""
    started = perf_counter()
    config = config or ForecastConfig()
    metadata = provenance(config)
    try:
        response = _build_risk_forecast(payload, asset_provider=asset_provider, asset_providers=asset_providers,
                                        config=config, forecast_as_of=forecast_as_of)
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as exc:
        response = operational_error("configuration_or_runtime_error", str(exc), metadata=metadata)
    # Only an actual forecast has authoritative, inference-loaded artifact hashes.
    # Early validation envelopes must not overwrite caller-selected provenance
    # with the default artifacts used by the generic error-envelope helper.
    versions = {**metadata["versions"], **(response.get("versions", {}) if response["response_type"] == "risk_forecast" else {})}
    source, may_include = response.get("behavioral_score_source", "unknown"), response.get("risk_score_may_include_asset_impact")
    response.update({**metadata, "versions": versions, "behavioral_score_source": source, "risk_score_may_include_asset_impact": may_include})
    response.setdefault("diagnostics", {})["total_ms"] = round((perf_counter() - started) * 1000, 3)
    # The optional layer runs AFTER final assessment/provenance/timings. It has
    # no references to mutable engine state and cannot re-run scoring.
    if explanation_config is not None and explanation_config.enabled:
        from .llm_explanation import explain_forecast
        response = explain_forecast(response, payload, config=explanation_config, provider=explanation_provider)
    return response

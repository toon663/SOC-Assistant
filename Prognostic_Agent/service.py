"""History/shadow boundary around the pure forecast engine, with optional summary writer."""

from datetime import datetime
import sqlite3
from time import perf_counter
from typing import Protocol

from .config import ForecastConfig
from .contracts import AnalystAlert, RequestValidationError, content_hash, parse_time, utc_text
from .prognostic_agent import build_risk_forecast
from .provenance import operational_error, provenance


class SummaryWriter(Protocol):
    def __call__(self, summary: dict) -> None: ...


def forecast_summary(response):
    return {key: response.get(key) for key in (
        "alert_id", "analyst_revision", "input_fingerprint", "status", "reason", "risk_score", "risk_score_basis",
        "environment", "behavioral_score_source", "risk_score_may_include_asset_impact",
        "numeric_assessment_status", "explanation_status", "time_horizon", "versions", "history"
    )} | {"predicted_path": [step["technique_id"] for step in (response.get("predicted_path") or {}).get("steps", [])]}


def shadow_metrics(response, payload, *, elapsed_ms, replay=False, legacy=None, llm_enabled=False):
    diagnostics = response.get("diagnostics", {})
    context = response.get("asset_context", {})
    radius = response.get("blast_radius", {})
    issues = response.get("issues", [])
    invalid = [error for error in response.get("errors", []) if error["code"] == "invalid_technique_id"]
    legacy = legacy or {}
    old_score = legacy.get("forecast_score")
    return {
        "schema_version": 1, "agent_version": response["agent_version"], "config_version": response["config_version"],
        "environment": response["environment"], "behavioral_score_source": response.get("behavioral_score_source", "unknown"),
        "risk_score_may_include_asset_impact": response.get("risk_score_may_include_asset_impact"),
        "versions": response["versions"], "request_id": response.get("request_id"), "alert_id": response.get("alert_id"),
        "analyst_verdict": payload.get("verdict") if isinstance(payload, dict) else None,
        "shadow_context": response.get("shadow_context"),
        "analyst_revision": response.get("analyst_revision"), "input_fingerprint": response.get("input_fingerprint"),
        "response_type": response["response_type"], "status": response.get("status"), "reason": response.get("reason"),
        "reason_detail": response.get("reason_detail"),
        "validation_errors": response.get("errors", []), "invalid_technique_count": len(invalid),
        "delivery_issues": response.get("delivery_issues", []),
        "idempotent_replay": replay, "time_horizon": response.get("time_horizon"),
        "numeric_assessment_status": response.get("numeric_assessment_status"), "explanation_status": response.get("explanation_status"),
        "risk_score": response.get("risk_score"), "impact": response.get("impact_assessment"),
        "likelihood": response.get("likelihood"), "confidence": response.get("confidence"),
        "candidate_scores": [{"candidate_id": path["candidate_id"], "index": path["likelihood_index"],
                              "range": path["uncertainty_range"], "path_length": len(path["steps"]),
                              "factor_contributions": [step["factor_contributions"] for step in path["steps"]]} for path in response.get("candidate_paths", [])],
        "generated_candidates": diagnostics.get("generated_candidates", 0), "eligible_candidates": diagnostics.get("eligible_candidates", 0),
        "rejected_transitions": diagnostics.get("rejected_transitions", []),
        "unsupported_starting_techniques": response.get("unsupported_starting_techniques", []),
        "asset_coverage": context.get("coverage"), "fresh_asset_field_coverage": context.get("fresh_field_coverage"),
        "missing_asset_fields": context.get("missing_fields", []), "issues": issues,
        "blast_radius": {key: value for key, value in radius.items() if key.endswith("count") or key.endswith("by_type") or key in {"inventory_coverage", "truncated", "unknown_relationship_entities"}},
        "stage_timings_ms": {} if replay else diagnostics.get("stage_timings_ms", {}), "total_ms": round(elapsed_ms, 3),
        "asset_timeouts": 0 if replay else sum(issue["code"] == "asset_lookup_timeout" for issue in issues),
        "asset_errors": 0 if replay else sum(issue["code"] in {"asset_provider_error", "asset_record_invalid"} for issue in issues),
        "asset_provider_stats": [] if replay else context.get("provider_stats", []),
        "asset_fallback_replacements": 0 if replay else context.get("fallback_replacements", 0),
        "llm_enabled": llm_enabled, "llm_tokens": None if llm_enabled else 0, "llm_cost": None if llm_enabled else 0,
        "llm_timeouts": sum(i["code"] == "llm_timeout" for i in issues),
        "llm_validation_failures": sum(i["code"] == "llm_output_rejected" for i in issues),
        "stale_result_rejected": False,
        "legacy": legacy or None,
        "legacy_score_delta": response.get("risk_score") - old_score if isinstance(old_score, (int, float)) and response.get("risk_score") is not None else None,
        "legacy_path_changed": ([step["technique_id"] for step in (response.get("predicted_path") or {}).get("steps", [])] != legacy["attack_path"]) if isinstance(legacy.get("attack_path"), list) else None,
        "proposed_bi_difference": legacy.get("proposed_bi_difference"), "proposed_playbook_difference": legacy.get("proposed_playbook_difference"),
        "observation_window_end": response.get("time_horizon", {}).get("end"),
        "outcome_status": "pending_observation", "observation_coverage": None,
        "subsequent_observed_techniques": None, "interventions": None,
        "candidate_recall": None, "top_k_recall": None, "precision": None, "brier_score": None,
    }


class ForecastService:
    def __init__(self, history, *, config=None, summary_writer: SummaryWriter | None = None,
                 explanation_config=None, explanation_provider=None):
        self.history = history
        self.config = config or ForecastConfig(store_full_evidence=history.store_full_evidence,
                                               environment=history.environment,
                                               history_retention_days=history.retention_days,
                                               sqlite_busy_timeout_ms=history.busy_timeout_ms)
        if (self.config.environment != history.environment or self.config.store_full_evidence != history.store_full_evidence or
            self.config.history_retention_days != history.retention_days or
            self.config.sqlite_busy_timeout_ms != history.busy_timeout_ms):
            raise ValueError("History settings and ForecastConfig must agree")
        self.summary_writer = summary_writer
        self.explanation_config = explanation_config
        self.explanation_provider = explanation_provider

    def assess(self, payload, *, asset_provider=None, asset_providers=None, forecast_as_of=None, evaluation_id=None, legacy=None,
               shadow_context=None):
        start = perf_counter()
        normalized = None
        metadata = provenance(self.config)
        response = None
        try:
            normalized = AnalystAlert.from_dict(payload)
        except RequestValidationError:
            pass
        try:
            self.history.purge()
            if isinstance(forecast_as_of, datetime) and (forecast_as_of.tzinfo is None or forecast_as_of.utcoffset() is None):
                raise ValueError("forecast_as_of must be timezone-aware")
            cutoff = utc_text(parse_time(forecast_as_of)) if isinstance(forecast_as_of, str) else (utc_text(forecast_as_of) if forecast_as_of else None)
            if evaluation_id is not None and (not isinstance(evaluation_id, str) or not evaluation_id.strip()):
                raise ValueError("evaluation_id must be a nonempty string")
            key = content_hash({"input": normalized.input_fingerprint, "versions": metadata["versions"],
                                "cutoff": cutoff, "evaluation_id": evaluation_id}) if normalized else None
            if key and self.explanation_config is not None and self.explanation_config.enabled:
                key = content_hash({"numeric_key": key, "explanation_profile": {
                    "version": 2, "model": self.explanation_config.model,
                    "provider": type(self.explanation_provider).__qualname__ if self.explanation_provider is not None else "anthropic"}})
            if key:
                response = self.history.find(key)
            replay = response is not None
            if response is None:
                response = build_risk_forecast(payload, config=self.config, asset_provider=asset_provider,
                                               asset_providers=asset_providers, forecast_as_of=forecast_as_of,
                                               explanation_config=self.explanation_config,
                                               explanation_provider=self.explanation_provider)
                if shadow_context is not None:
                    response["shadow_context"] = shadow_context
                    for field in ("source", "original_triage_id"):
                        if field in shadow_context:
                            response[field] = shadow_context[field]
                if response["response_type"] == "risk_forecast":
                    response, replay = self.history.save(response, normalized.data, key)
            if isinstance(payload, dict):
                response["request_id"] = payload.get("request_id")
            if response.get("history"):
                response["history"]["idempotent_replay"] = replay
                if self.summary_writer:
                    try:
                        self.summary_writer(forecast_summary(response))
                    except Exception as exc:
                        response.setdefault("delivery_issues", []).append({"code": "summary_writer_error", "detail": type(exc).__name__})
            self.history.record_attempt(shadow_metrics(response, payload, elapsed_ms=(perf_counter() - start) * 1000, replay=replay, legacy=legacy,
                                                       llm_enabled=self.explanation_config is not None and self.explanation_config.enabled),
                                        response.get("history", {}).get("forecast_id"))
        except (sqlite3.Error, OSError, ValueError, TypeError) as exc:
            error = operational_error("history_or_assessment_error", str(exc), metadata=metadata)
            if shadow_context is not None:
                error["shadow_context"] = shadow_context
                for field in ("source", "original_triage_id"):
                    if field in shadow_context:
                        error[field] = shadow_context[field]
            if response is not None:
                error["computed_result"] = response
                error["persisted"] = bool(response.get("history", {}).get("persisted"))
            try:
                self.history.record_attempt(shadow_metrics(error, payload, elapsed_ms=(perf_counter() - start) * 1000))
            except (sqlite3.Error, OSError, ValueError, TypeError):
                error["provenance_issues"].append({"code": "attempt_log_unavailable"})
            return error
        return response

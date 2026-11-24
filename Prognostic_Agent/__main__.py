"""python -m Prognostic_Agent --input alert.json --asset-inventory assets.json"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import sqlite3
import uuid

from .asset_context import LocalJSONAssetProvider
from .config import ForecastConfig
from .contracts import parse_time, validation_error
from .prognostic_agent import build_risk_forecast
from .analyst_adapter import adapt_analyst_incident
from .provenance import provenance, operational_error
from .storage import ForecastHistory, DEFAULT_HISTORY_PATH
from .service import ForecastService, shadow_metrics
from .reporting import export_unsupported, shadow_summary
from .batch_replay import replay_batch, DEFAULT_SOURCE_PATH


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def main(argv=None):
    parser = Parser(description="Forecast Analyst alerts and manage agent-owned forecast history.")
    parser.add_argument("command", nargs="?", default="forecast", choices=("forecast", "purge", "history", "unsupported-report", "shadow-report", "batch-replay"))
    parser.add_argument("--backend-db", type=Path, default=DEFAULT_SOURCE_PATH, help="Existing checkpointed backend snapshot; batch reads immutable/read-only")
    parser.add_argument("--limit", type=int, default=20, help="Maximum persisted incidents to replay; suspicious first")
    parser.add_argument("--input", default="-", help="Analyst alert JSON file, or - for stdin")
    parser.add_argument("--asset-inventory", type=Path)
    parser.add_argument("--analyst-incident", action="store_true")
    parser.add_argument("--behavioral-score", type=float, help="Explicit asset-independent score for the Analyst adapter")
    parser.add_argument("--rules-path", type=Path, default=ForecastConfig.rules_path)
    parser.add_argument("--weights-path", type=Path, default=ForecastConfig.weights_path)
    parser.add_argument("--history-db", type=Path, default=DEFAULT_HISTORY_PATH)
    parser.add_argument("--environment", choices=("test", "demo", "production"), default="demo", help="Tag stored assessments; default demo")
    parser.add_argument("--report-environment", choices=("test", "demo", "production", "all"), help="Report/history/export filter; defaults to --environment")
    parser.add_argument("--no-history", action="store_true", help="Compute only; no database creation or writes")
    parser.add_argument("--evaluation-id", help="New identity to reassess unchanged input against new context")
    parser.add_argument("--retention-days", type=int, default=90)
    parser.add_argument("--busy-timeout-ms", type=int, default=5000)
    parser.add_argument("--store-full-evidence", action="store_true")
    parser.add_argument("--alert-id", help="Alert identity for the history command")
    parser.add_argument("--report-output", type=Path, help="New file for unsupported-technique export")
    parser.add_argument("--format", choices=("json", "csv"), default="json")
    parser.add_argument("--output-dir", type=Path, help="Optionally write a unique JSON document; stdout always contains JSON")
    parser.add_argument("--as-of", help="Explicit UTC cutoff for historical replay")
    parser.add_argument("--evidence-freshness-hours", type=float, default=24)
    parser.add_argument("--forecast-horizon-hours", type=float, default=24)
    parser.add_argument("--asset-timeout-seconds", type=float, default=2)
    parser.add_argument("--enrichment-timeout-seconds", type=float, default=5)
    parser.add_argument("--min-candidate-score", type=float, default=0.5)
    llm = parser.add_mutually_exclusive_group()
    llm.add_argument("--no-llm", action="store_true", help="Deterministic only (the default); no SDK or credentials required")
    llm.add_argument("--llm-explanation", action="store_true", help="Opt in to bounded, pseudonymized Anthropic explanation selection")
    parser.add_argument("--llm-model", default="claude-haiku-5-5")
    config, metadata, args = None, None, None
    try:
        args = parser.parse_args(argv)
        config = ForecastConfig(
            evidence_freshness_limit_hours=args.evidence_freshness_hours,
            forecast_horizon_hours=args.forecast_horizon_hours,
            asset_provider_timeout_seconds=args.asset_timeout_seconds,
            enrichment_timeout_seconds=args.enrichment_timeout_seconds,
            min_candidate_score=args.min_candidate_score,
            environment=args.environment,
            rules_path=args.rules_path, weights_path=args.weights_path,
            history_retention_days=args.retention_days, sqlite_busy_timeout_ms=args.busy_timeout_ms,
            store_full_evidence=args.store_full_evidence,
        )
        metadata = provenance(config)
        explanation_config = None
        if args.llm_explanation:
            if args.command != "forecast":
                raise ValueError("--llm-explanation is supported only for forecast, not report/batch commands")
            from .llm_explanation import ExplanationConfig
            explanation_config = ExplanationConfig(enabled=True, model=args.llm_model)
        if args.command == "batch-replay":
            if args.no_history or args.behavioral_score is not None or args.report_environment is not None:
                raise ValueError("batch-replay requires history and does not accept a global behavioral-score override or report filter")
            result = replay_batch(args.backend_db, limit=args.limit, history_path=args.history_db, config=config,
                                  forecast_as_of=args.as_of, evaluation_id=args.evaluation_id, output_dir=args.output_dir,
                                  asset_provider=LocalJSONAssetProvider(args.asset_inventory) if args.asset_inventory else None)
            print(json.dumps(result, indent=2, allow_nan=False))
            return 1 if result["status_counts"].get("operational_error") else 0
        if args.command != "forecast":
            if args.command == "purge" and args.report_environment is not None:
                raise ValueError("purge is scoped by --environment; --report-environment is for reads/exports only")
            if args.no_history:
                raise ValueError("History commands cannot use --no-history")
            with ForecastHistory(args.history_db, busy_timeout_ms=args.busy_timeout_ms, retention_days=args.retention_days, environment=args.environment) as history:
                if args.command == "purge":
                    output = {"response_type": "purge_result", **history.purge()}
                elif args.command == "history":
                    if not args.alert_id:
                        raise ValueError("history requires --alert-id")
                    output = {"response_type": "history_result", "items": history.history(args.alert_id, environment=args.report_environment), "environment_filter": args.report_environment or args.environment}
                elif args.command == "shadow-report":
                    output = {"response_type": "shadow_report", **shadow_summary(history, environment=args.report_environment)}
                else:
                    report = export_unsupported(history, args.report_output, format=args.format, metadata=metadata, environment=args.report_environment) if args.report_output else history.unsupported_report(metadata=metadata, environment=args.report_environment)
                    output = {"response_type": "unsupported_report", **report}
                print(json.dumps({**output, **metadata}, indent=2, allow_nan=False))
                return 0
        try:
            if args.input == "-":
                payload = json.load(sys.stdin)
            else:
                with open(args.input, encoding="utf-8-sig") as stream:
                    payload = json.load(stream)
        except (ValueError, OSError) as exc:
            output = validation_error({}, [{"field": "$", "code": "input_unreadable" if isinstance(exc, OSError) else "invalid_json", "message": str(exc)}], metadata=metadata)
            if not args.no_history:
                with ForecastHistory(args.history_db, busy_timeout_ms=args.busy_timeout_ms, retention_days=args.retention_days, environment=args.environment) as history:
                    history.record_attempt(shadow_metrics(output, {}, elapsed_ms=0))
            print(json.dumps(output, indent=2))
            return 2
        if args.analyst_incident:
            payload = adapt_analyst_incident(payload, behavioral_score=args.behavioral_score)
        as_of = parse_time(args.as_of) if args.as_of else None
        provider = LocalJSONAssetProvider(args.asset_inventory) if args.asset_inventory else None
        if args.no_history:
            output = build_risk_forecast(payload, config=config, asset_provider=provider, forecast_as_of=as_of,
                                         explanation_config=explanation_config)
        else:
            with ForecastHistory(args.history_db, busy_timeout_ms=args.busy_timeout_ms, retention_days=args.retention_days, store_full_evidence=args.store_full_evidence, environment=args.environment) as history:
                output = ForecastService(history, config=config, explanation_config=explanation_config).assess(payload, asset_provider=provider, forecast_as_of=as_of, evaluation_id=args.evaluation_id)
        encoded = json.dumps(output, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        if args.output_dir:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            path = args.output_dir / f"forecast_{stamp}_{uuid.uuid4().hex}.json"
            with path.open("x", encoding="utf-8") as stream:
                stream.write(encoded)
            print(f"Saved {path}", file=sys.stderr)
        print(encoded, end="")
        return {"validation_error": 2, "operational_error": 1}.get(output["response_type"], 0)
    except (ValueError, OSError, KeyError, TypeError, AttributeError, RuntimeError, sqlite3.Error) as exc:
        output = operational_error("configuration_or_runtime_error", str(exc), config=config, metadata=metadata)
        if config is None:
            output["versions"]["config_hash"] = None
            output["provenance_issues"].append({"code": "configuration_not_constructed"})
            if args is not None:
                output["environment"] = args.environment
        if args is not None and args.command == "forecast" and not args.no_history:
            try:
                with ForecastHistory(args.history_db, environment=args.environment) as history:
                    history.record_attempt(shadow_metrics(output, {}, elapsed_ms=0))
            except (ValueError, OSError, sqlite3.Error):
                output["provenance_issues"].append({"code": "attempt_log_unavailable"})
        print(json.dumps(output, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

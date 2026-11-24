"""Six synthetic forecast audits and side-by-side explanations, fake provider only."""
import argparse
import json
import os
from pathlib import Path
import uuid

from .config import ForecastConfig
from .contracts import canonical_json
from .llm_explanation import ExplanationConfig, Pseudonymizer, audit_logged_payloads, explain_forecast, prepare
from .private_paths import PRIVATE_DIR, private_path, write_private
from .prognostic_agent import build_risk_forecast
from .synthetic_contrasts import FixtureInventoryProvider, prepare_variant
from .tests.fake_explanation_provider import FakeExplanationProvider


def _replace(value, old, new):
    if isinstance(value, str):
        return value.replace(old, new)
    if isinstance(value, list):
        return [_replace(v, old, new) for v in value]
    if isinstance(value, dict):
        return {_replace(k, old, new): _replace(v, old, new) for k, v in value.items()}
    return value


def _has_alias_map(value):
    if isinstance(value, dict):
        return any(k in {"alias_map", "forward", "reverse"} or _has_alias_map(v) for k, v in value.items())
    return isinstance(value, list) and any(_has_alias_map(v) for v in value)


def case_input(name):
    variant = {"abstained": "expired_evidence_25h", "stale_asset_partial": "stale_asset_record"}.get(name, "baseline")
    request, inventory, settings = prepare_variant(variant)
    if name == "partial":
        inventory["entities"][0]["asset_owner"] = None
    elif name == "domain_username":
        request = _replace(request, "user:fixture-admin", "user:LAB\\fixture-admin")
        inventory = _replace(inventory, "user:fixture-admin", "user:LAB\\fixture-admin")
    elif name == "embedded_hostname":
        request = _replace(request, "host:fixture-workstation", "host:prefix-LAB-NODE-suffix")
        inventory = _replace(inventory, "host:fixture-workstation", "host:prefix-LAB-NODE-suffix")
        request["normalized_events"][0].setdefault("metadata", {})["hostname"] = "LAB-NODE"
    return request, inventory, settings


def run_review(directory):
    directory = private_path(directory)
    if directory.exists():
        raise ValueError("Use a new private review directory")
    rows, comparisons = [], {}
    for name in ("complete", "partial", "abstained", "domain_username", "embedded_hostname", "stale_asset_partial"):
        request, inventory, settings = case_input(name)
        baseline = build_risk_forecast(request, config=ForecastConfig(environment="test", max_candidates=5),
                                      asset_provider=FixtureInventoryProvider({r["entity_id"]:r for r in inventory["entities"]}),
                                      forecast_as_of=settings["forecast_as_of"])
        if baseline["response_type"] != "risk_forecast":
            raise AssertionError("Synthetic forecast fixture failed")
        payloads = directory / name / "payloads"
        result = explain_forecast(baseline, request, config=ExplanationConfig(enabled=True, audit_directory=payloads),
                                  provider=FakeExplanationProvider())
        expected_status = "abstained" if name == "abstained" else ("partial" if name in {"partial", "stale_asset_partial"} else "complete")
        if baseline["status"] != expected_status:
            raise AssertionError("Unexpected synthetic assessment status")
        forbidden = [e.get("message", "") for e in request["normalized_events"]]
        if baseline["candidate_paths"]:
            _, _, aliases = prepare(baseline, request)
            forbidden += list(aliases.forward)
        audit = audit_logged_payloads(payloads, forbidden_strings=forbidden)
        expected_logs = 0 if name == "abstained" else 1
        if not audit["clean"] or audit["payloads_checked"] != expected_logs:
            raise AssertionError("Synthetic payload audit failed")
        changed = {k for k in baseline if baseline[k] != result[k]}
        if changed - {"explanation", "explanation_status"}:
            raise AssertionError("Unexpected assessment mutation")
        row = {"case": name, "status": result["status"], "reason": result["reason"],
               "explanation_status": result["explanation_status"], "payloads_logged": audit["payloads_checked"],
               "privacy_clean": audit["clean"],
               "alias_map_persisted": any(_has_alias_map(json.loads(p.read_text())) for p in payloads.glob("*.json")),
               "numeric_assessment_unchanged": baseline["numeric_assessment_status"] == result["numeric_assessment_status"],
               "disposition": "no_candidates_no_call_no_payload" if expected_logs == 0 else "fake_provider_only"}
        if name == "embedded_hostname":
            aliases = Pseudonymizer([("host", "LAB-NODE")])
            probe = "prefix-LAB-NODE-suffix"
            redacted = aliases.redact(probe)
            row["embedded_redaction"] = redacted
            row["round_trip_passed"] = aliases.restore(redacted) == probe
        rows.append(row)
        write_private(directory / name / "deterministic.json", baseline)
        write_private(directory / name / "selected.json", result)
        write_private(directory / name / "payload_audit.json", audit)
        comparisons[name] = {"deterministic": baseline["explanation"], "llm_selected": result["explanation"]}
    comparison = comparisons["complete"]
    summary = {"environment": "test", "model": ExplanationConfig().model, "external_calls": 0,
               "forecasts_audited": len(rows), "payloads_audited": sum(r["payloads_logged"] for r in rows),
               "all_clean": all(r["privacy_clean"] for r in rows), "cases": rows,
               "side_by_side": {"deterministic": comparison["deterministic"]["candidate_explanations"][0]["text"],
                                "llm_selected": comparison["llm_selected"]["candidate_explanations"][0]["text"]},
               "artifact_directory": directory.relative_to(PRIVATE_DIR.parent.parent).as_posix()}
    write_private(directory / "review.json", summary)
    return summary


def credential_probe():
    """Called only by tests with a fake credential sentinel, never a real key."""
    from tempfile import TemporaryDirectory
    if not os.environ.get("ANTHROPIC_API_KEY", "").startswith("offline-test-"):
        raise ValueError("A synthetic offline test credential is required")
    request, inventory, settings = case_input("complete")
    base = build_risk_forecast(request, config=ForecastConfig(environment="test"),
                               asset_provider=FixtureInventoryProvider({r["entity_id"]:r for r in inventory["entities"]}),
                               forecast_as_of=settings["forecast_as_of"])
    with TemporaryDirectory(dir=PRIVATE_DIR, prefix="test-credential-") as work:
        config = ExplanationConfig(enabled=True, audit_directory=Path(work))
        for mode in ("credential_echo", "credential_error", "credential_reply"):
            result = explain_forecast(base, request, config=config, provider=FakeExplanationProvider(mode))
            secret = os.environ.get("ANTHROPIC_API_KEY", "")
            contents = canonical_json(result) + "".join(p.read_text() for p in Path(work).glob("*.json"))
            if secret and secret in contents:
                raise AssertionError("Credential boundary failed")
        if not audit_logged_payloads(work)["clean"]:
            raise AssertionError("Credential journal audit failed")
    print(json.dumps({"fake_credential_probe_passed": True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--credential-probe", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.credential_probe:
        credential_probe()
        return 0
    print(json.dumps(run_review(args.output_dir or (PRIVATE_DIR / "phase3-privacy-review" / uuid.uuid4().hex[:10])), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

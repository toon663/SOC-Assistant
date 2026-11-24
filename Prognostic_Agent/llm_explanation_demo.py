"""Offline fake-provider comparison; no real endpoint events or external calls."""
import argparse
import difflib
import json
from pathlib import Path
import uuid

from .analyst_adapter import adapt_analyst_incident
from .contracts import canonical_json
from .llm_explanation import ExplanationConfig, explain_forecast, prepare, audit_logged_payloads
from .private_paths import PRIVATE_DIR, private_path, write_private
from .synthetic_demo import run_fixture, FIXTURE_DIR
from .tests.fake_explanation_provider import FakeExplanationProvider


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    directory = private_path(args.output_dir or (PRIVATE_DIR / "phase3-review" / uuid.uuid4().hex[:10]))
    if directory.exists():
        parser.error("Choose a new private output directory")
    baseline = run_fixture()
    incident = json.loads((FIXTURE_DIR / "incident.json").read_text())
    settings = json.loads((FIXTURE_DIR / "settings.json").read_text())
    request = adapt_analyst_incident(incident, behavioral_score=settings["behavioral_score"], technique_evidence=settings["technique_evidence"])
    config = ExplanationConfig(enabled=True, audit_directory=directory / "payloads")
    fake = explain_forecast(baseline, request, config=config, provider=FakeExplanationProvider())
    if fake["explanation_status"] != "llm":
        raise RuntimeError("Fake-provider explanation did not validate")
    changed = [key for key in baseline if baseline[key] != fake[key]]
    if set(changed) != {"explanation", "explanation_status"}:
        raise AssertionError("Only explanation fields may differ")
    _, _, aliases = prepare(baseline, request)
    forbidden = list(aliases.forward) + [e.get("message", "") for e in request["normalized_events"]]
    privacy = audit_logged_payloads(directory / "payloads", forbidden_strings=forbidden)
    if not privacy["clean"] or privacy["payloads_checked"] != 1:
        raise AssertionError("Payload privacy audit failed")
    write_private(directory / "disabled.json", baseline)
    write_private(directory / "fake_provider.json", fake)
    write_private(directory / "privacy_audit.json", privacy)
    pretty = lambda value: json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    diff = "".join(difflib.unified_diff(pretty(baseline).splitlines(True), pretty(fake).splitlines(True), fromfile="disabled.json", tofile="fake_provider.json"))
    (directory / "explanation.diff").write_text(diff, encoding="utf-8")
    output = {"environment": "test", "external_calls": 0, "changed_fields": changed,
              "non_explanation_bytes_identical": canonical_json({k:v for k,v in baseline.items() if k not in changed}) == canonical_json({k:v for k,v in fake.items() if k not in changed}),
              "status": baseline["status"], "numeric_assessment_status": baseline["numeric_assessment_status"],
              "risk_score": baseline["risk_score"], "privacy": privacy,
              "artifacts": directory.relative_to(PRIVATE_DIR.parent.parent).as_posix()}
    write_private(directory / "comparison.json", output)
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

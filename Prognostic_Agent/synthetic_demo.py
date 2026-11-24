"""Run a hand-authored fixture through the adapter, existing provider, and engine.

No backend imports, inventory schema changes, history writes, or LLM calls.
Technique attribution is explicit fixture ground truth, never inferred by an LLM.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import uuid

from .analyst_adapter import adapt_analyst_incident
from .asset_context import LocalJSONAssetProvider
from .config import AGENT_DIR, ForecastConfig
from .prognostic_agent import build_risk_forecast

FIXTURE_DIR = AGENT_DIR / "examples" / "synthetic_powershell"


def run_fixture():
    with (FIXTURE_DIR / "incident.json").open(encoding="utf-8") as stream:
        incident = json.load(stream)
    with (FIXTURE_DIR / "settings.json").open(encoding="utf-8") as stream:
        settings = json.load(stream)
    request = adapt_analyst_incident(incident, behavioral_score=settings["behavioral_score"],
                                    technique_evidence=settings["technique_evidence"])
    config = ForecastConfig(environment="test", max_candidates=settings["max_candidates"])
    response = build_risk_forecast(request, config=config, forecast_as_of=settings["forecast_as_of"],
                                   asset_provider=LocalJSONAssetProvider(FIXTURE_DIR / "inventory.json"))
    return response


def main(argv=None):
    parser = argparse.ArgumentParser(description="Synthetic test fixture: valid account -> PowerShell -> credential access.")
    parser.add_argument("--output-dir", type=Path, default=AGENT_DIR / "forecasts" / "synthetic")
    parser.add_argument("--summary", action="store_true", help="Print a summary; the saved JSON always contains the FULL engine response")
    args = parser.parse_args(argv)
    directory = args.output_dir.resolve()
    if not directory.is_relative_to(AGENT_DIR.resolve()):
        parser.error("Fixture outputs must stay inside Prognostic_Agent")
    response = run_fixture()
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = directory / f"powershell_forecast_{stamp}_{uuid.uuid4().hex}.json"
    with destination.open("x", encoding="utf-8") as stream:
        json.dump(response, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")
    print(f"Full engine response: {destination}", file=sys.stderr)
    if args.summary:
        shown = {key: response.get(key) for key in ("environment", "response_type", "status", "reason", "risk_score", "behavioral_score_source", "likelihood", "issues")}
        shown["predicted_path"] = [step["technique_id"] for step in (response.get("predicted_path") or {}).get("steps", [])]
        shown["starting_technique"] = (response.get("predicted_path") or {}).get("starting_technique")
        shown["candidate_rule_sequences"] = [[step["rule_id"] for step in path["steps"]] for path in response.get("candidate_paths", [])]
        shown["full_output_file"] = str(destination)
    else:
        shown = response
    print(json.dumps(shown, indent=2, ensure_ascii=False, allow_nan=False))
    return 0 if response.get("status") in {"complete", "partial"} and response.get("predicted_path") else 1


if __name__ == "__main__":
    raise SystemExit(main())

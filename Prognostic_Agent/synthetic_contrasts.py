"""Controlled fixture contrasts; no production scoring, rules, or inventory changes."""

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import uuid

from .analyst_adapter import adapt_analyst_incident
from .config import AGENT_DIR, ForecastConfig
from .contracts import parse_time, utc_text
from .prognostic_agent import build_risk_forecast
from .provenance import provenance
from .scoring import load_weights
from .synthetic_demo import FIXTURE_DIR


@dataclass
class FixtureInventoryProvider:
    """Importable/picklable provider for independent in-memory test inventories."""
    records: dict
    name: str = "synthetic_contrast_inventory"

    def lookup(self, entity, *, deadline):
        return self.records.get(entity["entity_id"])


def _read(name):
    with (FIXTURE_DIR / name).open(encoding="utf-8") as stream:
        return json.load(stream)


def variant_definitions():
    return _read("contrast_variants.json")["variants"]


def prepare_variant(name):
    """Fresh copies on each call prevent one contrast leaking into another."""
    definitions = {item["name"]: item for item in variant_definitions()}
    if name not in definitions:
        raise ValueError("Unknown fixture contrast: " + name)
    incident, inventory, settings = _read("incident.json"), _read("inventory.json"), _read("settings.json")
    changes = definitions[name]["changes"]
    for record in inventory["entities"]:
        if record["entity_id"] == "user:fixture-admin":
            if "user_privilege_level" in changes:
                record["privilege_level"] = changes["user_privilege_level"]
            if "user_asset_age_hours" in changes:
                record["as_of"] = utc_text(parse_time(settings["forecast_as_of"]) - timedelta(hours=changes["user_asset_age_hours"]))
        if "reachable" in changes:
            for relationship in record.get("related_assets", []):
                relationship["reachable"] = changes["reachable"]
    if "age_evidence_hours" in changes:
        for event in incident["events"]:
            event["timestamp"] = utc_text(parse_time(event["timestamp"]) - timedelta(hours=changes["age_evidence_hours"]))
    if "behavioral_score" in changes:
        settings["behavioral_score"] = changes["behavioral_score"]
        # Keep the hand-authored upstream fixture internally consistent. The
        # adapter still uses the explicit behavioral argument, not this total.
        incident["risk_analysis"]["findings"][0]["points"] = changes["behavioral_score"]
        incident["risk_analysis"]["risk_score"] = changes["behavioral_score"] + 10
    kwargs = {"behavioral_score": settings["behavioral_score"]}
    if not changes.get("omit_attribution"):
        kwargs["technique_evidence"] = settings["technique_evidence"]
    else:
        incident["risk_analysis"].pop("technique_evidence", None)
    request = adapt_analyst_incident(incident, **kwargs)
    return request, inventory, settings


def probability_audit(value):
    locations, non_null = [], []

    def visit(item, path):
        if isinstance(item, dict):
            for key, child in item.items():
                location = path + "." + key
                if key == "probability":
                    locations.append(location)
                    if child is not None:
                        non_null.append(location)
                visit(child, location)
        elif isinstance(item, list):
            for index, child in enumerate(item):
                visit(child, f"{path}[{index}]")

    visit(value, "responses")
    return {"fields_checked": len(locations), "all_null": not non_null, "non_null_locations": non_null,
            "note": "Abstentions have likelihood=null rather than a fabricated probability object."}


def baseline_explanation(response):
    selected = response.get("predicted_path")
    triple = next((path for path in response.get("candidate_paths", []) if len(path["steps"]) == 3), None)
    if selected is None or triple is None:
        return {"available": False, "reason": "The baseline did not produce the required candidate paths."}
    request, _, _ = prepare_variant("baseline")
    weights = load_weights(ForecastConfig().weights_path)
    equal_index = [path for path in response["candidate_paths"] if path["candidate_id"] != selected["candidate_id"] and path["likelihood_index"] == selected["likelihood_index"]]
    return {
        "available": True,
        "risk_assessment": {"risk_score": response["risk_score"], "behavioral_score_source": response["behavioral_score_source"],
                            "risk_score_may_include_asset_impact": response["risk_score_may_include_asset_impact"],
                            "behavioral_input": request["triage_score"], "behavioral_weight": weights["risk_weights"]["analyst_behavior"],
                            "maximum_known_asset_criticality_score": response["impact_assessment"]["technical_impact_score"],
                            "asset_weight": weights["risk_weights"]["technical_impact"],
                            "contributions": response["impact_assessment"]["factor_contributions"]},
        "selected": {"starting_technique": selected["starting_technique"], "future_steps": len(selected["steps"]),
                     "index": selected["likelihood_index"], "evidence_refs": selected["evidence_refs"],
                     "factor_contributions": selected["steps"][0]["factor_contributions"]},
        "three_step": {"starting_technique": triple["starting_technique"], "future_steps": len(triple["steps"]),
                       "index": triple["likelihood_index"], "evidence_refs": triple["evidence_refs"],
                       "factor_contributions": triple["steps"][0]["factor_contributions"]},
        "ranking_order": ["descending likelihood index", "fewer future steps on an index tie", "stable candidate ID on a remaining tie"],
        "selected_beats_three_step_by_index": selected["likelihood_index"] > triple["likelihood_index"],
        "equal_index_alternative_future_steps": [len(path["steps"]) for path in equal_index],
        "path_score_method": "minimum edge index; no multiplication or numeric length penalty",
    }


def run_contrasts():
    config = ForecastConfig(environment="test", max_candidates=5)
    responses, attributions, rows = {}, {}, []
    for definition in variant_definitions():
        name = definition["name"]
        request, inventory, settings = prepare_variant(name)
        response = build_risk_forecast(request, config=config, forecast_as_of=settings["forecast_as_of"],
                                       asset_provider=FixtureInventoryProvider({item["entity_id"]: item for item in inventory["entities"]}))
        responses[name] = response
        attributions[name] = request["observed_techniques"]
        selected = response.get("predicted_path")
        rows.append({"variant": name, "status": response.get("status", response["response_type"]),
                     "reason": response.get("reason"), "likelihood_index": (response.get("likelihood") or {}).get("index"),
                     "risk_score": response.get("risk_score"), "selected_path": [selected["starting_technique"]] + [step["technique_id"] for step in selected["steps"]] if selected else None,
                     "behavioral_score_source": response.get("behavioral_score_source", "unknown"),
                     "risk_score_may_include_asset_impact": response.get("risk_score_may_include_asset_impact")})
    return {**provenance(config), "response_type": "synthetic_contrast_result", "comparison": rows,
            "baseline_explanation": baseline_explanation(responses["baseline"]), "probability_audit": probability_audit(responses),
            "attributions": attributions, "responses": responses, "variants": variant_definitions()}


def comparison_table(rows):
    lines = ["| Variant | Status | Reason | Likelihood index | Risk score | Selected path |",
             "|---|---|---|---:|---:|---|"]
    for row in rows:
        index = "null" if row["likelihood_index"] is None else f"{row['likelihood_index']:.6f}"
        score = "null" if row["risk_score"] is None else f"{row['risk_score']:g}"
        path = " -> ".join(row["selected_path"]) if row["selected_path"] else "null"
        lines.append(f"| {row['variant']} | {row['status']} | {row['reason']} | {index} | {score} | {path} |")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run isolated test-only synthetic contrasts and print one comparison table.")
    parser.add_argument("--output-dir", type=Path, default=AGENT_DIR / "private" / "synthetic-contrasts")
    args = parser.parse_args(argv)
    directory = args.output_dir.resolve()
    if not directory.is_relative_to(AGENT_DIR.resolve()):
        parser.error("Contrast outputs must stay inside Prognostic_Agent")
    result = run_contrasts()
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = directory / f"contrast_results_{stamp}_{uuid.uuid4().hex}.json"
    with destination.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")
    print(comparison_table(result["comparison"]))
    print(f"\nFull results: {destination}")
    print("Probability audit: " + json.dumps(result["probability_audit"]))
    baseline = result["responses"]["baseline"]
    return 0 if result["probability_audit"]["all_null"] and baseline.get("status") in {"complete", "partial"} else 1


if __name__ == "__main__":
    raise SystemExit(main())

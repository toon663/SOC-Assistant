"""Explainable heuristic indices. No calibrated probabilities or LLM scoring."""

import json
import math

from .contracts import content_hash

FACTORS = {"evidence_support", "prerequisite_satisfaction", "privilege_fit", "reachable_target_support", "recency"}


def load_weights(path):
    with open(path, encoding="utf-8") as stream:
        weights = json.load(stream)
    if weights.get("schema_version") != 1:
        raise ValueError("Unsupported weights schema")
    if not isinstance(weights.get("version"), str) or not weights["version"]:
        raise ValueError("Weights require a nonempty version")
    for key, names in (("candidate_weights", FACTORS), ("risk_weights", {"analyst_behavior", "technical_impact"})):
        values = weights[key]
        if set(values) != names or any(isinstance(v, bool) or not isinstance(v, (float, int)) or not math.isfinite(v) or v < 0 for v in values.values()) or not math.isclose(sum(values.values()), 1):
            raise ValueError(f"{key} must have the expected factors and sum to one")
    weights["content_hash"] = content_hash(weights)
    return weights


def score_candidate(factors, weights):
    contributions = {}
    lower, upper = 0.0, 0.0
    for name, weight in weights["candidate_weights"].items():
        value = factors[name]
        contributions[name] = None if value is None else round(value * weight, 6)
        lower += weight * (value if value is not None else 0)
        upper += weight * (value if value is not None else 1)
    return {"likelihood_index": round(lower, 6),
            "uncertainty_range": [round(lower, 6), round(upper, 6)],
            "factor_contributions": contributions,
            "factor_coverage": round(sum(weight for name, weight in weights["candidate_weights"].items() if factors[name] is not None), 6)}


def analyze_risk_impact(alert, asset_context, weights):
    """Worst documented asset criticality; no repeat anomaly or criticality bonus."""
    usable = [record for record in asset_context["entities"] if not record["stale"]]
    impact_values = [weights["criticality_scores"][record["asset_criticality"]] for record in usable if record.get("asset_criticality") is not None]
    impact = max(impact_values) if impact_values else None
    behavioral = alert["triage_score"]
    contributions = {"analyst_behavior": None if behavioral is None else round(behavioral * weights["risk_weights"]["analyst_behavior"], 2),
                     "technical_impact": None if impact is None else round(impact * weights["risk_weights"]["technical_impact"], 2)}
    risk = None if impact is None or behavioral is None else round(sum(contributions.values()), 2)
    cap = weights["benign_risk_cap"] if alert["verdict"] == "benign" else None
    if risk is not None and cap is not None:
        risk = min(cap, risk)
    return {"risk_score": risk, "technical_impact_score": impact,
            "behavioral_score_source": alert.get("behavioral_score_source", "supplied" if behavioral is not None else "unknown"),
            "risk_score_may_include_asset_impact": risk is not None,
            "factor_contributions": contributions, "benign_risk_cap": cap,
            "method": "analyst_behavior_plus_max_known_criticality",
            "assumption": "triage_score excludes asset-criticality bonuses; anomaly_score is provenance only",
            "coverage": len(impact_values) / len(alert["entities"]) if alert["entities"] else 0.0}


def blast_radius(alert, asset_context, paths, limit):
    """Union of the FULL supplied entity list and supported one-hop path targets."""
    records = {record["entity_id"]: record for record in asset_context["entities"]}
    observed = {}
    for entity in alert["entities"]:
        record = records.get(entity["entity_id"], {})
        canonical = record.get("canonical_id", entity["entity_id"])
        observed.setdefault(canonical, {"entity_id": canonical, "entity_type": entity["entity_type"], "evidence_refs": []})
        refs = [event["event_id"] for event in alert["normalized_events"] if entity["entity_id"] in event["entity_ids"]]
        observed[canonical]["evidence_refs"] = sorted(set(observed[canonical]["evidence_refs"] + refs))
    potential = {}
    for path in paths:
        for target in path["potential_targets"]:
            canonical = records.get(target["entity_id"], {}).get("canonical_id", target.get("canonical_id", target["entity_id"]))
            if canonical not in observed:
                potential.setdefault(canonical, {**target, "entity_id": canonical})
    ordered = [potential[key] for key in sorted(potential)]
    counts = {kind: sum(item["entity_type"] == kind for item in observed.values()) for kind in ("user", "host", "service")}
    return {"observed_entities": list(observed.values()), "potential_entities": ordered[:limit],
            "observed_count": len(observed), "potential_count": min(len(ordered), limit),
            "observed_counts_by_type": counts,
            "potential_counts_by_type": {kind: sum(item["entity_type"] == kind for item in ordered[:limit]) for kind in counts},
            "inventory_coverage": asset_context["coverage"],
            "unknown_relationship_entities": [entity["entity_id"] for entity in alert["entities"] if entity["entity_id"] not in records or records[entity["entity_id"]]["stale"] or "related_assets" not in records[entity["entity_id"]]],
            "truncated": len(ordered) > limit, "max_relationship_hops": 1,
            "scope": "Observed means present in the alert, not confirmed compromised; potential means path-supported reachability, not compromise."}

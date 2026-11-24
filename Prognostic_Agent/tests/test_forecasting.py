from copy import deepcopy
import json
import time
import unittest

from Prognostic_Agent import ForecastConfig, build_risk_forecast
from Prognostic_Agent.asset_context import LocalJSONAssetProvider, enrich_asset_context
from Prognostic_Agent.contracts import parse_time
from Prognostic_Agent.scoring import blast_radius, load_weights
from Prognostic_Agent.transition_rules import forecast_risk_path, load_rules, matching_rules
from Prognostic_Agent.tests.test_contracts import ROOT, alert

AS_OF = "2026-11-23T12:00:00Z"


class MemoryProvider:
    name = "memory"

    def __init__(self, records, delay_entity=None):
        self.records = records
        self.delay_entity = delay_entity

    def lookup(self, entity, *, deadline):
        if entity["entity_id"] == self.delay_entity:
            time.sleep(30)  # Parent must terminate this uncooperative provider.
        return self.records.get(entity["entity_id"])


def inventory():
    document = json.loads((ROOT / "assets" / "sample_asset_inventory.json").read_text(encoding="utf-8"))
    return {record["entity_id"]: record for record in document["entities"]}


def run(request=None, provider=None, config=None):
    return build_risk_forecast(request or alert(), asset_provider=provider or MemoryProvider(inventory()),
                               config=config or ForecastConfig(), forecast_as_of=AS_OF)


class ForecastTests(unittest.TestCase):
    def test_complete_offline_forecast_full_entity_radius_and_explanation(self):
        response = run(provider=LocalJSONAssetProvider(ROOT / "assets" / "sample_asset_inventory.json"))
        self.assertEqual(response["status"], "complete")
        self.assertEqual(response["numeric_assessment_status"], "complete")
        self.assertEqual(response["explanation_status"], "deterministic")
        self.assertIsNone(response["likelihood"]["probability"])
        self.assertEqual(response["risk_score"], 82)
        self.assertEqual(response["behavioral_score_source"], "supplied")
        self.assertTrue(response["risk_score_may_include_asset_impact"])
        self.assertEqual(response["impact_assessment"]["behavioral_score_source"], "supplied")
        self.assertTrue(response["impact_assessment"]["risk_score_may_include_asset_impact"])
        self.assertEqual(response["blast_radius"]["observed_count"], 3)
        self.assertEqual(response["blast_radius"]["potential_count"], 1)
        self.assertEqual(response["blast_radius"]["observed_counts_by_type"]["service"], 1)
        self.assertNotIn("message", response["evidence_references"][0])
        for path in response["candidate_paths"]:
            self.assertLessEqual(len(path["steps"]), 3)
            self.assertEqual(path["likelihood_index"], min(step["likelihood_index"] for step in path["steps"]))

    def test_missing_assets_abstains_and_keeps_unknown_impact_null(self):
        result = run(provider=MemoryProvider({}))
        self.assertEqual(result["status"], "abstained")
        self.assertEqual(result["reason"], "prerequisites_unresolved")
        self.assertIsNone(result["predicted_path"])
        self.assertIsNone(result["likelihood"])
        self.assertIsNone(result["risk_score"])
        self.assertEqual(result["numeric_assessment_status"], "unavailable")

    def test_missing_secondary_context_returns_supported_partial_result(self):
        records = inventory()
        del records["service:build"]
        response = run(provider=MemoryProvider(records))
        self.assertEqual(response["status"], "partial")
        self.assertTrue(response["candidate_paths"])
        self.assertEqual(response["blast_radius"]["observed_count"], 3)

    def test_freshness_and_horizon_are_independent_and_future_evidence_is_excluded(self):
        for timestamp in ("2026-11-22T10:00:00Z", "2026-11-23T13:00:00Z"):
            request = alert()
            request["normalized_events"][0]["timestamp"] = timestamp
            result = run(request, config=ForecastConfig(forecast_horizon_hours=72))
            self.assertEqual(result["reason"], "stale_evidence")
            self.assertEqual(result["time_horizon"]["hours"], 72)
        request = alert()
        request["normalized_events"][0]["timestamp"] = "2026-11-23T10:00:00Z"
        result = run(request, config=ForecastConfig(evidence_freshness_limit_hours=1, forecast_horizon_hours=72))
        self.assertEqual(result["status"], "abstained")

    def test_unsupported_starting_technique_is_reported(self):
        request = alert()
        request["observed_techniques"][0]["technique_id"] = "T1486"
        result = run(request)
        self.assertEqual(result["reason"], "unsupported_transition")
        self.assertEqual(result["unsupported_starting_techniques"][0]["technique_id"], "T1486")

    def test_mandatory_privilege_and_reachability_cannot_be_assumed(self):
        request = alert()
        request["observed_techniques"][0]["technique_id"] = "T1003.001"
        records = inventory()
        records["host:workstation-01"]["related_assets"] = []
        result = run(request, MemoryProvider(records))
        self.assertEqual(result["reason"], "prerequisites_failed")
        request["observed_techniques"][0]["technique_id"] = "T1059.001"
        records["user:alice"]["privilege_level"] = "user"
        result = run(request, MemoryProvider(records))
        self.assertEqual(result["reason"], "prerequisites_failed")

    def test_low_index_abstains_and_benign_verdict_does_not_seed_attack_paths(self):
        response = run(config=ForecastConfig(min_candidate_score=1))
        self.assertEqual(response["reason"], "below_candidate_threshold")
        request = alert()
        request["verdict"] = "benign"
        response = run(request)
        self.assertEqual(response["status"], "abstained")
        self.assertLessEqual(response["risk_score"], 20)

    def test_actual_timeout_preserves_completed_records_and_has_no_lingering_worker(self):
        import multiprocessing
        config = ForecastConfig(asset_provider_deadlines={"memory": 1.0}, enrichment_timeout_seconds=2)
        # Canonical entity order looks up host, then service, then user.
        provider = MemoryProvider(inventory(), delay_entity="user:alice")
        start = time.monotonic()
        response = run(provider=provider, config=config)
        self.assertLess(time.monotonic() - start, 4)
        self.assertTrue(any(item["code"] == "asset_lookup_timeout" for item in response["issues"]))
        self.assertGreater(response["asset_context"]["coverage"], 0)
        self.assertFalse(multiprocessing.active_children())

    def test_timeout_with_enough_retained_context_returns_partial(self):
        request = alert()
        request["observed_techniques"][0]["technique_id"] = "T1078"
        result = run(request, provider=MemoryProvider(inventory(), delay_entity="user:alice"),
                     config=ForecastConfig(asset_provider_deadlines={"memory": 1.0}))
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["reason"], "asset_lookup_timeout")
        self.assertTrue(result["candidate_paths"])
        self.assertEqual({record["entity_id"] for record in result["asset_context"]["entities"]}, {"host:workstation-01", "service:build"})

    def test_parent_covers_children_with_explicit_opt_out_and_exclusions(self):
        request = alert()
        request["observed_techniques"][0]["technique_id"] = "T1078.003"
        result = run(request)
        self.assertTrue(result["candidate_paths"])
        self.assertEqual(result["candidate_paths"][0]["starting_technique"], "T1078.003")
        rule = load_rules(ForecastConfig().rules_path)["rules"][0]
        self.assertTrue(matching_rules("T1078.003", [rule]))
        self.assertFalse(matching_rules("T1078.003", [{**rule, "include_subtechniques": False}]))
        self.assertFalse(matching_rules("T1078.003", [{**rule, "excluded_subtechniques": ["T1078.003"]}]))
        self.assertFalse(matching_rules("T1078", [{**rule, "source": "T1078.003"}]))

    def test_cycles_are_bounded_and_future_remote_privileges_are_not_assumed(self):
        config = ForecastConfig(max_path_steps=3)
        request = alert()
        context = enrich_asset_context(request, [MemoryProvider(inventory())], config, parse_time(AS_OF))
        rules = load_rules(config.rules_path)
        cycle = deepcopy(rules["rules"][1])
        cycle.update(rule_id="cycle", source="T1003.001", target="T1059.001")
        rules["rules"].append(cycle)
        result = forecast_risk_path(request, context, {}, config, parse_time(AS_OF), rules, load_weights(config.weights_path))
        for path in result["candidate_paths"]:
            ids = [path["starting_technique"]] + [step["technique_id"] for step in path["steps"]]
            self.assertEqual(len(ids), len(set(ids)))

    def test_blast_radius_aliases_count_once_and_truncation_is_explicit(self):
        request = alert()
        records = inventory()
        records["service:build"]["canonical_id"] = "host:workstation-01"
        # Use consistent entity types for aliases in this direct counting fixture.
        request["entities"][2]["entity_type"] = "host"
        records["service:build"]["entity_type"] = "host"
        for record in records.values():
            record["stale"] = False
        context = {"entities": list(records.values()), "coverage": 1}
        targets = [{"entity_id": "extra:" + str(i), "entity_type": "host", "evidence_ref": "inventory:r"} for i in range(3)]
        result = blast_radius(request, context, [{"potential_targets": targets}], 1)
        self.assertEqual(result["observed_count"], 2)
        self.assertEqual(result["potential_count"], 1)
        self.assertTrue(result["truncated"])

    def test_configuration_rejects_invalid_deadlines(self):
        for kwargs in ({"asset_provider_deadlines": {"memory": 0}}, {"forecast_horizon_hours": float("nan")}, {"evidence_freshness_limit_hours": 0}):
            with self.assertRaises(ValueError):
                ForecastConfig(**kwargs)

    def test_stale_asset_provider_can_be_replaced_by_fresh_fallback(self):
        stale = inventory()
        for record in stale.values():
            record["as_of"] = "2026-11-20T12:00:00Z"
        first = MemoryProvider(stale)
        first.name = "old"
        response = build_risk_forecast(alert(), asset_providers=[first, MemoryProvider(inventory())], forecast_as_of=AS_OF)
        self.assertEqual(response["status"], "complete")
        self.assertTrue(all(record["provider"] == "memory" for record in response["asset_context"]["entities"]))

    def test_stale_and_future_asset_context_cannot_satisfy_prerequisites(self):
        for timestamp in ("2026-11-20T12:00:00Z", "2026-11-24T12:00:00Z"):
            records = inventory()
            for record in records.values():
                record["as_of"] = timestamp
            response = run(provider=MemoryProvider(records))
            self.assertEqual(response["status"], "abstained")
            self.assertIsNone(response["risk_score"])

    def test_unknown_optional_reachability_has_range_and_partial_numeric_status(self):
        records = inventory()
        for record in records.values():
            record.pop("related_assets")
        response = run(provider=MemoryProvider(records))
        self.assertEqual(response["status"], "partial")
        self.assertEqual(response["numeric_assessment_status"], "partial")
        low, high = response["likelihood"]["uncertainty_range"]
        self.assertLess(low, high)
        self.assertEqual(response["blast_radius"]["potential_count"], 0)

    def test_zero_confidence_cannot_seed_candidates(self):
        request = alert()
        request["analyst_confidence"] = 0
        self.assertEqual(run(request)["reason"], "insufficient_evidence")

    def test_abstained_score_retention_matches_documented_input_requirements(self):
        request = alert()
        request["observed_techniques"][0]["technique_id"] = "T1486"
        retained = run(request)
        self.assertEqual(retained["status"], "abstained")
        self.assertEqual(retained["risk_score"], 82)
        self.assertEqual(retained["risk_score_basis"], "impact_assessment_only")
        missing_behavior = deepcopy(request)
        missing_behavior["triage_score"] = None
        unknown = run(missing_behavior)
        self.assertIsNone(unknown["risk_score"])
        self.assertEqual(unknown["impact_assessment"]["technical_impact_score"], 100)
        partial_assets = inventory()
        del partial_assets["service:build"]
        partial = run(request, MemoryProvider(partial_assets))
        self.assertEqual(partial["status"], "abstained")
        self.assertEqual(partial["risk_score"], 72)
        request["verdict"] = "benign"
        self.assertEqual(run(request)["risk_score"], 20)

    def test_platform_gap_is_reported_without_inventing_a_transition(self):
        records = inventory()
        for record in records.values():
            record["platform"] = "linux"
        response = run(provider=MemoryProvider(records))
        self.assertEqual(response["status"], "abstained")
        self.assertEqual(response["unsupported_starting_techniques"][0]["reason"], "platform_mismatch")


if __name__ == "__main__":
    unittest.main()

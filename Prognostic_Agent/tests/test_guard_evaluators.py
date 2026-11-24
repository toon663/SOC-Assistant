"""Unit-only in-memory auth edge; no new runtime rule file is created."""

from copy import deepcopy
import unittest
from unittest.mock import patch

from Prognostic_Agent.config import ForecastConfig
from Prognostic_Agent.contracts import AnalystAlert, RequestValidationError, content_hash, parse_time
from Prognostic_Agent.prognostic_agent import build_risk_forecast
from Prognostic_Agent.analyst_adapter import adapt_analyst_incident
from Prognostic_Agent.guard_evaluators import evaluate_guards
from Prognostic_Agent.scoring import load_weights
from Prognostic_Agent.transition_rules import forecast_risk_path
from Prognostic_Agent.tests.test_contracts import alert
from Prognostic_Agent.tests.test_forecasting import AS_OF, inventory
from Prognostic_Agent.tests.test_rule_schema import document


def fixture(count=5):
    request = alert()
    request["source_ip"] = "203.0.113.42"
    request["normalized_events"] = [
        {"event_id": f"failure-{index}", "timestamp": f"2026-11-23T11:{50+index:02d}:00Z",
         "event_type": "failed_logon", "entity_ids": ["user:alice", "host:workstation-01"],
         "source_ip": "203.0.113.42"} for index in range(count)]
    refs = [item["event_id"] for item in request["normalized_events"]]
    request["observed_techniques"] = [{"technique_id": "T1110.001", "attribution": "exact", "evidence_refs": refs}]
    common = {"source": "inventory:test", "as_of": "2026-11-23T11:59:00Z", "evidence_refs": refs}
    request["guard_context"] = {"schema_version": 1, "bindings": []}
    for identity in refs:
        binding = {"technique_id": "T1110.001", "seed_event_id": identity,
                   "user_id": "user:alice", "host_id": "host:workstation-01", "source_ip": "203.0.113.42",
                   "endpoint_id": "auth:workstation-01:network-logon",
                   "analyst_correlation": {**deepcopy(common), "source": "analyst", "activity": "online_authentication_failures",
                                           "event_count": count, "window_start": request["normalized_events"][0]["timestamp"],
                                           "window_end": request["normalized_events"][-1]["timestamp"]},
                   "authentication_reachability": {**deepcopy(common), "reachable": True},
                   "account_authentication": {**deepcopy(common), "enabled": True, "locked": False, "blocked": False}}
        request["guard_context"]["bindings"].append(binding)
    rules = document()
    edge = deepcopy(rules["rules"][0])
    edge.update(rule_id="unit-only-auth-transition", source="T1110", target="T1078", target_name="Valid Accounts",
                minimum_privilege="none", excluded_subtechniques=["T1110.002"], terminal=True,
                guards=[{"type": "exact_attribution"}, {"type": "evidence_freshness", "max_age_hours": 24},
                        {"type": "analyst_correlation", "minimum_events": 5, "window_hours": 1},
                        {"type": "authentication_reachability"}, {"type": "account_authentication"},
                        {"type": "target_not_observed"}])
    rules["rules"] = [edge, *rules["rules"]]
    return request, rules


def run_guards(request, rules, records=None):
    request = AnalystAlert.from_dict(request).data
    records = deepcopy(records if records is not None else inventory())
    for record in records.values():
        record.update(stale=False, provider="unit_test")
    config = ForecastConfig(max_candidates=20)
    return forecast_risk_path(request, {"entities": list(records.values())}, {}, config,
                              parse_time(AS_OF), rules, load_weights(config.weights_path))


def change_assertion(request, name, **changes):
    for binding in request["guard_context"]["bindings"]:
        binding[name].update(changes)


class GuardEvaluatorTests(unittest.TestCase):
    def test_all_guards_pass_with_auditable_supplied_proof_and_terminal_target(self):
        request, rules = fixture()
        before = deepcopy(request)
        result = run_guards(request, rules)
        self.assertEqual(request, before)
        self.assertTrue(result["candidate_paths"])
        for path in result["candidate_paths"]:
            self.assertEqual(len(path["steps"]), 1)
            self.assertEqual(path["steps"][0]["technique_id"], "T1078")
            self.assertEqual(path["evidence_refs"], [f"failure-{i}" for i in range(5)])
            evaluations = path["steps"][0]["guard_evaluations"]
            self.assertEqual(len(evaluations), 6)
            self.assertTrue(all(item["status"] == "pass" for item in evaluations))
            self.assertTrue(any(item.get("source") == "analyst" for item in evaluations))
        baseline = deepcopy(rules)
        baseline["rules"][0]["guards"] = []
        self.assertEqual(result["candidate_paths"][0]["likelihood_index"], run_guards(request, baseline)["candidate_paths"][0]["likelihood_index"])

    def test_missing_assertions_do_not_inherit_generic_inventory_reachability(self):
        for missing in ("analyst_correlation", "authentication_reachability", "account_authentication"):
            request, rules = fixture()
            for binding in request["guard_context"]["bindings"]:
                binding.pop(missing)
            result = run_guards(request, rules)
            self.assertEqual(result["abstain_reason"], "prerequisites_unresolved")
            self.assertTrue(all("guard_" + missing + "_unresolved" in row["reasons"] for row in result["rejected_transitions"]))

    def test_disabled_locked_blocked_or_unreachable_facts_reject(self):
        for kind, changes in (("account_authentication", {"enabled": False}), ("account_authentication", {"locked": True}),
                              ("account_authentication", {"blocked": True}), ("authentication_reachability", {"reachable": False})):
            with self.subTest(kind=kind, changes=changes):
                request, rules = fixture()
                change_assertion(request, kind, **changes)
                self.assertEqual(run_guards(request, rules)["abstain_reason"], "prerequisites_failed")

    def test_unknown_control_states_are_unresolved_and_known_blocking_wins(self):
        for kind, changes in (("account_authentication", {"enabled": None}), ("account_authentication", {"locked": None}),
                              ("authentication_reachability", {"reachable": None})):
            request, rules = fixture()
            change_assertion(request, kind, **changes)
            self.assertEqual(run_guards(request, rules)["abstain_reason"], "prerequisites_unresolved")
        request, rules = fixture()
        change_assertion(request, "account_authentication", enabled=None, blocked=True)
        self.assertEqual(run_guards(request, rules)["abstain_reason"], "prerequisites_failed")

    def test_stale_future_and_predated_assertions_do_not_establish_current_facts(self):
        for timestamp in ("2026-11-21T11:59:00Z", "2026-11-24T11:59:00Z", "2026-11-23T11:49:00Z"):
            request, rules = fixture()
            change_assertion(request, "authentication_reachability", as_of=timestamp)
            self.assertEqual(run_guards(request, rules)["abstain_reason"], "prerequisites_unresolved")

    def test_source_freshness_checks_all_attributed_evidence(self):
        request, rules = fixture()
        request["normalized_events"][0]["timestamp"] = "2026-11-21T11:50:00Z"
        result = run_guards(request, rules)
        self.assertFalse(result["candidate_paths"])
        self.assertTrue(any("guard_evidence_freshness_unresolved" in row["reasons"] for row in result["rejected_transitions"]))

    def test_correlation_is_verified_not_inferred_from_counts_or_findings(self):
        for changes, reason in (({"source": "inventory:test"}, "prerequisites_unresolved"),
                                ({"event_count": 500}, "prerequisites_unresolved"),
                                ({"activity": "unknown"}, "prerequisites_unresolved"),
                                ({"activity": "offline_password_cracking"}, "prerequisites_failed"),
                                ({"window_end": "2026-11-23T11:53:00Z"}, "prerequisites_unresolved")):
            request, rules = fixture()
            change_assertion(request, "analyst_correlation", **changes)
            self.assertEqual(run_guards(request, rules)["abstain_reason"], reason)
        request, rules = fixture(4)
        self.assertEqual(run_guards(request, rules)["abstain_reason"], "prerequisites_failed")
        request, rules = fixture()
        rules["rules"][0]["guards"][2]["window_hours"] = .01
        self.assertEqual(run_guards(request, rules)["abstain_reason"], "prerequisites_failed")

    def test_bound_subject_source_and_endpoint_are_not_borrowed(self):
        request, rules = fixture()
        for binding in request["guard_context"]["bindings"]:
            binding["source_ip"] = "203.0.113.43"
        self.assertEqual(run_guards(request, rules)["abstain_reason"], "prerequisites_unresolved")
        request, rules = fixture()
        request["guard_context"]["bindings"][0]["user_id"] = "user:someone-else"
        with self.assertRaises(RequestValidationError):
            run_guards(request, rules)
        request, rules = fixture()
        duplicate = deepcopy(request["guard_context"]["bindings"][0])
        duplicate["endpoint_id"] = "auth:another-endpoint"
        request["guard_context"]["bindings"].append(duplicate)
        with self.assertRaises(RequestValidationError):
            run_guards(request, rules)

    def test_observed_target_even_coarse_or_parent_child_blocks_prediction(self):
        for technique in ("T1078", "T1078.003"):
            request, rules = fixture()
            request["observed_techniques"].append({"technique_id": technique, "attribution": "coarse", "evidence_refs": []})
            result = run_guards(request, rules)
            self.assertEqual(result["abstain_reason"], "prerequisites_failed")
            self.assertTrue(any("guard_target_not_observed_failed" in row["reasons"] for row in result["rejected_transitions"]))

    def test_coarse_technique_cannot_be_upgraded_by_a_guard(self):
        request, rules = fixture()
        request.pop("guard_context")
        request["observed_techniques"][0].update(attribution="coarse", evidence_refs=[])
        validated = AnalystAlert.from_dict(request).data
        result = evaluate_guards(rules["rules"][0], validated, validated["observed_techniques"][0],
                                 validated["normalized_events"][0], "T1110.001", ForecastConfig(), parse_time(AS_OF))
        self.assertIn("guard_exact_attribution_unresolved", result["failures"])
        self.assertEqual(run_guards(request, rules)["abstain_reason"], "insufficient_evidence")

    def test_guards_cannot_inherit_proof_for_hypothetical_intermediate_techniques(self):
        request, rules = fixture()
        rules["rules"][0]["terminal"] = False
        rules["rules"][1]["guards"] = [{"type": "exact_attribution"}]
        result = run_guards(request, rules)
        self.assertTrue(result["candidate_paths"])
        self.assertTrue(all(len(path["steps"]) == 1 for path in result["candidate_paths"]))
        self.assertTrue(any("guard_exact_attribution_unresolved" in row["reasons"] for row in result["rejected_transitions"]))

    def test_no_authenticated_privilege_is_required_when_policy_minimum_is_none(self):
        request, rules = fixture()
        records = inventory()
        for record in records.values():
            record.pop("privilege_level", None)
        self.assertTrue(run_guards(request, rules, records)["candidate_paths"])

    def test_guard_context_canonicalization_and_validation(self):
        request, _ = fixture()
        equivalent = deepcopy(request)
        equivalent["guard_context"]["bindings"].reverse()
        for binding in equivalent["guard_context"]["bindings"]:
            for name in ("analyst_correlation", "authentication_reachability", "account_authentication"):
                binding[name]["evidence_refs"].reverse()
                binding[name]["as_of"] = binding[name]["as_of"].replace("Z", "+00:00")
        self.assertEqual(AnalystAlert.from_dict(request).input_fingerprint, AnalystAlert.from_dict(equivalent).input_fingerprint)
        invalid_cases = []
        value = deepcopy(request)
        value["guard_context"]["bindings"][0]["account_authentication"]["enabled"] = "true"
        invalid_cases.append(value)
        value = deepcopy(request)
        value["guard_context"]["bindings"][0]["authentication_reachability"]["evidence_refs"] = ["missing-event"]
        invalid_cases.append(value)
        value = deepcopy(request)
        value["guard_context"]["bindings"][0]["unexpected"] = True
        invalid_cases.append(value)
        for value in invalid_cases:
            with self.assertRaises(RequestValidationError):
                AnalystAlert.from_dict(value)

    def test_full_forecast_statuses_preserve_supported_paths_and_independent_impact(self):
        for mode in ("complete", "unknown", "blocked", "partial"):
            with self.subTest(mode=mode):
                request, rules = fixture()
                rules["version"] = "unit-only-guarded-v2"
                if mode in ("unknown", "partial"):
                    change_assertion(request, "account_authentication", locked=None)
                elif mode == "blocked":
                    change_assertion(request, "account_authentication", blocked=True)
                if mode == "partial":
                    request["normalized_events"].append({"event_id": "execution", "event_type": "process_creation",
                        "timestamp": "2026-11-23T11:56:00Z", "entity_ids": ["user:alice", "host:workstation-01"],
                        "source_ip": "203.0.113.42"})
                    request["observed_techniques"].append({"technique_id": "T1059.001", "evidence_refs": ["execution"]})
                records = inventory()
                for record in records.values():
                    record.update(stale=False, provider="unit_test")
                context = {"entities": list(records.values()), "issues": [], "coverage": 1,
                           "fresh_field_coverage": 1, "provider_stats": [], "missing_fields": []}
                rules["content_hash"] = content_hash(rules)
                with patch("Prognostic_Agent.prognostic_agent.load_rules", return_value=rules), \
                     patch("Prognostic_Agent.prognostic_agent.enrich_asset_context", return_value=context):
                    result = build_risk_forecast(request, config=ForecastConfig(environment="test"), forecast_as_of=AS_OF)
                expected = {"complete": ("complete", "assessment_complete"), "unknown": ("abstained", "prerequisites_unresolved"),
                            "blocked": ("abstained", "prerequisites_failed"), "partial": ("partial", "candidate_coverage_incomplete")}[mode]
                self.assertEqual((result.get("status"), result.get("reason")), expected)
                self.assertIsNotNone(result["risk_score"])
                if result["predicted_path"]:
                    self.assertIsNone(result["likelihood"]["probability"])
                else:
                    self.assertEqual(result["risk_score_basis"], "impact_assessment_only")

    def test_adapter_copies_explicit_guard_context_without_manufacturing_assertions(self):
        from Prognostic_Agent.tests.test_adapter import incident
        payload = incident()
        self.assertNotIn("guard_context", adapt_analyst_incident(payload))
        request, _ = fixture()
        supplied = request["guard_context"]
        converted = adapt_analyst_incident(payload, guard_context=supplied)
        self.assertEqual(converted["guard_context"], supplied)
        self.assertIsNot(converted["guard_context"], supplied)
        self.assertEqual(converted["adapter_metadata"]["guard_context_provenance"], "explicit_argument")
        payload["risk_analysis"]["guard_context"] = supplied
        self.assertEqual(adapt_analyst_incident(payload)["adapter_metadata"]["guard_context_provenance"], "analyst.guard_context")

    def test_cross_host_and_cross_account_control_evidence_cannot_be_reused(self):
        for kind in ("host", "user"):
            request, rules = fixture()
            entity_id = kind + ":other"
            request["entities"].append({"entity_id": entity_id, "entity_type": kind})
            ids = ["user:alice", "host:workstation-01"]
            ids[1 if kind == "host" else 0] = entity_id
            request["normalized_events"].append({"event_id": "other-subject", "event_type": "inventory_snapshot",
                "timestamp": "2026-11-23T11:59:00Z", "entity_ids": ids})
            change_assertion(request, "account_authentication", evidence_refs=["other-subject"])
            self.assertEqual(run_guards(request, rules)["abstain_reason"], "prerequisites_unresolved")

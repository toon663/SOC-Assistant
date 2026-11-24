from copy import deepcopy
import json
import unittest
from unittest.mock import mock_open, patch

from Prognostic_Agent.config import ForecastConfig
from Prognostic_Agent.contracts import AnalystAlert, parse_time
from Prognostic_Agent.rule_schema import GUARD_FIELDS, validate_rule_document
from Prognostic_Agent.scoring import load_weights
from Prognostic_Agent.transition_rules import forecast_risk_path, load_rules
from Prognostic_Agent.tests.test_contracts import ROOT, alert
from Prognostic_Agent.tests.test_forecasting import AS_OF, inventory


def document(version=2):
    value = json.loads((ROOT / "rules/attack_transitions.json").read_text(encoding="utf-8"))
    value["schema_version"] = version
    return value


def run_rules(rules):
    request = AnalystAlert.from_dict(alert()).data
    records = inventory()
    for record in records.values():
        record.update(stale=False, provider="unit_test")
    config = ForecastConfig(max_candidates=20)
    return forecast_risk_path(request, {"entities": list(records.values())}, {}, config,
                              parse_time(AS_OF), rules, load_weights(config.weights_path))


class RuleSchemaTests(unittest.TestCase):
    def test_legacy_file_and_v2_without_guards_have_identical_paths(self):
        original = document(1)
        self.assertEqual(run_rules(original), run_rules(document(2)))
        self.assertEqual(validate_rule_document(original), original)
        self.assertEqual(len(load_rules(ForecastConfig().rules_path)["rules"]), 3)

    def test_loader_accepts_all_typed_guards_without_mutating_input(self):
        value = document()
        guards = [{"type": "exact_attribution"}, {"type": "evidence_freshness", "max_age_hours": 24},
                  {"type": "analyst_correlation", "minimum_events": 5, "window_hours": 1},
                  {"type": "authentication_reachability"}, {"type": "account_authentication"},
                  {"type": "target_not_observed"}]
        value["rules"][1].update(guards=guards, terminal=True)
        before = deepcopy(value)
        with patch("builtins.open", mock_open(read_data=json.dumps(value))):
            loaded = load_rules("in-memory-only.json")
        self.assertEqual(value, before)
        self.assertEqual(loaded["rules"][1]["guards"], guards)
        self.assertIn("content_hash", loaded)

    def test_assertion_guards_fail_closed_without_supplied_facts(self):
        for kind in ("analyst_correlation", "authentication_reachability", "account_authentication"):
            with self.subTest(kind=kind):
                value = document()
                guard = {"type": kind, **{name: 1 for name in GUARD_FIELDS[kind]}}
                value["rules"][1]["guards"] = [guard]
                result = run_rules(value)
                self.assertEqual(result["candidate_paths"], [])
                self.assertEqual(result["abstain_reason"], "prerequisites_unresolved")
                self.assertTrue(any("guard_" + kind + "_unresolved" in item["reasons"]
                                    for item in result["rejected_transitions"]))

    def test_evidence_only_guards_use_existing_supplied_event_evidence(self):
        for kind in ("exact_attribution", "evidence_freshness", "target_not_observed"):
            with self.subTest(kind=kind):
                value = document()
                value["rules"][1]["guards"] = [{"type": kind, **{name: 24 for name in GUARD_FIELDS[kind]}}]
                result = run_rules(value)
                self.assertTrue(result["candidate_paths"])
                self.assertEqual(result["candidate_paths"][0]["steps"][0]["guard_evaluations"][0]["status"], "pass")

    def test_terminal_target_prevents_further_expansion(self):
        value = document()
        value["rules"][1]["terminal"] = True
        baseline = run_rules(document())
        result = run_rules(value)
        self.assertTrue(any(len(path["steps"]) > 1 for path in baseline["candidate_paths"]))
        self.assertTrue(result["candidate_paths"])
        self.assertTrue(all(len(path["steps"]) == 1 for path in result["candidate_paths"]))
        self.assertEqual(result["candidate_paths"][0]["steps"][0]["technique_id"], "T1003.001")

    def test_invalid_guard_names_parameters_and_expression_fields_are_rejected(self):
        invalid = [None, {}, False, [None], [{"type": "unknown"}],
                   [{"type": "exact_attribution", "enabled": False}],
                   [{"type": "exact_attribution"}, {"type": "exact_attribution"}],
                   [{"type": "evidence_freshness"}],
                   [{"type": "evidence_freshness", "max_age_hours": True}],
                   [{"type": "evidence_freshness", "max_age_hours": 0}],
                   [{"type": "evidence_freshness", "max_age_hours": -1}],
                   [{"type": "evidence_freshness", "max_age_hours": float("inf")}],
                   [{"type": "evidence_freshness", "max_age_hours": 10**500}],
                   [{"type": "evidence_freshness", "max_age_hours": "24"}],
                   [{"type": "analyst_correlation", "minimum_events": 1.5, "window_hours": 1}],
                   [{"type": "analyst_correlation", "minimum_events": True, "window_hours": 1}],
                   [{"type": "analyst_correlation", "minimum_events": 0, "window_hours": 1}],
                   [{"type": "target_not_observed", "expression": "true"}]]
        for guards in invalid:
            with self.subTest(guards=str(guards)[:120]):
                value = document()
                value["rules"][1]["guards"] = guards
                with self.assertRaises(ValueError):
                    validate_rule_document(value)

    def test_v1_rejects_guards_and_unknown_fields_cannot_be_silently_ignored(self):
        for key, item in (("guards", []), ("terminal", False), ("guard", {})):
            value = document(1)
            value["rules"][1][key] = item
            with self.subTest(key=key), self.assertRaises(ValueError):
                run_rules(value)
        value = document()
        value["rules"][1]["terminal"] = "true"
        with self.assertRaises(ValueError):
            validate_rule_document(value)
        value = document()
        value["schema_version"] = True
        with self.assertRaises(ValueError):
            validate_rule_document(value)

    def test_schema_document_lists_the_same_guard_vocabulary(self):
        schema = json.loads((ROOT / "schemas/transition_rules.schema.json").read_text(encoding="utf-8"))
        options = schema["$defs"]["rule"]["properties"]["guards"]["items"]["oneOf"]
        self.assertEqual({option["properties"]["type"]["const"] for option in options}, set(GUARD_FIELDS))
        for option in options:
            kind = option["properties"]["type"]["const"]
            self.assertEqual(set(option["required"]), {"type", *GUARD_FIELDS[kind]})

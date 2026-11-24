from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path
import unittest

from Prognostic_Agent.contracts import parse_time
from Prognostic_Agent.orchestrator_contract import (ContractError, assert_live_usable, contract_schema,
    empty_record, serialize_forecast, validate_contract)
from Prognostic_Agent.synthetic_demo import run_fixture

_PRODUCER = None
AS_OF = "2026-11-23T12:00:00Z"


def producer_response():
    global _PRODUCER
    if _PRODUCER is None:
        _PRODUCER = run_fixture()
    result = deepcopy(_PRODUCER)
    result["history"] = {"forecast_id":"fixture-forecast", "revision":1, "persisted":True}
    return result


def record(status="complete", destination="T1003.001"):
    response = producer_response()
    if status == "abstained":
        response.update(status=status, reason="unsupported_transition", numeric_assessment_status="partial",
                        predicted_path=None, likelihood=None, risk_score_basis="impact_assessment_only")
    elif status == "partial":
        response.update(status=status, reason="asset_context_incomplete", numeric_assessment_status="partial")
        response["issues"].append({"code":"asset_context_incomplete", "detail":"Some context is unknown."})
    result = serialize_forecast(response)
    if status != "abstained" and destination != result["destination_technique"]:
        result["selected_path"]["steps"][-1]["technique_id"] = destination
        result["destination_technique"] = destination
    return validate_contract(result)


class OrchestratorContractTests(unittest.TestCase):
    def test_schema_artifact_and_runtime_definition_match(self):
        path = Path(__file__).parents[1]/"schemas/prognostic_forecast_for_orchestrator.v1.schema.json"
        self.assertEqual(json.loads(path.read_text()), contract_schema())

    def test_non_object_and_malformed_producer_are_fixed_contract_errors(self):
        for value in ([], [1], None, "bad"):
            with self.subTest(value=value), self.assertRaises(ContractError): validate_contract(value)
        with self.assertRaises(ContractError): serialize_forecast({"response_type":"risk_forecast"})

    def test_complete_partial_abstained_and_identity_versions(self):
        for status in ("complete","partial","abstained"):
            result = record(status)
            self.assertEqual(result["status"], status)
            self.assertEqual(result["forecast_id"], "fixture-forecast")
            self.assertEqual(result["forecast_revision"], 1)
            self.assertEqual(result["risk_score"], 72)
            self.assertIsNone(result["probability"])
            self.assertTrue(result["heuristic"])
            self.assertTrue(all(result["versions"].values()))

    def test_errors_and_skip_are_not_zero_risk_or_empty_known_scope(self):
        for kind in ("validation_error","operational_error","skipped_benign"):
            value = empty_record(kind, "skipped_benign" if kind == "skipped_benign" else "failed")
            validate_contract(value)
            self.assertIsNone(value["risk_score"])
            self.assertIsNone(value["status"])
            self.assertIsNone(value["blast_radius"]["observed_entities"])
            self.assertEqual(value["numeric_assessment_status"], "unavailable")

    def test_nullable_risk_is_unknown_not_zero(self):
        value = record("partial")
        value.update(risk_score=None, risk_score_may_include_asset_impact=None, behavioral_score_source="unknown")
        self.assertIsNone(validate_contract(value)["risk_score"])

    def test_abstention_retains_impact_only_and_cannot_have_a_path(self):
        value = record("abstained")
        self.assertEqual(value["risk_score_basis"], "impact_assessment_only")
        value["destination_technique"] = "T1078"
        with self.assertRaises(ContractError): validate_contract(value)

    def test_non_null_probability_bool_numbers_extra_fields_and_bad_destination_rejected(self):
        for key, bad in (("probability",0.1),("risk_score",True),("risk_score",float("nan")),
                         ("forecast_revision",False),("destination_technique","T1078"),("extra",True)):
            with self.subTest(key=key):
                value = record(); value[key] = bad
                with self.assertRaises(ContractError): validate_contract(value)

    def test_path_requires_real_history_and_candidate_membership(self):
        value = producer_response(); value.pop("history")
        with self.assertRaises(ContractError): serialize_forecast(value)
        value = producer_response(); value["candidate_paths"] = []
        with self.assertRaises(ContractError): serialize_forecast(value)

    def test_revision_environment_fingerprint_and_expiration_binding(self):
        value = record()
        for kwargs in ({"expected_revision":"wrong"},{"expected_environment":"production"},
                       {"expected_fingerprint":"0"*64},{"expected_alert_id":"other"},
                       {"now":parse_time(value["time_horizon"]["end"])+timedelta(seconds=1)}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ContractError): validate_contract(value,**kwargs)

    def test_scope_disjoint_and_null_versions_rejected(self):
        value = record()
        self.assertEqual(value["blast_radius"]["observed_meaning"],"present_in_evidence_not_proven_compromise")
        self.assertEqual(value["blast_radius"]["reachable_meaning"],"potentially_reachable_not_proven_compromise")
        value["blast_radius"]["potentially_reachable_entities"] = [value["blast_radius"]["observed_entities"][0]]
        value["blast_radius"]["potentially_reachable_count"] = 1
        with self.assertRaises(ContractError): validate_contract(value)
        value = record(); value["versions"]["weights"] = None
        with self.assertRaises(ContractError): validate_contract(value)

    def test_every_environment_is_refused_for_live_use_in_v1(self):
        for environment in ("test","demo","production"):
            value=record(); value["environment"]=environment
            with self.assertRaises(ContractError) as error: assert_live_usable(value)
            self.assertEqual(error.exception.code,"shadow_only_contract" if environment=="production" else "non_production_forecast")

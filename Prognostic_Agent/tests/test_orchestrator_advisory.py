from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from Prognostic_Agent.contracts import canonical_json, parse_time
from Prognostic_Agent.orchestrator_advisory import MAPPING_HASH, MAPPING_VERSION, prioritize_response_options
from Prognostic_Agent.orchestrator_contract import empty_record
from Prognostic_Agent.orchestrator_shadow_log import ShadowDecisionLog
from Prognostic_Agent.private_paths import PRIVATE_DIR
from Prognostic_Agent.tests.test_orchestrator_contract import AS_OF, record


def options():
    def option(action,target):
        return {"option_id":action,"action":action,"target_entity_id":target,"eligible":True,"approval_required":True,
                "probability":0.9,"selected":True,"policy":{"allowed":True,"requires_approval":True}}
    return [option("disable_user","user:fixture-admin"), option("block_ip",None),
            option("isolate_endpoint","host:fixture-workstation"), option("monitor",None)]


class OrchestratorAdvisoryTests(unittest.TestCase):
    def run_advisory(self, baseline=None, forecast=None):
        return prioritize_response_options(options() if baseline is None else baseline, record() if forecast is None else forecast, now=AS_OF)

    def test_slot_permutation_keeps_unmapped_exact_positions(self):
        baseline=options(); before=deepcopy(baseline)
        value=self.run_advisory(baseline)
        self.assertTrue(value["order_changed"])
        self.assertEqual([o["action"] for o in value["prioritized_options"]], ["isolate_endpoint","block_ip","disable_user","monitor"])
        self.assertEqual(value["prioritized_options"][1],baseline[1]);self.assertEqual(value["prioritized_options"][3],baseline[3])
        self.assertEqual(baseline,before)

    def test_all_mapped_options_must_be_present_and_independently_eligible(self):
        for baseline in ([options()[2]], [options()[0]], options()[:2]):
            value=self.run_advisory(baseline)
            self.assertFalse(value["order_changed"])
        for field,bad in (("eligible",False),("eligible",None),("selected",False),("approval_required",None),("policy",{"allowed":False})):
            baseline=options();baseline[0][field]=bad
            self.assertFalse(self.run_advisory(baseline)["order_changed"])

    def test_single_mapped_eligible_option_does_not_move_unmapped_slots(self):
        baseline=options()
        value=self.run_advisory(baseline,record(destination="T1021.002"))
        self.assertEqual(value["prioritized_options"],baseline)

    def test_abstention_errors_skip_and_unmapped_exact_destinations_preserve_order(self):
        forecasts=[record("abstained"),record(destination="T1059.001"),record(destination="T1078.001"),
                   empty_record("skipped_benign","skipped_benign"),empty_record("operational_error","forecast_timeout"),
                   empty_record("validation_error","invalid_input")]
        for value in forecasts:
            result=self.run_advisory(forecast=value)
            self.assertEqual(result["prioritized_options"],options())
            self.assertFalse(result["order_changed"])

    def test_valid_accounts_mapping_and_partial_limitations(self):
        baseline=options();baseline[0],baseline[2]=baseline[2],baseline[0]
        value=self.run_advisory(baseline,record("partial",destination="T1078"))
        self.assertTrue(value["order_changed"])
        self.assertEqual(value["prioritized_options"][0]["action"],"disable_user")
        self.assertTrue(value["limitations"])

    def test_eligibility_approval_probabilities_and_targets_are_byte_identical(self):
        baseline=options();value=self.run_advisory(baseline)
        before={o["option_id"]:canonical_json(o) for o in baseline}
        after={o["option_id"]:canonical_json(o) for o in value["prioritized_options"]}
        self.assertEqual(before,after)

    def test_reachable_only_target_is_not_used(self):
        baseline=options();baseline[2]["target_entity_id"]="host:fixture-file-server"
        value=self.run_advisory(baseline)
        self.assertEqual(value["reason"],"mapped_target_not_observed")
        self.assertEqual(value["prioritized_options"],baseline)

    def test_null_risk_and_criticality_metadata_are_never_zero_or_multiplied(self):
        value=record("partial");value.update(risk_score=None,behavioral_score_source="unknown",risk_score_may_include_asset_impact=None)
        before=deepcopy(value);answer=self.run_advisory(forecast=value)
        self.assertTrue(answer["order_changed"])
        self.assertIsNone(value["risk_score"]);self.assertEqual(value,before)
        baseline=options()
        for criticality in ("low","critical"):
            baseline[0]["asset_criticality"]=criticality
            forecast=record();self.assertEqual(forecast["risk_score"],72)
            result=self.run_advisory(baseline,forecast)
            self.assertEqual(forecast["risk_score"],72)
            self.assertEqual(result["prioritized_options"][2]["asset_criticality"],criticality)

    def test_duplicate_mapped_option_and_expired_forecast_preserve_order(self):
        baseline=options()+[deepcopy(options()[0])]
        self.assertFalse(self.run_advisory(baseline)["order_changed"])
        value=prioritize_response_options(options(),record(),now="2026-12-01T00:00:00Z")
        self.assertEqual(value["reason"],"invalid_or_expired_forecast")


class OrchestratorShadowLogTests(unittest.TestCase):
    def setUp(self):
        self.work=TemporaryDirectory(dir=PRIVATE_DIR,prefix="test-shadow-decisions-");self.addCleanup(self.work.cleanup)
        self.log=ShadowDecisionLog(Path(self.work.name)/"decisions")

    def test_summary_counts_statuses_reasons_changes_skips_and_errors(self):
        for forecast in (record(),record("partial"),record("abstained"),empty_record("skipped_benign","skipped_benign",alert_id="skip"),
                         empty_record("operational_error","forecast_timeout",alert_id="error")):
            item=self.log.record(forecast,options(),now=parse_time(AS_OF))
            self.assertEqual(item["mapping_version"],MAPPING_VERSION);self.assertEqual(item["mapping_hash"],MAPPING_HASH)
            self.assertEqual(item["executed_actions"],[])
        summary=self.log.summary()
        self.assertEqual(summary["forecast_status_counts"],{"complete":1,"partial":1,"abstained":1})
        self.assertEqual(summary["order_changed_count"],2)
        self.assertEqual(summary["skipped_incident_count"],1);self.assertEqual(summary["errored_incident_count"],1)
        self.assertEqual(summary["reason_counts"]["skipped_benign"],1)

    def test_replay_distinct_incident_counts_and_private_hashed_targets(self):
        value=empty_record("skipped_benign","skipped_benign",alert_id="same")
        for _ in range(2):self.log.record(value,options())
        self.assertEqual(self.log.summary()["skipped_decision_count"],2)
        self.assertEqual(self.log.summary()["skipped_incident_count"],1)
        text="".join(p.read_text() for p in self.log.directory.glob("*.json"))
        self.assertNotIn("fixture-admin",text);self.assertNotIn("fixture-workstation",text)

    def test_invalid_contract_and_corrupt_file_report_errors_without_actions(self):
        self.log.record({},options())
        (self.log.directory/"corrupt.json").write_text("{")
        summary=self.log.summary()
        self.assertEqual(summary["errored_incident_count"],0)
        self.assertEqual(summary["errored_decision_count"],1)
        self.assertEqual(summary["unbound_decision_count"],1)
        self.assertEqual(summary["invalid_log_file_count"],1)
        self.assertEqual(summary["executed_action_count"],0)

from contextlib import redirect_stdout
from datetime import timedelta
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from Prognostic_Agent.contracts import parse_time
from Prognostic_Agent.orchestrator_contract import empty_record
from Prognostic_Agent.orchestrator_shadow_log import ShadowDecisionLog, summarize_shadow_log, main
from Prognostic_Agent.private_paths import PRIVATE_DIR


class ShadowRangeTests(unittest.TestCase):
    def setUp(self):
        self.work=TemporaryDirectory(dir=PRIVATE_DIR,prefix="test-shadow-range-")
        self.addCleanup(self.work.cleanup)
        self.root=Path(self.work.name)
        self.log=ShadowDecisionLog(self.root/"log")
        for date,kind in (("2026-11-23T00:00:00Z","skipped_benign"),("2026-11-24T00:00:00Z","operational_error")):
            self.log.record(empty_record(kind,"skipped_benign" if kind=="skipped_benign" else "forecast_timeout",alert_id="fixture",analyst_revision="revision:"+date),[],now=parse_time(date))

    def test_range_is_start_inclusive_end_exclusive_and_queue_is_not_zero(self):
        summary=summarize_shadow_log(self.log.directory,start="2026-11-23T00:00:00Z",end="2026-11-24T00:00:00Z")
        self.assertEqual(summary["decision_count"],1)
        self.assertEqual(summary["skipped_decision_count"],1)
        self.assertEqual(summary["errored_decision_count"],0)
        self.assertFalse(summary["queue_counters"]["available"])
        self.assertNotIn("counts",summary["queue_counters"])
        with self.assertRaises(ValueError):summarize_shadow_log(self.log.directory,start="2026-11-24T00:00:00Z",end="2026-11-23T00:00:00Z")

    def test_command_includes_only_safe_snapshot_counters_and_labels_their_scope(self):
        status=self.root/"status.json"
        status.write_text(json.dumps({"prognostic_observer":{"mode":"shadow","environment":"test","queued":1,"capacity":64,"counts":{"accepted":9,"observer_queue_full":2,"fixture-sensitive-key":3}}}))
        stream=io.StringIO()
        with redirect_stdout(stream):
            self.assertEqual(main(["--directory",str(self.log.directory),"--start","2026-11-23T00:00:00Z","--end","2026-11-24T00:00:00Z","--queue-status-file",str(status)]),0)
        result=json.loads(stream.getvalue())
        self.assertEqual(result["queue_counters"]["scope"],"process_lifetime_not_date_filtered")
        self.assertEqual(result["queue_counters"]["counts"],{"accepted":9,"observer_queue_full":2})
        self.assertEqual(result["decision_count"],1)
        self.assertNotIn("fixture-sensitive-key",stream.getvalue())

    def test_disabled_or_mismatched_environment_snapshot_is_unavailable(self):
        for snapshot in ({},{"prognostic_observer":{"mode":"shadow","environment":"production"}}):
            self.assertFalse(summarize_shadow_log(self.log.directory,queue_status=snapshot)["queue_counters"]["available"])

    def test_reassessment_counts_distinct_revisions_and_notifications_separately(self):
        from Prognostic_Agent.tests.test_orchestrator_contract import record, AS_OF
        directory=self.root/"reassessments"
        log=ShadowDecisionLog(directory)
        for index,status in enumerate(("complete","partial","abstained")):
            value=record(status)
            log.record(value,[],now=parse_time(AS_OF)+timedelta(minutes=index))
        value=record("partial");value["analyst_revision"]+="-new"
        log.record(value,[],now=parse_time(AS_OF)+timedelta(minutes=3))
        summary=summarize_shadow_log(directory)
        self.assertEqual(summary["notification_count"],4)
        self.assertEqual(summary["distinct_incident_revision_count"],2)
        self.assertEqual(summary["forecast_status_counts"],{"abstained":1,"partial":1})
        self.assertEqual(summary["notification_status_counts"],{"complete":1,"partial":2,"abstained":1})
        self.assertEqual(summary["incident_count"],1)

    def test_missing_revision_is_reported_without_inventing_one(self):
        directory=self.root/"unknown"
        log=ShadowDecisionLog(directory)
        for _ in range(2):log.record(empty_record("skipped_benign","skipped_benign",alert_id="same"),[])
        summary=summarize_shadow_log(directory)
        self.assertEqual(summary["notification_count"],2)
        self.assertEqual(summary["distinct_incident_revision_count"],0)
        self.assertEqual(summary["revision_unavailable_notification_count"],2)
        self.assertEqual(summary["notification_skipped_count"],2)

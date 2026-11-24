"""Review-only test runner; machine-specific logs stay in private/test-runs.

--baseline-analyst loads HEAD's Analyst in memory, without changing the checkout,
to distinguish existing backend failures from additive-contract regressions.
"""

import argparse
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import ModuleType
import unittest


class ReportingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passed_tests = []

    def addSuccess(self, test):
        self.passed_tests.append(test.id())
        super().addSuccess(test)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", choices=["backend", "prognostic"])
    parser.add_argument("--baseline-analyst", action="store_true")
    args = parser.parse_args(argv)
    if args.baseline_analyst and args.suite != "backend":
        parser.error("Baseline is only for the unchanged backend tests")
    agent_dir = Path(__file__).resolve().parent
    root = agent_dir.parent
    directory = agent_dir / "private" / "test-runs" / "contract-review"
    directory.mkdir(parents=True, exist_ok=True)
    review_temp_dir = directory / "temporary"
    review_temp_dir.mkdir(exist_ok=True)
    tempfile.tempdir = str(review_temp_dir)
    os.environ.update(TEMP=str(review_temp_dir), TMP=str(review_temp_dir),
                      PYTHONDONTWRITEBYTECODE="1", SOC_DATABASE_PATH=":memory:", SOC_LLM_TRIAGE="off")
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root / "backend"))
    if str(root) not in sys.path:
        sys.path.insert(1, str(root))
    source_revision = None
    if args.baseline_analyst:
        source = subprocess.check_output(["git", "show", "HEAD:backend/analyst.py"], cwd=root, text=True, encoding="utf-8")
        source_revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        module = ModuleType("analyst")
        module.__file__ = str(root / "backend" / "analyst.py")
        sys.modules["analyst"] = module
        exec(compile(source, module.__file__, "exec"), module.__dict__)
    stream = io.StringIO()
    with redirect_stdout(stream), redirect_stderr(stream):
        loader = unittest.TestLoader()
        if args.suite == "backend":
            suite = loader.discover(str(root / "backend" / "tests"))
        else:
            suite = loader.discover(str(agent_dir / "tests"), top_level_dir=str(root))
        result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=ReportingResult).run(suite)
    label = args.suite + ("_baseline" if args.baseline_analyst else "_current")
    stem = directory / (label + "_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    log_path = stem.with_suffix(".log")
    log_path.write_text(stream.getvalue(), encoding="utf-8")
    report = {"suite": args.suite, "baseline_analyst": args.baseline_analyst,
              "baseline_revision": source_revision, "tests_run": result.testsRun,
              "failures": [{"test": test.id(), "traceback": trace} for test, trace in result.failures],
              "errors": [{"test": test.id(), "traceback": trace} for test, trace in result.errors],
              "skipped": [{"test": test.id(), "reason": reason} for test, reason in result.skipped],
              "passed_tests": result.passed_tests,
              "expected_failures": [{"test": test.id(), "traceback": trace,
                                     "reason": getattr(getattr(test, test._testMethodName), "expected_failure_reason", None)}
                                    for test, trace in result.expectedFailures],
              "unexpected_successes": [test.id() for test in result.unexpectedSuccesses],
              "successful": result.wasSuccessful(), "log_path": str(log_path)}
    report_path = stem.with_suffix(".json")
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"suite": label, "tests_run": result.testsRun, "failures": len(result.failures),
                      "errors": len(result.errors), "skipped": len(result.skipped),
                      "expected_failures": len(result.expectedFailures), "unexpected_successes": len(result.unexpectedSuccesses),
                      "report": str(report_path), "log": str(log_path)}, indent=2))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())

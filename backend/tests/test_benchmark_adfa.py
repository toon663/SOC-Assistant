"""Offline benchmark checks with tiny synthetic traces, not ADFA results."""

import csv
import json
from pathlib import Path
import tempfile
import unittest

from benchmark_adfa import average_precision, benchmark, load_dataset, select_threshold


class AdfaBenchmarkTests(unittest.TestCase):
    def fixture(self, root):
        samples = {
            "Training_Data_Master/train.txt": "1 2 1 2 1 2",
            "Validation_Data_Master/a.txt": "1 2 1 2",
            "Validation_Data_Master/b.txt": "2 1 2 1",
            "Validation_Data_Master/c.txt": "1 2 1 2 1",
            "Validation_Data_Master/d.txt": "2 1 2 1 2",
            "Attack_Data_Master/Example_1/attack.txt": "9 8 9 8",
        }
        for name, content in samples.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)

    def test_end_to_end_reports_actual_agent_scores_and_partial_traces(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            report = benchmark(root, root / "results")
            self.assertEqual(report["counts"]["test_attack"], 1)
            self.assertEqual(report["counts"]["calibration_benign"], 2)
            self.assertEqual(len(report["experiments"]), 4)
            self.assertEqual(json.loads((root / "results/report.json").read_text()), report)
            with (root / "results/predictions.csv").open(newline="") as stream:
                rows = list(csv.DictReader(stream))
            attack_rows = [row for row in rows if row["label"] == "1"]
            self.assertEqual([int(row["observed_calls"]) for row in attack_rows], [1, 2, 3, 4])
            for row in rows:
                self.assertEqual(float(row["prognostic_score"]), round(0.7 * float(row["detector_score"]), 2))
                self.assertEqual(float(row["confidence"]), 0.6)
            for experiment in report["experiments"]:
                self.assertEqual(experiment["detector"]["false_positive_rate"], 0)
                self.assertEqual(experiment["prognostic"]["recall"], 1)

    def test_duplicate_exclusion_and_conflicting_labels(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            (root / "Validation_Data_Master/duplicate.txt").write_text("1 2 1 2 1 2")
            self.assertEqual(load_dataset(root)[3], 1)
            (root / "Attack_Data_Master/conflict.txt").write_text("1 2 1 2 1 2")
            with self.assertRaisesRegex(ValueError, "conflicting"):
                load_dataset(root)

    def test_conflicts_are_removed_from_every_partition_when_explicitly_requested(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            (root / "Attack_Data_Master/conflict.txt").write_text("1 2 1 2")
            training, benign, attacks, duplicates, conflicts = load_dataset(root, True)
            self.assertEqual(conflicts, 1)
            self.assertEqual(len(benign), 3)
            self.assertEqual(len(attacks), 1)
            self.assertTrue(all(trace.calls != (1, 2, 1, 2) for trace in training + benign + attacks))

    def test_calibration_ties_and_average_precision(self):
        scores = [0.0] * 19 + [100.0]
        threshold = select_threshold(scores, 0.05)
        self.assertEqual(sum(score > threshold for score in scores), 1)
        self.assertEqual(average_precision([0, 1], [1, 1]), 0.5)
        self.assertEqual(average_precision([0, 1], [0, 1]), 1)


if __name__ == "__main__":
    unittest.main()

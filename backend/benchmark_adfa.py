"""Offline ADFA-LD baseline; does not collect live logs or execute responses."""

from __future__ import annotations

import argparse
from collections import Counter
import csv
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path

from agents import DemoExternalSystems, Incident, PrognosticAgent, SecurityEvent
from evaluation import classification_metrics


@dataclass(frozen=True)
class Trace:
    path: str
    calls: tuple[int, ...]
    label: int
    family: str
    digest: str


def load_dataset(root: Path, exclude_label_conflicts: bool = False) -> tuple[list[Trace], list[Trace], list[Trace], int, int]:
    """Read only the three ADFA-LD trace directories, excluding exact duplicates."""
    seen: dict[str, int] = {}
    duplicates = 0
    conflicts: set[str] = set()
    partitions = []
    for directory, label in (("Training_Data_Master", 0),
                             ("Validation_Data_Master", 0),
                             ("Attack_Data_Master", 1)):
        folder = root / directory
        if not folder.is_dir():
            raise ValueError(f"Missing {folder}; --data must name the extracted ADFA-LD root")
        traces = []
        for path in sorted(folder.rglob("*.txt")):
            try:
                calls = tuple(int(token) for token in path.read_text(encoding="utf-8-sig").split())
            except ValueError as exc:
                raise ValueError(f"Expected integer ADFA-LD system-call tokens in {path}") from exc
            if not calls or any(call < 0 for call in calls):
                raise ValueError(f"Empty or invalid system-call trace: {path}")
            digest = hashlib.sha256(" ".join(map(str, calls)).encode()).hexdigest()
            if digest in seen:
                if seen[digest] != label:
                    if not exclude_label_conflicts:
                        raise ValueError(f"Identical trace has conflicting benign/attack labels: {path}. "
                                         "Use --exclude-label-conflicts to exclude these contents from every split.")
                    conflicts.add(digest)
                duplicates += 1
                continue
            seen[digest] = label
            relative = path.relative_to(folder)
            # ADFA-LD run folders typically end in _1, _2, etc.; retain raw paths in CSV.
            run = relative.parts[0] if len(relative.parts) > 1 else "unknown"
            family = run.rsplit("_", 1)[0] if run.rsplit("_", 1)[-1].isdigit() else run
            traces.append(Trace(str(path.relative_to(root)), calls, label,
                                family if label else "benign", digest))
        if not traces:
            raise ValueError(f"No unique .txt traces found in {folder}")
        partitions.append(traces)
    partitions = [[trace for trace in traces if trace.digest not in conflicts] for traces in partitions]
    if any(not traces for traces in partitions):
        raise ValueError("A dataset partition is empty after excluding conflicting labels")
    return (*partitions, duplicates, len(conflicts))


class BigramBaseline:
    """Score the fraction of adjacent call pairs absent from benign training data."""

    def __init__(self, traces: list[Trace]):
        self.pairs = {pair for trace in traces for pair in zip(trace.calls, trace.calls[1:])}
        self.calls = {call for trace in traces for call in trace.calls}

    def score(self, calls: tuple[int, ...]) -> float:
        if len(calls) == 1:
            return 100.0 if calls[0] not in self.calls else 0.0
        return 100.0 * sum(pair not in self.pairs for pair in zip(calls, calls[1:])) / (len(calls) - 1)


def select_threshold(scores: list[float], target_fpr: float) -> float:
    """Use strict > threshold, including ties conservatively at the FPR boundary."""
    ordered = sorted(scores)
    return ordered[max(0, math.ceil((1 - target_fpr) * len(ordered)) - 1)]


def average_precision(labels: list[int], scores: list[float]) -> float:
    """Non-interpolated PR summary, grouping identical scores to avoid tie bias."""
    positives = sum(labels)
    if not positives:
        return 0.0
    groups: dict[float, Counter] = {}
    for label, score in zip(labels, scores):
        groups.setdefault(score, Counter())[label] += 1
    tp = total = 0
    result = 0.0
    for score in sorted(groups, reverse=True):
        group = groups[score]
        tp += group[1]
        total += sum(group.values())
        result += group[1] / positives * tp / total
    return result


def forecast(score: float, identity: str, agent: PrognosticAgent) -> dict:
    # Labels, paths, family names, and call counts never enter the agent.
    # The timestamp is a placeholder, not dataset time or an attack onset.
    event = SecurityEvent(identity, "1970-01-01T00:00:00Z", "adfa-ld",
                          "system_call_trace", host="adfa-host")
    incident = Incident(identity, [event], event.timestamp, anomaly_score=score,
                        risk_analysis={"risk_score": score})
    return agent.forecast_risk(incident).forecast


def benchmark(root: Path, output: Path, target_fpr: float = 0.05,
              exclude_label_conflicts: bool = False) -> dict:
    if not 0 < target_fpr < 1:
        raise ValueError("--target-fpr must be between 0 and 1")
    training, benign, attacks, duplicates, conflicts = load_dataset(root, exclude_label_conflicts)
    # Split complete benign traces by content hash; all prefixes inherit that split.
    benign = sorted(benign, key=lambda trace: trace.digest)
    if len(benign) < 2:
        raise ValueError("At least two unique validation traces are required")
    cut = len(benign) // 2
    calibration, test_benign = benign[:cut], benign[cut:]
    test = test_benign + attacks
    model = BigramBaseline(training)
    agent = PrognosticAgent(DemoExternalSystems())
    report = {
        "dataset": "ADFA-LD", "baseline": "unseen adjacent system-call pair fraction",
        "counts": {"training_benign": len(training), "calibration_benign": len(calibration),
                   "test_benign": len(test_benign), "test_attack": len(attacks),
                   "exact_duplicate_traces_excluded": duplicates},
        "conflicting_unique_trace_contents_excluded": conflicts,
        "exclude_label_conflicts": exclude_label_conflicts,
        "target_calibration_fpr": target_fpr,
        "decision_rule": "score > threshold",
        "limitations": [
            "Partial-trace attack classification; not time-to-attack forecasting.",
            "No IP evidence: prognostic score is 0.7 times the detector score (rounded).",
            "Risk paths are fixed templates; confidence is not a calibrated probability.",
            "Splits remove exact duplicate traces; related benign sessions may remain.",
            "Attack-family labels are inferred from directory names; inspect predictions.csv.",
        ],
        "experiments": [],
    }
    rows = []
    for fraction in (0.25, 0.5, 0.75, 1.0):
        def prefix(trace: Trace) -> tuple[int, ...]:
            return trace.calls[:max(1, math.ceil(len(trace.calls) * fraction))]

        calibration_scores = [model.score(prefix(trace)) for trace in calibration]
        calibration_forecasts = [forecast(score, f"cal-{i}", agent)["forecast_score"]
                                 for i, score in enumerate(calibration_scores)]
        threshold = select_threshold(calibration_scores, target_fpr)
        prognostic_threshold = select_threshold(calibration_forecasts, target_fpr)
        labels, scores, prognostic_scores = [], [], []
        for trace in test:
            calls = prefix(trace)
            score = model.score(calls)
            result = forecast(score, trace.digest, agent)
            projected = result["forecast_score"]
            labels.append(trace.label)
            scores.append(score)
            prognostic_scores.append(projected)
            rows.append({"trace": trace.path, "label": trace.label, "family": trace.family,
                         "fraction": fraction, "observed_calls": len(calls),
                         "detector_score": score, "prognostic_score": projected,
                         "detector_prediction": int(score > threshold),
                         "prognostic_prediction": int(projected > prognostic_threshold),
                         "risk_path": " | ".join(result["risk_path"]),
                         "confidence": result["confidence"]})
        experiment = {"fraction": fraction}
        for name, values, boundary, calibration_values in (
            ("detector", scores, threshold, calibration_scores),
            ("prognostic", prognostic_scores, prognostic_threshold, calibration_forecasts),
        ):
            predictions = [int(score > boundary) for score in values]
            family_recall = {}
            for family in sorted({trace.family for trace in attacks}):
                indices = [i for i, trace in enumerate(test) if trace.label and trace.family == family]
                family_recall[family] = {"traces": len(indices),
                                         "recall": sum(predictions[i] for i in indices) / len(indices)}
            experiment[name] = {
                "threshold": boundary,
                "calibration_fpr": sum(score > boundary for score in calibration_values) / len(calibration_values),
                **classification_metrics(labels, predictions),
                "average_precision": average_precision(labels, values),
                "attack_family_recall": family_recall,
            }
        report["experiments"].append(experiment)
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    with (output / "predictions.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True, help="Extracted ADFA-LD root")
    parser.add_argument("--output", type=Path, default=Path("benchmark-results/adfa-ld"))
    parser.add_argument("--target-fpr", type=float, default=0.05)
    parser.add_argument("--exclude-label-conflicts", action="store_true",
                        help="Exclude contents found under both benign and attack labels from all splits")
    args = parser.parse_args()
    try:
        report = benchmark(args.data, args.output, args.target_fpr, args.exclude_label_conflicts)
    except (ValueError, OSError) as exc:
        parser.exit(2, f"ADFA benchmark error: {exc}\n")
    print(json.dumps(report["counts"], indent=2))
    print(f"Conflicting unique trace contents excluded: {report['conflicting_unique_trace_contents_excluded']}")
    for experiment in report["experiments"]:
        for name in ("detector", "prognostic"):
            metrics = experiment[name]
            print(f"{experiment['fraction']:.0%} {name}: recall={metrics['recall']:.3f} "
                  f"FPR={metrics['false_positive_rate']:.3f} F1={metrics['f1']:.3f} "
                  f"AP={metrics['average_precision']:.3f}")
    print(f"Results: {args.output.resolve()}")


if __name__ == "__main__":
    main()

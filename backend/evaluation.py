"""Evaluation metrics for detection, triage, and response quality."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Iterable, Mapping, Sequence


def _validate_labels(y_true: Sequence[Any], y_pred: Sequence[Any]) -> None:
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must have the same length")
    if not y_true:
        raise ValueError("at least one label is required")


def confusion_counts(y_true: Sequence[Any], y_pred: Sequence[Any]) -> dict[str, int]:
    """Return TP, TN, FP, and FN for binary labels."""
    _validate_labels(y_true, y_pred)
    values = {True, False, 0, 1}
    if any(value not in values for value in y_true) or any(value not in values for value in y_pred):
        raise ValueError("labels must be binary: 0/1 or False/True")
    pairs = [(bool(actual), bool(predicted)) for actual, predicted in zip(y_true, y_pred)]
    return {
        "tp": sum(actual and predicted for actual, predicted in pairs),
        "tn": sum(not actual and not predicted for actual, predicted in pairs),
        "fp": sum(not actual and predicted for actual, predicted in pairs),
        "fn": sum(actual and not predicted for actual, predicted in pairs),
    }


def _safe_divide(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def classification_metrics(y_true: Sequence[Any], y_pred: Sequence[Any]) -> dict[str, float]:
    counts = confusion_counts(y_true, y_pred)
    tp, tn, fp, fn = (counts[key] for key in ("tp", "tn", "fp", "fn"))
    precision = _safe_divide(tp, tp + fp)
    recall = _safe_divide(tp, tp + fn)
    return {
        **counts,
        "accuracy": _safe_divide(tp + tn, tp + tn + fp + fn),
        "precision": precision,
        "recall": recall,
        "f1": _safe_divide(2 * precision * recall, precision + recall),
        "false_positive_rate": _safe_divide(fp, fp + tn),
    }


def alert_reduction_rate(initial_alerts: int, final_alerts: int) -> float:
    """Percentage of alerts removed or consolidated by the pipeline."""
    if initial_alerts < 0 or final_alerts < 0:
        raise ValueError("alert counts cannot be negative")
    if final_alerts > initial_alerts:
        raise ValueError("final_alerts cannot exceed initial_alerts")
    return _safe_divide(initial_alerts - final_alerts, initial_alerts) * 100


def mean_time_to_resolution(durations_seconds: Iterable[float]) -> float:
    durations = list(durations_seconds)
    if any(duration < 0 for duration in durations):
        raise ValueError("durations cannot be negative")
    return _safe_divide(sum(durations), len(durations))


def action_safety_rate(action_results: Iterable[Mapping[str, Any]]) -> float:
    """Percentage of actions that were approved and successfully confirmed."""
    results = list(action_results)
    if not results:
        return 0.0
    safe = sum(
        result.get("status") in {"executed", "confirmed", "simulated"}
        and result.get("approved", True)
        for result in results
    )
    return safe / len(results) * 100


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def incident_resolution_seconds(opened_at: str, resolved_at: str) -> float:
    duration = (parse_timestamp(resolved_at) - parse_timestamp(opened_at)).total_seconds()
    if duration < 0:
        raise ValueError("resolved_at cannot precede opened_at")
    return duration


@dataclass
class EvaluationReport:
    """Combined evaluation report suitable for a dashboard or experiment log."""

    classification: dict[str, float]
    alert_reduction_percent: float
    mttr_seconds: float
    action_safety_percent: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_report(
    y_true: Sequence[Any],
    y_pred: Sequence[Any],
    *,
    initial_alerts: int,
    final_alerts: int,
    resolution_times_seconds: Iterable[float],
    action_results: Iterable[Mapping[str, Any]],
) -> EvaluationReport:
    return EvaluationReport(
        classification=classification_metrics(y_true, y_pred),
        alert_reduction_percent=alert_reduction_rate(initial_alerts, final_alerts),
        mttr_seconds=mean_time_to_resolution(resolution_times_seconds),
        action_safety_percent=action_safety_rate(action_results),
    )

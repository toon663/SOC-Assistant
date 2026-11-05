"""Local ML baselines for detection, triage, deduplication, and forecasting.

These implementations are dependency-free demonstrations. In production,
replace the detector with Isolation Forest, the triage model with XGBoost or
another calibrated classifier, and persist/version trained model artifacts.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import math
import statistics
from typing import Any, Iterable, Mapping, Sequence


@dataclass(frozen=True)
class AnomalyResult:
    score: float
    is_anomaly: bool
    reason: str


class AnomalyDetector:
    """Robust z-score detector over numeric telemetry features."""

    def __init__(self, threshold: float = 2.5):
        if threshold <= 0:
            raise ValueError("threshold must be positive")
        self.threshold = threshold
        self._baseline: dict[str, tuple[float, float]] = {}

    def fit(self, rows: Iterable[Mapping[str, float]]) -> "AnomalyDetector":
        rows = list(rows)
        if not rows:
            raise ValueError("at least one baseline row is required")
        keys = set().union(*(row.keys() for row in rows))
        for key in keys:
            values = [float(row[key]) for row in rows if key in row]
            if values:
                mean = statistics.mean(values)
                deviation = statistics.pstdev(values) or 1.0
                self._baseline[key] = (mean, deviation)
        return self

    def score(self, row: Mapping[str, float]) -> AnomalyResult:
        if not self._baseline:
            raise RuntimeError("detector must be fitted before scoring")
        z_scores = [
            abs((float(row[key]) - mean) / deviation)
            for key, (mean, deviation) in self._baseline.items()
            if key in row
        ]
        if not z_scores:
            return AnomalyResult(0.0, False, "no known features")
        maximum = max(z_scores)
        normalized = min(100.0, maximum / self.threshold * 100)
        return AnomalyResult(
            round(normalized, 2),
            maximum >= self.threshold,
            f"maximum feature z-score={maximum:.2f}",
        )


class AlertTriageModel:
    """Explainable weighted triage baseline for alert prioritization."""

    weights = {
        "severity": 0.35,
        "asset_criticality": 0.25,
        "threat_intel": 0.20,
        "repetition": 0.10,
        "confidence": 0.10,
    }

    def predict(self, features: Mapping[str, float]) -> dict[str, Any]:
        score = sum(self.weights[name] * float(features.get(name, 0)) for name in self.weights)
        score = max(0.0, min(100.0, score))
        priority = "critical" if score >= 85 else "high" if score >= 65 else "medium" if score >= 40 else "low"
        contributions = {
            name: round(self.weights[name] * float(features.get(name, 0)), 2)
            for name in self.weights
        }
        return {"risk_score": round(score, 2), "priority": priority, "contributions": contributions}


class EventDeduplicator:
    """Fingerprint alerts to reduce repeated SOC notifications."""

    def fingerprint(self, event: Mapping[str, Any]) -> str:
        fields = [
            str(event.get("event_type", "")),
            str(event.get("user", "")),
            str(event.get("host", "")),
            str(event.get("source_ip", "")),
            str(event.get("destination", "")),
        ]
        return hashlib.sha256("|".join(fields).lower().encode()).hexdigest()

    def deduplicate(self, events: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
        unique: dict[str, Mapping[str, Any]] = {}
        for event in events:
            unique.setdefault(self.fingerprint(event), event)
        return list(unique.values())


class RiskForecaster:
    """Simple bounded risk projection for a future time horizon."""

    def predict(self, current_score: float, threat_velocity: float = 0.0, horizon_hours: float = 1.0) -> dict[str, float]:
        if not 0 <= current_score <= 100:
            raise ValueError("current_score must be between 0 and 100")
        if horizon_hours < 0:
            raise ValueError("horizon_hours cannot be negative")
        projected = max(0.0, min(100.0, current_score + threat_velocity * horizon_hours))
        return {"current_score": round(current_score, 2), "projected_score": round(projected, 2), "horizon_hours": horizon_hours}

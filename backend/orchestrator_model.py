"""The Orchestrator agent's trained response model.

A multi-label neural network (scikit-learn ``MLPClassifier``) that reads what the
Orchestrator knows about an incident (the Analyst's triage, the Prognostic
forecast, business impact, ATT&CK tactics, and which targets exist) and gives a
probability for each response action in ``playbooks.ACTIONS``.

It is trained offline by Orchestrator_Agent/train_orchestrator.py on OTRF
Security-Datasets (Mordor) recordings replayed through this pipeline, labeled
with MITRE D3FEND countermeasures. Online, ``learn`` applies ``partial_fit``
with each human approve/deny decision, so analysts keep teaching it.

The same ``incident_features`` function is used for training and inference.
scikit-learn is imported lazily; without it or without a model file the
Orchestrator falls back to its rule thresholds.
"""

from __future__ import annotations

import json
import logging
import math
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional

from playbooks import ACTIONS, targets_for

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENT_DIR = REPO_ROOT / "Orchestrator_Agent"
DEFAULT_MODEL_PATH = Path(os.getenv("SOC_ORCHESTRATOR_MODEL", AGENT_DIR / "models" / "orchestrator_mlp.joblib"))
FEEDBACK_PATH = AGENT_DIR / "feedback" / "decisions.jsonl"

SEVERITY_POINTS = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 0.95}
log = logging.getLogger(__name__)


def _techniques(incident: Any) -> tuple[list[str], list[str]]:
    analysis = incident.risk_analysis or {}
    confirmed = [str(t) for t in analysis.get("mitre_techniques") or []]
    candidates = [str(t) for t in (incident.alert or {}).get("mitre_techniques") or []]
    return confirmed, candidates


def incident_features(incident: Any, tactic_map: Mapping[str, Iterable[str]]) -> Dict[str, float]:
    """Sparse features for one incident; unknown keys are ignored by a trained vectorizer."""
    analysis = incident.risk_analysis or {}
    forecast = incident.forecast or {}
    impact = incident.business_impact or {}
    primary = incident.events[0]
    meta = primary.metadata or {}
    targets = targets_for(incident)

    features: Dict[str, float] = {
        f"verdict={analysis.get('verdict', 'none')}": 1.0,
        f"priority={analysis.get('priority', 'none')}": 1.0,
        f"category={analysis.get('category', 'none')}": 1.0,
        f"rule={analysis.get('rule', 'none')}": 1.0,
        f"event_type={primary.event_type}": 1.0,
        f"log={str(meta.get('log_name', primary.source)).lower()}": 1.0,
        "triage_score": float(analysis.get("risk_score", 0)) / 100,
        "triage_confidence": float(analysis.get("confidence", 0)),
        "anomaly_score": float(incident.anomaly_score or 0) / 100,
        "detector_score": float(primary.detector_score or 0),
        "severity": SEVERITY_POINTS.get(getattr(primary.severity, "value", primary.severity), 0.25),
        "forecast_score": float(forecast.get("forecast_score", 0)) / 100,
        "forecast_confidence": float(forecast.get("confidence", 0)),
        "impact_score": float(impact.get("impact_score", 0)) / 100,
        "critical_asset": 1.0 if impact.get("criticality") == "high" else 0.0,
        "occurrences": math.log1p(float((incident.alert or {}).get("occurrence_count") or len(incident.events))) / 5,
        "correlations": min(len(analysis.get("correlations") or []), 5) / 5,
        "candidate_techniques": min(len(_techniques(incident)[1]), 20) / 20,
    }
    for name, value in targets.items():
        features[f"has_{name}"] = 1.0 if value else 0.0
    confirmed, candidates = _techniques(incident)
    for weight, techniques in ((0.5, candidates), (1.0, confirmed)):
        for technique in techniques:
            for tactic in tactic_map.get(technique) or tactic_map.get(technique.split(".")[0]) or []:
                features[f"tactic={tactic}"] = max(features.get(f"tactic={tactic}", 0.0), weight)
    for technique in confirmed:
        features[f"technique={technique.split('.')[0]}"] = 1.0
    for step in forecast.get("risk_path") or []:
        features[f"path={str(step).lower()}"] = 1.0
    return features


class ResponseModel:
    """A loaded model bundle: vectorizer, network, per-action thresholds, tactic map."""

    def __init__(self, bundle: Dict[str, Any], path: Optional[Path] = None):
        if tuple(bundle["actions"]) != ACTIONS:
            raise ValueError(f"model actions {bundle['actions']} do not match {ACTIONS}")
        self.bundle = bundle
        self.path = path
        self._lock = threading.Lock()

    @classmethod
    def load(cls, path: Path = DEFAULT_MODEL_PATH) -> Optional["ResponseModel"]:
        if not Path(path).exists():
            log.warning("No Orchestrator model at %s; using rule thresholds. Train it with Orchestrator_Agent/train_orchestrator.py", path)
            return None
        try:
            import joblib
            return cls(joblib.load(path), Path(path))
        except Exception:  # a broken or incompatible model must not stop the pipeline
            log.exception("Could not load the Orchestrator model at %s; using rule thresholds", path)
            return None

    @property
    def thresholds(self) -> Dict[str, float]:
        return dict(self.bundle["thresholds"])

    @property
    def info(self) -> Dict[str, Any]:
        return {
            "name": self.bundle.get("name", "orchestrator_mlp"),
            "trained_at": self.bundle.get("trained_at"),
            "training_data": self.bundle.get("training_data"),
            "online_updates": self.bundle.get("online_updates", 0),
        }

    def features(self, incident: Any) -> Dict[str, float]:
        return incident_features(incident, self.bundle["tactic_map"])

    def score(self, incident: Any) -> Dict[str, float]:
        with self._lock:
            matrix = self.bundle["vectorizer"].transform([self.features(incident)])
            probabilities = self.bundle["model"].predict_proba(matrix)[0]
        return {action: float(p) for action, p in zip(ACTIONS, probabilities)}

    def learn(self, features: Mapping[str, float], labels: Mapping[str, int], *, save: bool = True) -> None:
        """One online step from a human decision; labels missing an action keep the current prediction."""
        with self._lock:
            matrix = self.bundle["vectorizer"].transform([dict(features)])
            current = self.bundle["model"].predict_proba(matrix)[0]
            target = [[int(labels[a]) if a in labels else int(p >= self.bundle["thresholds"][a]) for a, p in zip(ACTIONS, current)]]
            self.bundle["model"].partial_fit(matrix, target)
            self.bundle["online_updates"] = self.bundle.get("online_updates", 0) + 1
            if save and self.path is not None:
                import joblib
                temp = self.path.with_suffix(".tmp")
                joblib.dump(self.bundle, temp)
                os.replace(temp, self.path)


def record_feedback(features: Mapping[str, float], labels: Mapping[str, int], decision: Mapping[str, Any], path: Optional[Path] = None) -> None:
    """Append a human decision so the next full retrain includes it."""
    path = path or FEEDBACK_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "features": dict(features),
        "labels": dict(labels),
        "decision": dict(decision),
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")

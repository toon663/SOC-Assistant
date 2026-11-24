"""Train the Orchestrator agent's response model.

A multi-label neural network (scikit-learn MLPClassifier) that predicts which
response actions an incident needs. Input: data/orchestrator_dataset.jsonl from
build_dataset.py (Mordor attacks), data/witfoo_dataset.jsonl from
build_witfoo_dataset.py (production traffic that needs no containment) and
data/malware_dataset.jsonl from build_malware_dataset.py (EMBER2024 files) when built,
and any analyst decisions in feedback/decisions.jsonl (weighted higher, since a
person confirmed them).

Besides Mordor metrics, it reports the false-containment rate on held-out WitFoo
host-days for this model, the former rules, and the previous model on disk.

Evaluation holds out whole recordings (GroupKFold), so a score reflects attacks
the model has not seen. Per-action thresholds are tuned on those held-out
predictions. The old score-threshold rules are evaluated on the same folds as a
baseline.

Outputs (models/): orchestrator_mlp.joblib, orchestrator_metrics.json.

Usage (from the repository root):
    python Orchestrator_Agent/train_orchestrator.py
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
from sklearn.exceptions import ConvergenceWarning
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import GroupKFold
from sklearn.neural_network import MLPClassifier

AGENT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(AGENT_DIR.parent / "backend"))

from orchestrator_model import FEEDBACK_PATH  # noqa: E402
from playbooks import ACTIONS  # noqa: E402

DATA_DIR = AGENT_DIR / "data"
MODELS_DIR = AGENT_DIR / "models"
FEEDBACK_WEIGHT = 3.0
THRESHOLD_GRID = np.round(np.arange(0.3, 0.91, 0.05), 2)


def load_rows(datasets: list[Path], feedback: Path) -> tuple[list[dict], list[list[int]], list[str], list[float], list[str]]:
    features, labels, groups, weights, sources = [], [], [], [], []
    for dataset in datasets:
        for line in dataset.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if row.get("source") == "witfoo" and row.get("verdict") == "malicious":
                continue  # our Analyst and WitFoo's engine disagree outright; trust neither label
            features.append(row["features"])
            labels.append([int(row["labels"][a]) for a in ACTIONS])
            groups.append(row["recording"])
            weights.append(1.0)
            sources.append(row.get("source", "mordor"))
    if feedback.exists():
        for number, line in enumerate(feedback.read_text(encoding="utf-8").splitlines()):
            entry = json.loads(line)
            if not all(a in entry["labels"] for a in ACTIONS):
                continue  # a denial only labels the rejected actions; it is used online, not here
            features.append(entry["features"])
            labels.append([int(entry["labels"][a]) for a in ACTIONS])
            groups.append(f"feedback-{number}")
            weights.append(FEEDBACK_WEIGHT)
            sources.append("feedback")
    return features, labels, groups, weights, sources


def false_containment(predicted: np.ndarray) -> dict:
    """On WitFoo production traffic every label is 'no action': any proposal is a false alarm."""
    result = {
        "incidents": int(len(predicted)),
        "false_containment_rate": round(float(predicted.any(axis=1).mean()), 4) if len(predicted) else 0.0,
    }
    for index, action in enumerate(ACTIONS):
        result[f"{action}_rate"] = round(float(predicted[:, index].mean()), 4) if len(predicted) else 0.0
    return result


def previous_model_predictions(features: list[dict]) -> Optional[np.ndarray]:
    """The model on disk before this run, for a before/after comparison."""
    path = MODELS_DIR / "orchestrator_mlp.joblib"
    if not path.exists():
        return None
    bundle = joblib.load(path)
    probabilities = bundle["model"].predict_proba(bundle["vectorizer"].transform(features))
    return np.column_stack([probabilities[:, i] >= bundle["thresholds"][a] for i, a in enumerate(ACTIONS)]).astype(int)


def balance(y: np.ndarray, weights: np.ndarray, sources: np.ndarray) -> np.ndarray:
    """Give each dataset the same total weight, then up-weight incidents that need any action.

    Without this, the largest or most uniform dataset decides what the model learns.
    """
    weights = weights.copy()
    datasets = [s for s in np.unique(sources) if s != "feedback"]
    for source in datasets:
        rows = sources == source
        weights[rows] *= (~(sources == "feedback")).sum() / (len(datasets) * rows.sum())
    positive = y.any(axis=1)
    if positive.any() and (~positive).any():
        ratio = min(5.0, (~positive).sum() / positive.sum())
        return weights * np.where(positive, ratio, 1.0)
    return weights


def tune_threshold(y: np.ndarray, probabilities: np.ndarray, sources: np.ndarray) -> float:
    """Best mean F1 across the datasets that contain this action.

    Each dataset is scored together with the WitFoo production traffic, so a
    threshold that fires on ordinary activity is penalized everywhere.
    """
    restraint = sources == "witfoo"
    datasets = [s for s in np.unique(sources) if s != "witfoo" and y[sources == s].any()]

    def objective(t: float) -> float:
        values = []
        for source in datasets:
            rows = (sources == source) | restraint
            values.append(f1_score(y[rows], probabilities[rows] >= t, zero_division=0))
        return float(np.mean(values))

    return float(max(THRESHOLD_GRID, key=lambda t: (objective(t), t)))


def new_network(seed: int) -> MLPClassifier:
    return MLPClassifier(
        hidden_layer_sizes=(64, 32), activation="relu", alpha=1e-3,
        learning_rate_init=1e-3, max_iter=600, random_state=seed,
    )


def fit(model: MLPClassifier, x, y: np.ndarray, weights: np.ndarray) -> MLPClassifier:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ConvergenceWarning)
        try:
            return model.fit(x, y, sample_weight=weights)
        except TypeError:  # scikit-learn without MLP sample weights
            return model.fit(x, y)


def rules_baseline(features: list[dict]) -> np.ndarray:
    """The Orchestrator's former thresholds: isolate at 60, also disable the user at 85."""
    out = []
    for f in features:
        score = max(f.get("forecast_score", 0), f.get("impact_score", 0)) * 100
        out.append([
            int(score >= 60 and f.get("has_host", 0) > 0),
            int(score >= 85 and f.get("has_user", 0) > 0),
            0,
            0,
        ])
    return np.array(out)


def scores(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    per_action = {}
    for index, action in enumerate(ACTIONS):
        support = int(y_true[:, index].sum())
        per_action[action] = {
            "support": support,
            "predicted": int(y_pred[:, index].sum()),
            "precision": round(float(precision_score(y_true[:, index], y_pred[:, index], zero_division=0)), 4),
            "recall": round(float(recall_score(y_true[:, index], y_pred[:, index], zero_division=0)), 4),
            "f1": round(float(f1_score(y_true[:, index], y_pred[:, index], zero_division=0)), 4),
        }
    return {
        "per_action": per_action,
        "micro_f1": round(float(f1_score(y_true, y_pred, average="micro", zero_division=0)), 4),
        "macro_f1_learnable": round(float(np.mean([v["f1"] for v in per_action.values() if v["support"]] or [0])), 4),
        "exact_plan_match": round(float((y_true == y_pred).all(axis=1).mean()), 4),
        # Proposing a disruptive action the labels do not call for.
        "over_response_rate": round(float(((y_pred == 1) & (y_true == 0)).any(axis=1).mean()), 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--datasets", type=Path, nargs="+",
        default=[p for p in (DATA_DIR / "orchestrator_dataset.jsonl", DATA_DIR / "witfoo_dataset.jsonl", DATA_DIR / "malware_dataset.jsonl") if p.exists()],
        help="built datasets (default: Mordor, plus WitFoo when built)",
    )
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    features, labels, groups, weights, sources = load_rows(args.datasets, FEEDBACK_PATH)
    sources_arr = np.array(sources)
    y = np.array(labels)
    groups_arr = np.array(groups)
    sample_weights = balance(y, np.array(weights), sources_arr)
    print(f"{len(features)} incidents from {len(set(groups))} recordings/decisions")
    print("Incidents per source:", dict(Counter(sources)))
    print("Positives per action:", dict(zip(ACTIONS, y.sum(axis=0).tolist())))
    previous = previous_model_predictions(features)

    folds = GroupKFold(n_splits=min(args.folds, len(set(groups))))
    held_out = np.zeros_like(y, dtype=float)
    for fold, (train, test) in enumerate(folds.split(features, y, groups_arr), 1):
        vectorizer = DictVectorizer(sparse=True)
        x_train = vectorizer.fit_transform([features[i] for i in train])
        x_test = vectorizer.transform([features[i] for i in test])
        model = fit(new_network(args.seed), x_train, y[train], sample_weights[train])
        held_out[test] = model.predict_proba(x_test)
        print(f"  fold {fold}: trained on {len(train)}, tested on {len(test)}")

    thresholds = {}
    for index, action in enumerate(ACTIONS):
        if y[:, index].sum() == 0:
            thresholds[action] = 0.9  # never seen positive in training: stay conservative
            continue
        thresholds[action] = tune_threshold(y[:, index], held_out[:, index], sources_arr)
    predicted = np.column_stack([held_out[:, i] >= thresholds[a] for i, a in enumerate(ACTIONS)]).astype(int)

    mordor = sources_arr == "mordor"
    witfoo = sources_arr == "witfoo"
    baseline = rules_baseline(features)
    data_names = ["OTRF Security-Datasets (Mordor) Windows atomic recordings, labeled with MITRE D3FEND countermeasures"]
    if witfoo.any():
        data_names.append("WitFoo Precinct6 production Windows traffic as no-containment examples")
    ember = sources_arr == "ember"
    if ember.any():
        data_names.append("EMBER2024 test-set files scored by Sentinel's scanner (malware and false alarms)")
    metrics = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "training_data": "; ".join(data_names),
        "incidents": len(features),
        "incidents_per_source": dict(Counter(sources)),
        "recordings": len({g for g in groups if not g.startswith("feedback-")}),
        "analyst_decisions": sum(1 for g in groups if g.startswith("feedback-")),
        "evaluation": f"{folds.get_n_splits()}-fold GroupKFold, whole recordings / host-days held out",
        "thresholds": thresholds,
        "model": scores(y[mordor], predicted[mordor]),
        "rules_baseline": scores(y[mordor], baseline[mordor]),
    }
    if witfoo.any():
        metrics["witfoo_production_traffic"] = {
            "model": false_containment(predicted[witfoo]),
            "rules_baseline": false_containment(baseline[witfoo]),
        }
        if previous is not None:
            metrics["witfoo_production_traffic"]["previous_model"] = false_containment(previous[witfoo])
    if ember.any():
        # Malware rows always carry a label; files the scanner flagged by mistake carry none.
        malware = ember & y.any(axis=1)
        false_alarm = ember & ~y.any(axis=1)
        metrics["ember_malware_held_out_families"] = {"model": scores(y[malware], predicted[malware]), "rules_baseline": scores(y[malware], baseline[malware])}
        metrics["ember_false_alarm_files"] = {"model": false_containment(predicted[false_alarm]), "rules_baseline": false_containment(baseline[false_alarm])}
        if previous is not None:
            metrics["ember_malware_held_out_families"]["previous_model"] = scores(y[malware], previous[malware])
            metrics["ember_false_alarm_files"]["previous_model"] = false_containment(previous[false_alarm])

    vectorizer = DictVectorizer(sparse=True)
    x_all = vectorizer.fit_transform(features)
    model = fit(new_network(args.seed), x_all, y, sample_weights)
    tactic_map = json.loads((DATA_DIR / "tactic_map.json").read_text(encoding="utf-8"))
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "name": "orchestrator_mlp",
        "actions": list(ACTIONS),
        "vectorizer": vectorizer,
        "model": model,
        "thresholds": thresholds,
        "tactic_map": tactic_map,
        "trained_at": metrics["trained_at"],
        "training_data": metrics["training_data"],
        "online_updates": 0,
    }, MODELS_DIR / "orchestrator_mlp.joblib")
    (MODELS_DIR / "orchestrator_metrics.json").write_text(json.dumps(metrics, indent=2))

    print("\nThresholds:", thresholds)
    print("\nMordor attack recordings (held out):")
    for name in ("model", "rules_baseline"):
        result = metrics[name]
        print(f"\n{name}: micro F1 {result['micro_f1']}, exact plan {result['exact_plan_match']}, over-response {result['over_response_rate']}")
        for action, values in result["per_action"].items():
            print(f"  {action:17} support {values['support']:5}  P {values['precision']:.3f}  R {values['recall']:.3f}  F1 {values['f1']:.3f}")
    if "witfoo_production_traffic" in metrics:
        print("\nWitFoo production traffic (held-out host-days), share of incidents given a containment action:")
        for name, result in metrics["witfoo_production_traffic"].items():
            print(f"  {name:15} {result['false_containment_rate']:.3f}  ({result['incidents']} incidents)")
    if "ember_malware_held_out_families" in metrics:
        print("\nEMBER2024 malware, held-out families (quarantine_file / isolate_endpoint):")
        for name, result in metrics["ember_malware_held_out_families"].items():
            q, i = result["per_action"]["quarantine_file"], result["per_action"]["isolate_endpoint"]
            print(f"  {name:15} quarantine P {q['precision']:.3f} R {q['recall']:.3f} F1 {q['f1']:.3f} | isolate R {i['recall']:.3f}  ({q['support']} files)")
        print("Benign files the scanner flagged by mistake, share given any action / quarantine:")
        for name, result in metrics["ember_false_alarm_files"].items():
            print(f"  {name:15} {result['false_containment_rate']:.3f} / {result['quarantine_file_rate']:.3f}  ({result['incidents']} files)")
    print(f"\nSaved {MODELS_DIR / 'orchestrator_mlp.joblib'}")


if __name__ == "__main__":
    main()

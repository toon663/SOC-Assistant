"""Windows-specific rule and anomaly detection. Train anomaly model on a baseline dataset."""
from pathlib import Path
import joblib, numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from config import WINDOWS_ISO_PATH, WINDOWS_META_PATH
from soc.event_normalizer import feature_frame, normalise_events

def rule_score(row):
    score, reasons = 0, []
    eid = int(row.event_id)
    if eid == 4625: score += 25; reasons.append("Failed logon")
    if eid == 4672: score += 15; reasons.append("Special privileges assigned")
    if eid in (4720,4732): score += 30; reasons.append("Account or group membership change")
    if eid in (1102,): score += 45; reasons.append("Security audit log cleared")
    if eid in (4697,7045): score += 35; reasons.append("Service installation")
    if int(row.suspicious_keyword): score += 25; reasons.append("Suspicious command/process keyword")
    if int(row.is_process_create) and int(row.suspicious_keyword): score += 20; reasons.append("Suspicious process creation")
    return min(score,100), reasons

def train_windows_baseline(events_df, contamination=0.03):
    norm = normalise_events(events_df)
    if len(norm) < 30:
        raise ValueError("At least 30 baseline Windows events are required to train the anomaly model.")
    X = feature_frame(norm)
    model = Pipeline([("scale", StandardScaler()),
                      ("iforest", IsolationForest(n_estimators=200, contamination=contamination,
                                                  random_state=42, n_jobs=-1))])
    model.fit(X)
    joblib.dump(model, WINDOWS_ISO_PATH)
    WINDOWS_META_PATH.write_text('{"training_rows": %d, "contamination": %s}' % (len(norm), contamination))
    return model

def detect_windows_events(events_df):
    norm = normalise_events(events_df)
    if norm.empty: return norm
    scores = norm.apply(rule_score, axis=1, result_type="expand")
    norm["rule_score"] = scores[0]
    norm["rule_reasons"] = scores[1].apply(lambda x: "; ".join(x) if x else "No rule triggered")
    norm["ml_anomaly"] = False
    norm["ml_anomaly_score"] = 0.0
    if WINDOWS_ISO_PATH.exists():
        model = joblib.load(WINDOWS_ISO_PATH)
        X = feature_frame(norm)
        norm["ml_anomaly"] = model.predict(X) == -1
        norm["ml_anomaly_score"] = -model.score_samples(X)
    norm["risk_score"] = (norm["rule_score"] + norm["ml_anomaly"].astype(int)*20).clip(0,100)
    norm["risk_level"] = norm["risk_score"].apply(lambda x: "Critical" if x>=75 else "High" if x>=50 else "Medium" if x>=25 else "Low")
    norm["alert"] = (norm["risk_score"] >= 25) | norm["ml_anomaly"]
    norm["explanation"] = norm.apply(lambda r: f"{r.event_name} on {r.computer or 'unknown host'}. {r.rule_reasons}. Risk score {int(r.risk_score)}/100. ML anomaly: {bool(r.ml_anomaly)}.", axis=1)
    return norm

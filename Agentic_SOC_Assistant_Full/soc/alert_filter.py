"""Deduplicate and suppress low-value events while retaining an audit count."""
import pandas as pd

def filter_alerts(detected_df, min_risk=25, dedupe=True):
    if detected_df is None or detected_df.empty: return pd.DataFrame()
    alerts = detected_df[detected_df["alert"]].copy()
    alerts = alerts[alerts["risk_score"] >= min_risk]
    if dedupe:
        keys = [c for c in ["event_id","computer","account","source_ip","process_name"] if c in alerts]
        if keys:
            alerts = alerts.drop_duplicates(subset=keys, keep="last")
    return alerts.sort_values(["risk_score","timestamp"], ascending=[False,False])

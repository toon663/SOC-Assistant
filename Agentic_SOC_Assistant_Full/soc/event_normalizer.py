"""Normalise Windows event records and derive features for rules/ML."""
import json, re
import numpy as np
import pandas as pd

EVENT_NAMES = {
    4624: "Successful logon", 4625: "Failed logon", 4672: "Special privileges assigned",
    4688: "Process created", 4720: "User account created", 4732: "User added to local group",
    4740: "Account locked out", 1102: "Security audit log cleared",
    4697: "Service installed", 7045: "New service installed"
}
SUSPICIOUS_WORDS = ["powershell", "encodedcommand", "mimikatz", "rundll32", "regsvr32",
                    "psexec", "schtasks", "wmic", "vssadmin", "certutil", "bitsadmin"]

def _dict(value):
    if isinstance(value, dict): return value
    try: return json.loads(value) if value else {}
    except Exception: return {}

def normalise_events(df):
    if df is None or df.empty:
        return pd.DataFrame()
    out = df.copy()
    for col in ["timestamp", "event_id", "provider", "computer", "channel", "event_data", "message"]:
        if col not in out: out[col] = ""
    out["event_id"] = pd.to_numeric(out["event_id"], errors="coerce").fillna(0).astype(int)
    out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce", utc=True)
    out["event_name"] = out["event_id"].map(EVENT_NAMES).fillna("Other event")
    out["event_data_dict"] = out["event_data"].apply(_dict)
    text = (out["message"].fillna("").astype(str) + " " +
            out["event_data"].fillna("").astype(str)).str.lower()
    out["suspicious_keyword"] = text.apply(lambda s: int(any(w in s for w in SUSPICIOUS_WORDS)))
    out["is_failed_logon"] = (out.event_id == 4625).astype(int)
    out["is_success_logon"] = (out.event_id == 4624).astype(int)
    out["is_privilege_event"] = (out.event_id == 4672).astype(int)
    out["is_account_change"] = out.event_id.isin([4720, 4732, 4740]).astype(int)
    out["is_log_clear"] = (out.event_id == 1102).astype(int)
    out["is_service_install"] = out.event_id.isin([4697, 7045]).astype(int)
    out["is_process_create"] = (out.event_id == 4688).astype(int)
    out["hour"] = out.timestamp.dt.hour.fillna(0).astype(int)
    out["day_of_week"] = out.timestamp.dt.dayofweek.fillna(0).astype(int)
    out["message_length"] = out.message.fillna("").astype(str).str.len()
    out["host_key"] = out.computer.fillna("unknown").astype(str).str.lower()
    # Extract likely account/source identifiers from standard XML field names or message text.
    def find_value(d, keys):
        for k, v in d.items():
            if k.lower() in keys and str(v).strip():
                return str(v)
        return ""
    out["account"] = out.event_data_dict.apply(lambda d: find_value(d, {"targetusername","subjectusername","accountname","username"}))
    out["source_ip"] = out.event_data_dict.apply(lambda d: find_value(d, {"ipaddress","sourceaddress","clientaddress"}))
    out["process_name"] = out.event_data_dict.apply(lambda d: find_value(d, {"newprocessname","processname","image"}))
    out["account"] = out["account"].replace("", "unknown")
    out["source_ip"] = out["source_ip"].replace({"": "unknown", "-": "unknown"})
    return out

def feature_frame(df):
    cols = ["event_id","suspicious_keyword","is_failed_logon","is_success_logon",
            "is_privilege_event","is_account_change","is_log_clear","is_service_install",
            "is_process_create","hour","day_of_week","message_length"]
    return df[cols].replace([np.inf,-np.inf],np.nan).fillna(0).astype(float)

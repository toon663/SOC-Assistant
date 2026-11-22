"""Simple, explainable temporal correlation; production deployments need richer identity/host telemetry."""
import pandas as pd

def correlate_events(events, window_minutes=30):
    if events is None or events.empty: return pd.DataFrame()
    df = events.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df = df.sort_values("timestamp")
    groups = []
    for host, part in df.groupby("host_key", dropna=False):
        part = part.sort_values("timestamp")
        # Sliding window anchored to each event; emit groups with >=2 distinct event types.
        used = set()
        for idx, row in part.iterrows():
            if idx in used: continue
            end = row.timestamp + pd.Timedelta(minutes=window_minutes)
            win = part[(part.timestamp >= row.timestamp) & (part.timestamp <= end)]
            if len(win) < 2: continue
            ids = sorted(set(int(x) for x in win.event_id.tolist()))
            if len(ids) < 2: continue
            used.update(win.index.tolist())
            group = {
                "host": host, "start_time": win.timestamp.min(), "end_time": win.timestamp.max(),
                "event_count": len(win), "event_ids": ", ".join(map(str,ids)),
                "accounts": ", ".join(sorted(set(win.account.astype(str)))),
                "source_ips": ", ".join(sorted(set(win.source_ip.astype(str)))),
                "risk_score": int(min(100, win.risk_score.max() + min(30, (len(win)-1)*5))),
                "summary": f"{len(win)} events across {len(ids)} event types on {host}: {', '.join(map(str,ids))}"
            }
            groups.append(group)
    return pd.DataFrame(groups).drop_duplicates(subset=["host","start_time","event_ids"]) if groups else pd.DataFrame()

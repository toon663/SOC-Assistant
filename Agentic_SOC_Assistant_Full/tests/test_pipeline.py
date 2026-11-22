import pandas as pd
from soc.windows_detection import detect_windows_events
from soc.alert_filter import filter_alerts
from soc.event_correlator import correlate_events

def test_detection_and_filter():
    df=pd.DataFrame([{"timestamp":"2026-01-01T00:00:00Z","event_id":1102,
      "provider":"test","computer":"host","channel":"Security","event_data":"{}",
      "message":"audit log cleared"}])
    out=detect_windows_events(df)
    assert int(out.iloc[0].risk_score) >= 25
    assert len(filter_alerts(out)) == 1

def test_correlation():
    df=pd.DataFrame([
      {"timestamp":"2026-01-01T00:00:00Z","event_id":4625,"provider":"t","computer":"host","channel":"Security","event_data":"{}","message":"fail"},
      {"timestamp":"2026-01-01T00:02:00Z","event_id":4624,"provider":"t","computer":"host","channel":"Security","event_data":"{}","message":"success"},
    ])
    out=detect_windows_events(df)
    corr=correlate_events(out)
    assert len(corr) >= 1

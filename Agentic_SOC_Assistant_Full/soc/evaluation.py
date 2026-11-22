"""Generate reproducible evaluation on labelled simulated Windows events."""
import pandas as pd
from soc.windows_detection import detect_windows_events

def simulated_test_events():
    rows=[]
    examples=[
        (4625,"host-a","Failed logon user=admin ip=203.0.113.10"),
        (4625,"host-a","Failed logon user=admin ip=203.0.113.10"),
        (4624,"host-a","Successful logon user=admin ip=203.0.113.10"),
        (1102,"host-a","Security audit log cleared"),
        (7045,"host-b","New service installed ImagePath=powershell.exe"),
        (4720,"host-b","New user account created"),
        (4688,"host-b","Process created powershell encodedcommand")
    ]
    for i,(eid,host,msg) in enumerate(examples):
        rows.append({"timestamp":f"2026-11-19T10:{i:02d}:00Z","event_id":eid,
                     "provider":"Simulation","computer":host,"channel":"Security",
                     "event_data":"{}","message":msg})
    return pd.DataFrame(rows)

def evaluate_simulation():
    df=simulated_test_events()
    detected=detect_windows_events(df)
    return detected

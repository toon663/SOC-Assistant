import sqlite3
from datetime import datetime, timezone
import pandas as pd
from config import INCIDENT_DB

def connect():
    c=sqlite3.connect(INCIDENT_DB)
    c.execute("""CREATE TABLE IF NOT EXISTS incidents(
        id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT, host TEXT, event_id INTEGER,
        event_name TEXT, risk_level TEXT, risk_score INTEGER, explanation TEXT,
        mitre_techniques TEXT, recommended_actions TEXT, status TEXT DEFAULT 'Pending review',
        decision_notes TEXT)""")
    c.commit()
    return c

def save_incidents(items):
    c=connect()
    for x in items:
        c.execute("""INSERT INTO incidents(created_at,host,event_id,event_name,risk_level,risk_score,
        explanation,mitre_techniques,recommended_actions,status) VALUES(?,?,?,?,?,?,?,?,?,'Pending review')""",
        (datetime.now(timezone.utc).isoformat(),x.get("host"),x.get("event_id"),x.get("event_name"),
         x.get("risk_level"),x.get("risk_score"),x.get("explanation"),x.get("mitre_techniques"),
         x.get("recommended_actions")))
    c.commit(); c.close()

def get_incidents():
    c=connect(); df=pd.read_sql_query("SELECT * FROM incidents ORDER BY id DESC",c); c.close(); return df

def update_decision(i, status, notes):
    c=connect(); c.execute("UPDATE incidents SET status=?, decision_notes=? WHERE id=?",
                           (status,notes,int(i))); c.commit(); c.close()

"""Explainable agent workflow: filter -> correlate -> retrieve knowledge -> propose actions."""
from soc.raggraph import RAGGraph
from soc.response_recommender import recommend_actions

class SOCAgent:
    def __init__(self):
        self.rag = RAGGraph()

    def investigate(self, alerts, correlations=None):
        if alerts is None or alerts.empty:
            return []
        outputs=[]
        for _, row in alerts.iterrows():
            eid = int(row.event_id)
            knowledge = self.rag.explain([eid], str(row.get("message","")) + " " + str(row.get("process_name","")))
            actions = recommend_actions(eid, str(row.get("risk_level","Medium")))
            outputs.append({
                "timestamp": str(row.get("timestamp","")),
                "host": str(row.get("computer","")),
                "event_id": eid,
                "event_name": str(row.get("event_name","")),
                "risk_level": str(row.get("risk_level","")),
                "risk_score": int(row.get("risk_score",0)),
                "explanation": str(row.get("explanation","")),
                "mitre_summary": knowledge["summary"],
                "mitre_techniques": ", ".join(x["id"]+" "+x["name"] for x in knowledge["techniques"]),
                "recommended_actions": " | ".join(actions),
                "human_approval_required": True
            })
        return outputs

"""Local graph-backed retrieval over a small ATT&CK knowledge base (no external API required)."""
import json
from pathlib import Path
import networkx as nx
from config import KNOWLEDGE_DIR

KB_PATH = KNOWLEDGE_DIR / "mitre_knowledge.json"

class RAGGraph:
    def __init__(self, kb_path=KB_PATH):
        self.kb_path = Path(kb_path)
        self.techniques = json.loads(self.kb_path.read_text(encoding="utf-8"))
        self.graph = nx.MultiDiGraph()
        for item in self.techniques:
            tid = item["id"]
            self.graph.add_node(tid, **{k:v for k,v in item.items() if k not in ("response",)})
            for eid in item.get("evidence_event_ids", []):
                event = f"EventID:{eid}"
                self.graph.add_node(event, kind="windows_event")
                self.graph.add_edge(event, tid, relation="potentially_indicates")
            for tactic in item.get("tactic","").split(", "):
                tnode = f"Tactic:{tactic}"
                self.graph.add_node(tnode, kind="tactic")
                self.graph.add_edge(tid, tnode, relation="belongs_to")

    def retrieve(self, event_ids, query_text="", top_k=3):
        event_ids = set(int(x) for x in event_ids if str(x).isdigit())
        candidates = []
        q = (query_text or "").lower()
        for item in self.techniques:
            overlap = len(event_ids.intersection(item.get("evidence_event_ids", [])))
            haystack = " ".join([item["name"], item["description"], item["tactic"]]).lower()
            words = [w for w in q.split() if len(w)>3]
            lexical = sum(w in haystack for w in words)
            score = overlap * 3 + lexical
            if score > 0:
                candidates.append((score,item))
        candidates.sort(key=lambda x:x[0], reverse=True)
        results=[]
        for score,item in candidates[:top_k]:
            results.append({**item, "retrieval_score":score,
                            "graph_neighbours":list(self.graph.neighbors(item["id"]))})
        return results

    def explain(self, event_ids, query_text=""):
        hits = self.retrieve(event_ids, query_text)
        if not hits:
            return {"techniques":[],"summary":"No sufficiently relevant ATT&CK knowledge was retrieved. Gather more evidence before mapping."}
        lines=[]
        for h in hits:
            lines.append(f"{h['id']} – {h['name']} ({h['tactic']}): {h['description']} Evidence IDs: {h['evidence_event_ids']}. {h['confidence_note']}")
        return {"techniques":hits,"summary":"\\n".join(lines)}

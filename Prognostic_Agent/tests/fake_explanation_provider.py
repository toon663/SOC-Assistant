"""Offline-only provider used by Phase 3 tests and the synthetic comparison."""
import json
import time


class FakeExplanationProvider:
    def __init__(self, mode="success"):
        self.mode = mode

    def complete(self, request, *, deadline, attempt):
        # This fake never creates a client/socket or imports an optional SDK.
        if self.mode == "timeout":
            time.sleep(30)
        if self.mode == "error" or (self.mode == "retry" and attempt == 1):
            raise RuntimeError("sensitive provider response must never be logged")
        content = json.loads(request["messages"][0]["content"])
        result = {"candidate_comments": [{"candidate_id": c["candidate_id"],
                   "comment_ids": ["scope", "transition", "entities", "uncertainty"]} for c in content["candidates"]]}
        if self.mode == "number":
            result["risk_score"] = 99
        elif self.mode == "technique":
            result["candidate_comments"][0]["technique_id"] = "T9999"
        elif self.mode == "prose":
            result["candidate_comments"][0]["text"] = "New host, new technique, probability 0.99"
        elif self.mode == "candidate":
            result["candidate_comments"][0]["candidate_id"] = "candidate_999"
        elif self.mode == "comment":
            result["candidate_comments"][0]["comment_ids"].append("compromise_confirmed")
        elif self.mode == "invalid":
            result = ["not an object"]
        return result

# SOC Assistant architecture

Implemented workflow with default human approval enabled. Agent logic and enrichment are deterministic demonstrations. The ADFA experiment is a separate offline entry point.

```mermaid
flowchart TB
    subgraph INPUT["Event sources and ingestion"]
        WIN["Windows host or VM running the backend"]
        READ["gatherer.py / POST /scan<br/>Newest 200 Windows Security records"]
        RULES["Sentinel.inspect_computer / anomaly.py<br/>Rules: 4625, 4740, 4719, 1102"]
        JSON["Event JSON submitted to POST /events"]
        WIN --> READ --> RULES
    end

    subgraph CORE["SOC incident workflow — agents.py"]
        S["1 · Sentinel Agent<br/>Severity, repetition and event diversity"]
        A["2 · Analyst Agent<br/>Asset enrichment and incident risk"]
        P["3 · Prognostic Agent<br/>Incident risk + IP reputation<br/>Predefined risk path"]
        B["4 · Business Impact Agent<br/>Impact based on asset criticality"]
        O["5 · Orchestrator Agent<br/>Demo ticket and playbook selection"]
        WAIT["Pending incident stored<br/>Approval Required"]
        H{"Human review<br/>Reviewer + reason"}
        EXEC["Approve: resume stored playbook<br/>Simulated containment or monitoring"]
        DENY["Deny: record decision<br/>No response actions"]
        S --> A --> P --> B --> O --> WAIT --> H
        H -->|"Approve"| EXEC
        H -->|"Deny"| DENY
    end

    subgraph SERVICES["Application services and persistence"]
        UI["Analyst dashboard<br/>frontend/index.html + app.js"]
        API["FastAPI · api.py<br/>Scan, submit, list incidents, record decisions"]
        DB[("SQLite · database.py<br/>Incidents, decisions and audit entries")]
        HUB["IntegrationHub / DemoExternalSystems<br/>Simulated asset and IP lookups<br/>In-memory tickets and response adapters"]
        UI <-->|"HTTP / JSON"| API
        API <-->|"Save / read / decision transaction"| DB
    end

    RULES -->|"Matched findings only"| S
    JSON --> S
    RULES -->|"Snapshot, including scans without findings"| API
    API -.->|"Invoke pipeline for /scan or /events"| S
    API -.->|"Submit analyst decision"| H
    A -.->|"Asset lookup"| HUB
    P -.->|"IP lookup"| HUB
    O -.->|"Ticket creation"| HUB
    EXEC -.->|"Simulated response calls"| HUB
    WAIT -.->|"Persist through API"| DB
    EXEC --> API
    DENY --> API

    subgraph OFFLINE["Offline evaluation — benchmark_adfa.py"]
        DATA["ADFA-LD call traces<br/>Training / calibration / held-out test"]
        DET["Benign call-pair baseline<br/>25%, 50%, 75%, 100% prefixes"]
        BP["PrognosticAgent.forecast_risk<br/>Neutral event + detector risk<br/>No IP evidence"]
        REPORT["report.json + predictions.csv<br/>Precision, recall, F1, FPR, average precision"]
        DATA --> DET --> BP --> REPORT
        DET -->|"Baseline comparison"| REPORT
    end

    subgraph SUPPORT["Available modules — not wired into the live agent pipeline"]
        KNOW["retrieval.py<br/>Lexical MITRE / NIST / D3FEND examples"]
        MEM["memory.py<br/>In-memory context and reasoning graph"]
        POLICY["policy_engine.py<br/>Separate action-policy evaluator"]
        ML["ml_models.py<br/>Standalone detection, triage and projection"]
    end

    classDef source fill:#eee5f3,stroke:#816291,color:#27212d;
    classDef agent fill:#e0efdc,stroke:#6e9861,color:#20331c;
    classDef service fill:#e6efff,stroke:#6c8fbc,color:#1b304d;
    classDef human fill:#ffffff,stroke:#677280,color:#202a35;
    classDef evaluation fill:#fff0ce,stroke:#bc913a,color:#493812;
    classDef support fill:#f0f1f3,stroke:#9199a3,stroke-dasharray:5 4,color:#414b57;
    class WIN,JSON,DATA source;
    class S,A,P,B,O,EXEC,DENY,RULES agent;
    class READ,WAIT,UI,API,DB,HUB service;
    class H human;
    class DET,BP,REPORT evaluation;
    class KNOW,MEM,POLICY,ML support;
```

## Implementation notes

- Solid arrows carry events, incidents, decisions or results. Dashed arrows indicate invocation, enrichment or persistence relationships.
- `/scan` reads the computer running the backend. Running the backend inside a VM makes that VM the collection host; RustDesk supplies desktop access.
- Scans create incidents only for matched findings. Submitted `/events` payloads enter the pipeline directly.
- With default settings, the Orchestrator pauses for review. The decision API restores the stored pending incident and resumes its selected playbook without repeating detection. SQLite serializes decision updates.
- The Business Impact Agent also updates metrics after initial response evaluation; MTTR and alert-to-action times are currently placeholders.
- `PolicyEngine` is separate from the active approval mechanism in `OrchestratorAgent` and the decision API.
- The ADFA lane uses the same Prognostic Agent class, instantiated separately. It bypasses Sentinel, Analyst, BI, Orchestrator, the API and SQLite. With no IP evidence, its prognostic score is 0.7 times the detector score, rounded. The experiment measures partial-trace attack classification, not attack-onset forecasting.
- There is no active LLM, embedding pipeline or vector database in this workflow. Show those in a separately labeled future architecture if needed.

## Edit and export

Edit this Mermaid block to change groups, labels or arrows. GitHub renders Mermaid in Markdown. To export for a report, paste the block contents into a Mermaid editor that supports SVG/PNG export. SVG preserves sharp text at different sizes.

To resemble the reference image, retain a vertical green agent lane, blue application services, purple input sources, a white decision diamond, and an amber evaluation lane. Use an amber RAG lane only for a clearly labeled future design.

## Source map

| Component | Implementation |
| --- | --- |
| Collection and Security rules | `backend/gatherer.py`, `backend/anomaly.py`, `SentinelAgent.inspect_computer` |
| Five agents and human review | `backend/agents.py` |
| API and dashboard | `backend/api.py`, `backend/frontend/` |
| Persistent incidents and decisions | `backend/database.py` |
| Simulated integrations | `backend/integrations.py`, `DemoExternalSystems` |
| Offline evaluation | `backend/benchmark_adfa.py`, `backend/evaluation.py` |
| Additional modules | `backend/retrieval.py`, `backend/memory.py`, `backend/policy_engine.py`, `backend/ml_models.py` |

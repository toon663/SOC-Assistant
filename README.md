# SOC-Assistant
A multi-agent cybersecurity framework that combines Agentic AI, RAG, adaptive context engineering, MITRE ATT&amp;CK mapping, and human-in-the-loop safeguards to automate SOC alert triage and incident analysis.

# SOC Multi-Agent Cybersecurity Platform

This project models a human-supervised security operations workflow:

SIEM/EDR/IAM/TI -> Sentinel -> Analyst -> Prognostic -> BI -> Orchestrator
                                      |                         |
                               memory/retrieval          policy + approval

The system is designed to reduce alert fatigue while preserving analyst control. High-impact actions such as endpoint isolation, account disabling, and IP blocking require approval. Destructive data deletion is prohibited by the default policy.

Modules

agents.py — end-to-end Sentinel, Analyst, Prognostic, BI, and Orchestrator workflow

models.py — validated boundary models

ml_models.py — local baselines for anomaly scoring, triage, deduplication, and forecasting

memory.py — short-term, long-term, and reasoning-graph memory

retrieval.py — evidence retrieval with MITRE ATT&CK, NIST, and D3FEND examples

integrations.py — safe mock SIEM, EDR, IAM, and ticketing adapters

database.py — SQLite incident and audit persistence

policy_engine.py — deterministic safety and approval controls

evaluation.py — precision, recall, F1, false-positive rate, alert reduction, MTTR, and action safety

api.py — optional FastAPI service

config.py — environment-backed settings

windows_ingest.py — connects Event_Gatherer and Sentinel_Agent to the agent workflow

Windows event pipeline

Event_Gatherer -> Sentinel_Agent Random Forest -> windows_ingest.py -> Sentinel -> Analyst -> Prognostic -> BI -> Orchestrator -> SQLite and dashboard

Start the API from backend/ and use Collect and investigate on the dashboard, or call the API directly. Reading the Security log requires Administrator rights: double-click run_backend_admin.bat in the repository root, which requests elevation and serves the dashboard at http://127.0.0.1:8000/app/. Without elevation, System and Application are still collected and the response lists the Security error. Repeats are grouped into one incident per host, event, and user, and the alert shows the occurrence count and first and last seen times. Repeats in later scans update the open incident; once an incident has been acted on, a repeat opens a new one. Each incident stores its newest 50 events as evidence while the count stays exact. Events that were already processed are skipped, so lookback windows can overlap. Severity comes from Windows and threat-intel evidence; the Random Forest probability only adjusts the anomaly score. Threat intel is read from Sentinel_Agent/intel_cache and is never downloaded during a request.

Event_Gatherer/gatherer.py and Sentinel_Agent/anomaly_agent.py still work as standalone command-line tools.

Run locally

Run these commands from backend/. The core workflow uses only the Python standard library:

python agents.py
python -m unittest discover -s tests -v

Install optional runtime dependencies and start the API:

python -m pip install -r requirements.txt
uvicorn api:app --reload

The API exposes:

GET /health

POST /events

POST /ingest/windows — collect from this host, detect anomalies, and open incidents

POST /ingest/document — do the same for a saved gatherer JSON export

GET /incidents

GET /incidents/{incident_id}

Safety and governance

The current adapters are simulated. Connectors should be added only behind the policy engine and audit log. Production deployments should add authentication, authorization, secret management, rate limiting, approval identity verification, two-person approval for high-impact actions, rollback procedures, data minimization, and adversarial testing.

Recommended governance mappings include MITRE ATT&CK for adversary behavior, MITRE D3FEND for defensive techniques, and NIST CSF Respond/Recover functions for incident handling.

Replacing the baselines

ml_models.py intentionally provides explainable local baselines. A production experiment can replace them with Isolation Forest or XGBoost, calibrate confidence on held-out data, version the artifacts, and evaluate drift. LlamaIndex can replace lexical retrieval, while Cognee can replace the lightweight reasoning graph. The interfaces should remain bounded by the deterministic policy engine.
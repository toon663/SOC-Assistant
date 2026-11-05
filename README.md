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

Run locally

The core workflow uses only the Python standard library:

python agents.py
python -m unittest discover -s tests -v

Install optional runtime dependencies and start the API:

python -m pip install -r requirements.txt
uvicorn api:app --reload

The API exposes:

GET /health

POST /events

GET /incidents

GET /incidents/{incident_id}

Safety and governance

The current adapters are simulated. Connectors should be added only behind the policy engine and audit log. Production deployments should add authentication, authorization, secret management, rate limiting, approval identity verification, two-person approval for high-impact actions, rollback procedures, data minimization, and adversarial testing.

Recommended governance mappings include MITRE ATT&CK for adversary behavior, MITRE D3FEND for defensive techniques, and NIST CSF Respond/Recover functions for incident handling.

Replacing the baselines

ml_models.py intentionally provides explainable local baselines. A production experiment can replace them with Isolation Forest or XGBoost, calibrate confidence on held-out data, version the artifacts, and evaluate drift. LlamaIndex can replace lexical retrieval, while Cognee can replace the lightweight reasoning graph. The interfaces should remain bounded by the deterministic policy engine.
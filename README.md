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

analyst.py — Analyst agent triage rules: verdict, priority, correlation, and next steps

llm_analyst.py — Claude review of incidents the rules leave unresolved (optional)

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

file_scan.py — static malware scanning of executables for the Sentinel agent

Windows event pipeline

Event_Gatherer -> Sentinel_Agent Random Forest -> windows_ingest.py -> Sentinel -> Analyst -> Prognostic -> BI -> Orchestrator -> SQLite and dashboard

Start the API from backend/ and use Collect and investigate on the dashboard, or call the API directly. Reading the Security log requires Administrator rights: double-click run_backend_admin.bat in the repository root, which requests elevation and serves the dashboard at http://127.0.0.1:8000/app/. Without elevation, System and Application are still collected and the response lists the Security error. Repeats are grouped into one incident per host, event, and user, and the alert shows the occurrence count and first and last seen times. Repeats in later scans update the open incident; once an incident has been acted on, a repeat opens a new one. Each incident stores its newest 50 events as evidence while the count stays exact. Events that were already processed are skipped, so lookback windows can overlap. Severity comes from Windows and threat-intel evidence; the Random Forest probability only adjusts the anomaly score. Threat intel is read from Sentinel_Agent/intel_cache and is never downloaded during a request.

Event_Gatherer/gatherer.py and Sentinel_Agent/anomaly_agent.py still work as standalone command-line tools.

Analyst triage

Sentinel incident -> analyst.py rule for the event (by log name and event ID) -> correlation with other activity on the host -> verdict, priority, and next steps -> Prognostic

The Analyst decides what each Sentinel incident actually is. It reads the Windows message fields (accounts, logon type, source address, command line, service path, group name) and gives a verdict: malicious, suspicious, or benign. It also assigns a priority from P1 to P4, a decision (escalate, investigate, or close), the ATT&CK techniques the evidence supports, and recommended next steps. The triage score is the sum of the listed findings, so every verdict can be traced to evidence. Rules cover failed and successful logons, privileged logons, log clearing, account creation, privileged group changes, service installs, scheduled tasks, process command lines (encoded PowerShell is decoded and scored), group enumeration, clock changes, Defender detections, and scanner malware hits. Other channels with no security indicators are classed as operational noise. Benign incidents are capped at a low score, so they forecast low and get the monitor playbook.

During ingest, each incident is correlated with the rest of the same collection and with recent incidents on the host. Related incidents are linked by ID: failed logons followed by a success from the same source, a new account added to Administrators, or a log cleared after other suspicious activity. The dashboard shows the verdict on each row and hides benign incidents by default (verdict filter), and the incident drawer shows the score breakdown, linked incidents, and next steps.

Claude review (hybrid triage)

Rules triage every incident -> unresolved ones (suspicious, no matching rule, or low confidence) -> Claude investigates with read-only tools -> merged verdict -> Prognostic, BI, Orchestrator re-run

Claude reviews only what the rules cannot settle. It investigates with read-only tools: the incident's own events, other activity on the same host, linked incidents, PowerShell decoding, and IP reputation. It returns a verdict, its reasoning, the evidence it cited, and next steps. The dashboard shows each review in the incident drawer, including the tool calls Claude made, and the drawer has an "Ask Claude to review" button for any incident.

Guardrails are enforced in code, not left to the model. Claude can raise a verdict, or decide one where no rule applies, but it never lowers a verdict a rule reached: log text is partly attacker-controlled. A disagreement is flagged "needs human decision" instead. Reviews run in a background worker, so ingest and live detection never wait on the API. Repeats of a reviewed incident reuse its review, and an hourly cap limits spend. If the API refuses or fails, the rule verdict stands.

Claude review is off by default because it sends incident evidence (log messages, usernames, hostnames, IPs) to the Claude API. To turn it on, install requirements.txt, set ANTHROPIC_API_KEY, and start the backend with:

SOC_LLM_TRIAGE=auto — review unresolved incidents (all reviews every incident; off is the default)

SOC_LLM_MODEL=claude-opus-5-5, SOC_LLM_EFFORT=medium, SOC_LLM_MAX_REVIEWS_PER_HOUR=30 — optional

GET /llm/status reports the mode, queue, and outcomes; POST /incidents/{incident_id}/review asks for a review of one incident.

Malware scanning

Process-creation events (Security 4688, Sysmon 1) -> file_scan.py -> Sentinel_Agent/malware_classifier (LightGBM) -> malware_detected incident

During an ingest, the executables named in process-creation events are read (never executed) and scored by a LightGBM detector trained on the EMBER2024 Windows PE dataset. Files above the 1% false-positive threshold are "suspicious" (high severity) and above the 0.1% threshold "malicious" (critical). Flagged files are also classified into one of the 100 most common malware families (or "other"), and the family's typical MITRE ATT&CK techniques and tactics are attached for the Analyst and Prognostic agents. One incident is opened per host and file hash. Process-creation auditing (event 4688) must be enabled in Windows for this to see launches. If the models are not installed, ingest continues without malware scanning.

Dev mode (testing and demos)

Start the backend with run_backend_dev.bat (or set SOC_DEV_MODE=1) to show a Test scenarios panel on the dashboard. It injects synthetic Windows attack scenarios (brute force, log cleared, new admin account, service install, encoded PowerShell) through the full pipeline, with fresh record IDs each run, so nothing happens on the machine itself. A malware launch demo scores stored EMBER2024 test-set feature vectors (models/demo_vectors.npz, built by build_demo_vectors.py) with the real models, so no malware file is needed. Two resets are available: forget processed events (the next collection re-reports log records already seen) and wipe all incidents. Without dev mode the /dev endpoints are not registered. Never enable dev mode outside testing.

The models are not in git. To rebuild them (about 25 GB download, 105 GB extracted data, several hours of compute), install Sentinel_Agent/malware_classifier/requirements.txt and run, from the repository root: download_ember2024.py, build_features.py, train_detector.py, train_family.py, then build_family_profiles.py (all in Sentinel_Agent/malware_classifier). Test metrics are written to models/detector_metrics.json and models/family_metrics.json.

Orchestrator agent (trained response model)

Analyst triage + Prognostic forecast + BI impact -> orchestrator_model.py (MLP) -> playbooks.py (targets, policy) -> human verification gate -> external systems -> validation

The Orchestrator is a multi-label neural network (scikit-learn MLPClassifier) that scores four response actions for every incident: isolate the endpoint, disable the user, block the source IP, quarantine the file. An action is proposed when its score reaches the model's threshold and the incident names a target for it (a host, a human account, a remote source IP, or a file that is not a Windows system binary). Every proposed action is checked by policy_engine.py, with the model's score as its confidence, and waits at the human verification gate. Approve runs the plan, re-checks policy, and confirms each action. Reject runs nothing and sends the incident back for re-triage. Either decision is also a training step (partial_fit), and is logged to Orchestrator_Agent/feedback/decisions.jsonl (not in git) for the next full retrain. If the Analyst confirms a threat (malicious, confidence 0.8 or more) and the model proposes no containment, isolating the host is still proposed and marked as a guardrail. Without a model file, the former score thresholds decide and the dashboard says so. GET /orchestrator/status shows which is in use; POST /incidents/{incident_id}/decision takes {"decision": "approve" | "deny", "reviewer", "reason"}.

Training data: the OTRF Security-Datasets (Mordor) Windows recordings are replayed through this pipeline, so each example is an incident exactly as the Orchestrator sees it live. Mordor labels whole recordings with ATT&CK techniques, not responses. Labels therefore come from MITRE D3FEND, which lists the countermeasures for each technique (for example, Account Locking -> disable_user, Inbound Traffic Filtering -> block_ip). An incident gets those labels only if the Analyst rates it actionable and its own ATT&CK evidence shares a tactic with the recording. Mordor is almost all attack recordings, so the model also needs to learn when not to act. WitFoo Precinct6 supplies that: 758,000 Windows Security events of live production traffic from its 2M-signal release, replayed the same way. Every incident our pipeline raises on that traffic (4,065 from 161 host-days, most of them rated "suspicious" by the Analyst) is a "no containment" example, because WitFoo's own correlation engine found nothing there worth an incident. Incidents built from rows WitFoo marked malicious are left out, and so are the few our Analyst rated malicious (the two disagree, so neither label is trusted). WitFoo's malicious rows are mostly firewall and cloud flow logs, which this pipeline does not ingest, so they are not used as attack examples.

Neither Mordor nor WitFoo contains a malware drop, so file responses come from the EMBER2024 test split that the Sentinel malware classifier was evaluated on. 2,000 malware files and 60,000 benign files are scored by Sentinel's real scanner, and every flagged file is opened as an incident. Malware gets the D3FEND countermeasures for its family's ATT&CK techniques and for T1204.002 (User Execution: Malicious File), which include quarantining the file. The 623 benign files the scanner flagged by mistake get "no action". Malware folds are grouped by family, so results are on families the model has not seen.

The three datasets carry equal total weight in training, and each action's threshold is tuned for its average F1 across the datasets that contain it, each scored together with the WitFoo traffic. Evaluation holds out whole recordings, host-days and malware families (5-fold GroupKFold):

- Real production traffic (WitFoo): containment proposed for 0.9% of incidents, against 21% for the former thresholds.
- Malware from unseen families: quarantine precision 1.00, recall 0.94.
- Mordor attacks: micro F1 0.60 against 0.20 for the former thresholds (isolate 0.61, block IP 0.64, disable user 0.50).
- Benign files the scanner flagged by mistake: 12% get a quarantine proposal. These are the files the scanner rated "malicious" with high confidence, which the Orchestrator cannot tell apart from real malware; the human verification gate is where they are caught. For files rated only "suspicious", quarantine is never proposed.

Brute force from the internet is still thin: the model isolates the host but does not yet propose blocking the IP or disabling the account.

To rebuild, install Orchestrator_Agent/requirements.txt and run, from the repository root (all in Orchestrator_Agent): download_mordor.py and build_dataset.py (about 60 MB, a few minutes), download_witfoo.py and build_witfoo_dataset.py (about 125 MB, about 7 minutes), build_malware_dataset.py (needs the vectorized EMBER2024 features from Sentinel_Agent/malware_classifier/build_features.py, set with EMBER2024_DIR; about 15 minutes), then train_orchestrator.py. Metrics are written to Orchestrator_Agent/models/orchestrator_metrics.json.

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

POST /live/start, POST /live/stop, GET /live/status — live detection: poll this host's Event Viewer every 30 seconds and ingest new events (the "Start live detection" button on the dashboard)

GET /scan/status — whether the malware scanner and its models are loaded

POST /scan/path — scan a file on the server, e.g. {"path": "C:\\Users\\bob\\Downloads\\setup.exe"}

POST /scan/upload?filename=setup.exe — scan a file sent as the raw request body (application/octet-stream)

Safety and governance

The current adapters are simulated. Connectors should be added only behind the policy engine and audit log. Production deployments should add authentication, authorization, secret management, rate limiting, approval identity verification, two-person approval for high-impact actions, rollback procedures, data minimization, and adversarial testing.

Recommended governance mappings include MITRE ATT&CK for adversary behavior, MITRE D3FEND for defensive techniques, and NIST CSF Respond/Recover functions for incident handling.

Replacing the baselines

ml_models.py intentionally provides explainable local baselines. A production experiment can replace them with Isolation Forest or XGBoost, calibrate confidence on held-out data, version the artifacts, and evaluate drift. LlamaIndex can replace lexical retrieval, while Cognee can replace the lightweight reasoning graph. The interfaces should remain bounded by the deterministic policy engine.

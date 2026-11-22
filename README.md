# SOC-Assistant
A multi-agent cybersecurity framework that combines Agentic AI, RAG, adaptive context engineering, MITRE ATT&amp;CK mapping, and human-in-the-loop safeguards to automate SOC alert triage and incident analysis.

# SOC Multi-Agent Cybersecurity Platform

See the [editable architecture diagram](docs/architecture.md) for the implemented workflow, human review gate, offline ADFA-LD evaluation, and integration status of supporting modules.

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

Offline ADFA-LD benchmark

Download and extract **ADFA-LD** from the [UNSW dataset page](https://research.unsw.edu.au/projects/adfa-ids-datasets).
The old ADFA link may redirect to the university homepage. This benchmark supports the Linux integer system-call traces, not ADFA-WD or Windows Security event exports.
If the official download is unavailable, a [community mirror](https://github.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset) contains `ADFA-LD.zip`. It is not an authenticated UNSW distribution. From the repository root:

```powershell
New-Item -ItemType Directory -Path datasets -Force | Out-Null
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset/master/ADFA-LD.zip" -OutFile "datasets/ADFA-LD.zip"
Expand-Archive -LiteralPath "datasets/ADFA-LD.zip" -DestinationPath "datasets"
```

The inspected mirror archive has SHA-256 `58D625470749344843A7F730B0875CE9B8769F6FA48F18DC4A92BD07C342EAD5`. This records the tested copy, not authenticity against the publisher. Its traces include two distinct contents with conflicting benign/attack labels. To exclude those contents from every split and record the exclusions, run:

```powershell
python backend/benchmark_adfa.py --data "datasets/ADFA-LD" --output "benchmark-results/adfa-ld" --exclude-label-conflicts
```

The default remains to stop on conflicting labels. Reports after exclusion and deduplication describe a filtered dataset, not the unmodified original benchmark.
The publisher grants academic research use and prohibits commercial use; consult its terms and cite the listed papers when reporting research.

Place the extracted files under a directory such as:

```text
datasets/ADFA-LD/
  Training_Data_Master/
  Validation_Data_Master/
  Attack_Data_Master/
```

From the repository root, run (Python standard library only):

```powershell
python backend/benchmark_adfa.py --data "datasets/ADFA-LD" --output "benchmark-results/adfa-ld"
```

If extraction adds an extra directory level, point `--data` at the directory directly containing those three folders. No backend server, administrator access, VM, or RustDesk connection is required.

The runner fits an unseen-system-call-pair baseline on normal training traces. It splits unique normal validation traces into benign calibration and held-out test subsets by content hash, then evaluates the held-out benign traces and all attack traces. Exact duplicates are excluded across partitions; conflicting labels fail explicitly. Related benign sessions may remain across splits, since this runner does not infer their session identities. All prefixes from a trace stay in the same split. Attack traces are never used for fitting or threshold selection.

At 25%, 50%, 75%, and 100% of each trace, it selects separate detector and prognostic thresholds on benign calibration data with a default target false-positive rate of 5%. Decisions use `score > threshold`; ties may make the achieved calibration rate lower. Held-out false-positive rates can differ. Change the target with `--target-fpr 0.01` before evaluating, rather than tuning it on test results.

Inspect `report.json` for precision, recall, F1, false-positive rate, average precision (a non-interpolated PR summary), confusion counts, and per-family recall. `predictions.csv` records each trace, prefix, label, scores, decisions, risk path, and confidence. Family names are inferred by removing trailing run numbers from attack directory names; verify these against your archive. Dataset labels and paths stay outside the agent input.

The real `PrognosticAgent` receives one neutral event per trace and the detector score as incident risk. There is no IP evidence, so its score is the detector score multiplied by 0.7 and rounded; it should not add ranking value and rounding may create ties. Its fixed path templates and constant 0.60 confidence are not learned predictions or calibrated probabilities. This measures **attack classification from partial traces**, not attack onset, elapsed-time lead, or future attack stages. The adapter deliberately bypasses Sentinel/Analyst severity heuristics to isolate this comparison and never invokes response actions.

Benchmark verification with small synthetic fixtures:

```powershell
cd backend
python -m unittest tests.test_benchmark_adfa -v
```

Safety and governance

The current adapters are simulated. Connectors should be added only behind the policy engine and audit log. Production deployments should add authentication, authorization, secret management, rate limiting, approval identity verification, two-person approval for high-impact actions, rollback procedures, data minimization, and adversarial testing.

Recommended governance mappings include MITRE ATT&CK for adversary behavior, MITRE D3FEND for defensive techniques, and NIST CSF Respond/Recover functions for incident handling.

Replacing the baselines

ml_models.py intentionally provides explainable local baselines. A production experiment can replace them with Isolation Forest or XGBoost, calibrate confidence on held-out data, version the artifacts, and evaluate drift. LlamaIndex can replace lexical retrieval, while Cognee can replace the lightweight reasoning graph. The interfaces should remain bounded by the deterministic policy engine.

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

POST /incidents/{incident_id}/decision

Human approval and denial

Click an incident marked **Approval Required** to open its details. Review the proposed playbook and targets, enter a reviewer name and reason, then choose **Approve response** or **Deny response**.

- Approve resumes the stored playbook and changes the status to `executed` after the simulated response completes.
- Deny changes the status to `denied` without executing response actions.
- Both decisions store the reviewer, reason, decision timestamp, and an audit entry in SQLite. The details panel displays the recorded decision after refresh or a backend restart.
- Only pending incidents accept decisions. Repeated or conflicting requests return HTTP 409. Decisions are serialized in a SQLite transaction, and repeated ingestion of the same incident preserves the saved decision.

The API accepts JSON such as:

```json
{"decision": "approve", "reviewer": "Analyst One", "reason": "Reviewed the evidence and proposed targets"}
```

This is a local demo: the reviewer name is self-reported, and EDR/IAM responses are simulated. Before using real response adapters, bind reviewer identity to authenticated analyst roles and make response execution durable and idempotent across failures. A database transaction alone cannot roll back an external endpoint or account change.

Windows Security log scans

From the repository root, install dependencies and start the dashboard:

```powershell
cd backend
python -m pip install -r requirements.txt
python -m uvicorn api:app --reload
```

Run the backend on your Windows computer. Open http://127.0.0.1:8000/app/ and click **Read Security events**.

The data flow is `gatherer.py -> SentinelAgent.inspect_computer -> anomaly.py -> existing incident pipeline -> POST /scan JSON -> frontend/app.js`.

- `gatherer.py` reads the same **Windows Logs > Security** channel shown in Event Viewer, using built-in Windows PowerShell `Get-WinEvent`. It reads the newest 200 records, parses their XML fields, and reports when that limit excludes older records. No extra collector dependency is needed. Collection happens on the backend host, which may differ from the computer viewing the dashboard.
- `anomaly.py` selects events through `SECURITY_RULES`: **4625** (failed logon), **4740** (account lockout), **4719** (audit policy change), and **1102** (Security log cleared). These are review rules, not a learned behavioral baseline or proof of an attack. Successful logons and other unmatched events remain visible in the records read without creating incidents.
- `POST /scan` returns `{ "snapshot": { "events": [...], ... }, "anomalies": [...], "incident": {...} }`. Without rule matches, `anomalies` is empty and `incident` is null. Findings preserve Windows event IDs, record IDs, timestamps, user/IP fields where present, and original named event data. Stable event identities let an identical set of findings reuse its incident ID; changing scan windows can produce incidents with overlapping evidence.
- `frontend/app.js` calls `/scan` with `fetch`, displays findings and expandable Security records, and refreshes `/incidents` when an incident is created. Python data reaches JavaScript through the API; it is not written into JavaScript source files.

Scans run only when requested. If access is denied (HTTP 403), start the backend from **PowerShell run as Administrator**, or use an account with Security log read permissions. The collector does not change audit policy or clear logs. An empty result means no matching records; permission and service errors are reported separately. Which events Windows records depends on the computer's audit policy. `memory.py` does not need to change; matched incidents already persist in SQLite.

Reference: [Microsoft Get-WinEvent documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-5.1).

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

# Agentic SOC Assistant – Full VS Code Implementation

This project is an educational, human-in-the-loop SOC prototype. It combines:
- Windows Security Event Log collection (pywin32 or PowerShell)
- Windows event normalisation and explainable rule-based detection
- Optional Isolation Forest anomaly detection trained on a representative baseline
- Alert filtering and time-window event correlation
- Local graph-backed retrieval over a compact MITRE ATT&CK knowledge base
- Investigation workflow and response recommendations
- Streamlit dashboard and SQLite incident review register
- Separate UNSW-NB15 network-flow model training

## 1. Requirements
- Windows 10/11 or Windows Server for real Windows Event Log collection
- Python 3.10 or 3.11 recommended
- VS Code with Python extension
- Permission to read the Windows Security Event Log
- Internet is not required for the local RAGGraph demonstration

## 2. Open in VS Code
1. Extract the ZIP.
2. VS Code > File > Open Folder > select `Agentic_SOC_Assistant_Full`.
3. Open Terminal > New Terminal.

PowerShell commands:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, run:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## 3. Start dashboard
```powershell
streamlit run app.py
```
Open the local address printed in the terminal, normally `http://localhost:8501`.

## 4. Collect Windows Security Logs
Run VS Code/terminal with an authorised account. Select **Collect Windows Logs** in the sidebar and click **Collect Windows Security Logs**. Choose `pywin32` or `powershell`.

The collector requests Event IDs:
4624, 4625, 4672, 4688, 4720, 4732, 4740, 1102, 4697, 7045.

Some events require appropriate audit policies to be enabled. Event 4688 command-line data requires the relevant Windows audit policy configuration. Do not change organisational audit policy without administrator/security approval.

## 5. Run detection and investigation
1. Collect events.
2. Open **Threat Detection** and click **Run detection**.
3. Review alerts and optionally correlate events.
4. Open **Agent Investigation** and click **Investigate alerts with SOC agent**.
5. Review retrieved ATT&CK knowledge and recommended checks.
6. Save findings as incidents.
7. Open **Incident Management** and record analyst decision.

The system only recommends actions. It does not automatically disable accounts, terminate processes, isolate hosts or change firewall rules.

## 6. RAGGraph
The `soc/raggraph.py` module builds a NetworkX knowledge graph from `knowledge/mitre_knowledge.json`, links Windows Event IDs to candidate ATT&CK techniques and retrieves relevant entries using event-ID overlap and simple lexical matching.

This is a compact, transparent RAGGraph demonstration. It is not the complete ATT&CK corpus and does not use embeddings or an LLM by default. For production research, expand the corpus from official MITRE ATT&CK STIX data, add a vector index, source citations, versioning and analyst validation.

## 7. Train Windows anomaly baseline (optional)
Only train on a representative baseline that is reviewed as benign. Do not train on a mixture of unknown or malicious events and call it a clean baseline.

From Python:
```python
import pandas as pd
from soc.windows_detection import train_windows_baseline
df = pd.read_csv("data/windows_logs/known_benign_baseline.csv")
train_windows_baseline(df)
```
CSV must have the same raw columns as the collector: timestamp,event_id,provider,computer,channel,event_data,message.

## 8. UNSW-NB15 network model
Place your `UNSW-NB15_Dataset2.csv` at:
`data/raw/UNSW-NB15_Dataset2.csv`

Use **UNSW-NB15 Network Model** in the dashboard to train. This model is kept separate from Windows event detection because the feature schemas differ. The supplied CSV has five attack classes and no benign class; it cannot train a benign-vs-malicious classifier.

## 9. Testing
Use **Testing & Evaluation** for deterministic simulated events. This verifies pipeline behaviour, not real-world model accuracy. For meaningful evaluation, create a labelled test corpus with normal and malicious Windows event sequences and report precision, recall, F1, false-positive rate, false-negative rate and detection latency.

## 10. Security and limitations
- Run only on systems you own or are authorised to monitor.
- Security log access may require administrator or Event Log Readers permissions.
- Event availability depends on audit policy and log retention.
- Windows Event Logs are sensitive; protect CSV exports and the SQLite database.
- The rule scores are triage heuristics, not calibrated probabilities.
- Isolation Forest is optional and depends on a clean baseline.
- ATT&CK mappings are candidate relationships, not proof of adversary behaviour.
- No automatic containment is performed.
- This is an academic prototype, not a production SOC platform.

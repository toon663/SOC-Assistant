"""Download the WitFoo Precinct6 cybersecurity dataset (small, 2M-signal version).

Real SOC data from four organizations: about 94% benign traffic, with suspicious
and malicious rows labeled in place by WitFoo Precinct's correlation engine. Each
row carries ATT&CK techniques/tactics and MITRE D3FEND countermeasure IDs.

The Orchestrator uses it to learn restraint: most real activity needs no response.

Files already on disk are skipped.

Usage (from the repository root):
    python Orchestrator_Agent/download_witfoo.py
"""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent
WITFOO_DIR = AGENT_DIR / "data" / "witfoo"
REPO = "https://huggingface.co/datasets/witfoo/precinct6-cybersecurity/resolve/main/"
FILES = (
    "README.md",
    "signals/signals.parquet",
    "signals/incident_signals.parquet",
    "signals/metadata.json",
    "reference/lead_rules_catalog.json",
)


def download(path: str) -> None:
    target = WITFOO_DIR / path
    if target.exists():
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(target.suffix + ".part")
    print(f"Downloading {path}", flush=True)
    request = urllib.request.Request(REPO + path, headers={"User-Agent": "soc-assistant-orchestrator-trainer"})
    with urllib.request.urlopen(request, timeout=300) as response, partial.open("wb") as handle:
        while chunk := response.read(1 << 20):
            handle.write(chunk)
    partial.replace(target)


def main() -> None:
    for path in FILES:
        try:
            download(path)
        except OSError as error:
            sys.exit(f"Could not download {path}: {error}")
    print(f"Done -> {WITFOO_DIR}")


if __name__ == "__main__":
    main()

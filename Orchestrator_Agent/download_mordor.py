"""Download OTRF Security-Datasets (Mordor) Windows recordings and their D3FEND countermeasures.

Fetches every Windows atomic dataset's metadata (ATT&CK technique and tactics) and
host log archive, then asks the MITRE D3FEND API which defensive techniques counter
each ATT&CK technique. Those countermeasures become the Orchestrator's training labels.

Files already on disk are skipped, so the script can be re-run to resume.

Usage (from the repository root):
    python Orchestrator_Agent/download_mordor.py
    python Orchestrator_Agent/download_mordor.py --limit 20
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

AGENT_DIR = Path(__file__).resolve().parent
DATA_DIR = AGENT_DIR / "data"
MORDOR_DIR = DATA_DIR / "mordor"
D3FEND_DIR = DATA_DIR / "d3fend"
REPO_API = "https://api.github.com/repos/OTRF/Security-Datasets/git/trees/master?recursive=1"
RAW = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
D3FEND_API = "https://d3fend.mitre.org/api/offensive-technique/attack/{technique}.json"
USER_AGENT = "soc-assistant-orchestrator-trainer"


def fetch(url: str, retries: int = 3) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.read()
        except (urllib.error.URLError, TimeoutError) as error:
            if isinstance(error, urllib.error.HTTPError) and error.code < 500:
                raise
            if attempt == retries - 1:
                raise
            print(f"  retry {attempt + 1} after {error}", file=sys.stderr)
            time.sleep(2 * (attempt + 1))
    raise RuntimeError("unreachable")


def repo_tree() -> list[str]:
    return [item["path"] for item in json.loads(fetch(REPO_API))["tree"]]


def windows_metadata_paths(tree: list[str]) -> list[str]:
    return sorted(p for p in tree if p.startswith("datasets/atomic/_metadata/SDWIN-") and p.endswith(".yaml"))


def download_archive(link: str, target: Path, by_name: dict[str, str]) -> bool:
    """Metadata links can be stale; fall back to the archive with the same name in the repo."""
    try:
        target.write_bytes(fetch(link))
        return True
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
    moved = by_name.get(target.name)
    if moved:
        target.write_bytes(fetch(RAW + moved))
        return True
    print(f"  missing upstream: {link}", file=sys.stderr)
    return False


def host_archives(metadata: dict) -> list[str]:
    return [
        item["link"] for item in metadata.get("files") or []
        if str(item.get("type", "")).lower() == "host" and str(item.get("link", "")).endswith(".zip")
    ]


def techniques(metadata: dict) -> list[str]:
    result = []
    for mapping in metadata.get("attack_mappings") or []:
        technique = mapping.get("technique")
        if not technique:
            continue
        sub = mapping.get("sub-technique")
        result.append(f"{technique}.{str(sub).zfill(3)}" if sub else str(technique))
    return result


def download_d3fend(technique: str) -> None:
    """Countermeasures for a technique; sub-techniques also store their parent's."""
    for candidate in dict.fromkeys([technique, technique.split(".")[0]]):
        path = D3FEND_DIR / f"{candidate}.json"
        if path.exists():
            continue
        try:
            path.write_bytes(fetch(D3FEND_API.format(technique=candidate)))
        except urllib.error.HTTPError as error:
            print(f"  D3FEND has no entry for {candidate} ({error.code})", file=sys.stderr)
            path.write_text(json.dumps({"off_to_def": {"results": {"bindings": []}}}))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--limit", type=int, default=0, help="only the first N Windows datasets (0 = all)")
    args = parser.parse_args()

    for folder in (MORDOR_DIR / "metadata", MORDOR_DIR / "host", D3FEND_DIR):
        folder.mkdir(parents=True, exist_ok=True)

    tree = repo_tree()
    by_name = {Path(p).name: p for p in tree if "/host/" in p and p.endswith(".zip")}
    paths = windows_metadata_paths(tree)
    if args.limit:
        paths = paths[: args.limit]
    print(f"{len(paths)} Windows datasets")
    index = []
    for number, path in enumerate(paths, 1):
        local = MORDOR_DIR / "metadata" / Path(path).name
        if not local.exists():
            local.write_bytes(fetch(RAW + path))
        metadata = yaml.safe_load(local.read_text(encoding="utf-8"))
        archives = []
        for link in host_archives(metadata):
            target = MORDOR_DIR / "host" / Path(link).name
            if not target.exists():
                print(f"[{number}/{len(paths)}] {target.name}")
                if not download_archive(link, target, by_name):
                    continue
            archives.append(target.name)
        found = techniques(metadata)
        for technique in found:
            download_d3fend(technique)
        index.append({
            "id": metadata.get("id"),
            "title": metadata.get("title"),
            "techniques": found,
            "tactics": sorted({t for m in metadata.get("attack_mappings") or [] for t in m.get("tactics") or []}),
            "archives": archives,
        })
    (MORDOR_DIR / "index.json").write_text(json.dumps(index, indent=2))
    usable = sum(1 for item in index if item["archives"] and item["techniques"])
    print(f"Done: {usable} datasets with host logs and ATT&CK mappings -> {MORDOR_DIR}")


if __name__ == "__main__":
    main()

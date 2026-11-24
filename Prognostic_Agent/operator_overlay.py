"""Explicit host criticality overlay; no user privilege or topology inference."""

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path

from .contracts import content_hash, parse_time, utc_text
from .private_paths import private_path, write_private
from .shadow_source import sha256_file


def apply_overlay(inventory_path, overlay_path, output_dir):
    inventory_path, overlay_path, output_dir = map(private_path, (inventory_path, overlay_path, output_dir))
    inventory = json.loads(inventory_path.read_text(encoding="utf-8-sig"))
    overlay = json.loads(overlay_path.read_text(encoding="utf-8-sig"))
    if inventory.get("environment") != "test" or not inventory.get("publishable"):
        raise ValueError("Overlay requires a publishable test inventory")
    if overlay.get("schema_version") != 1 or overlay.get("environment") != "test":
        raise ValueError("Overlay requires schema_version=1 and environment=test")
    approved = parse_time(overlay["approved_at"])
    if approved > datetime.now(timezone.utc):
        raise ValueError("Overlay approval cannot be future-dated")
    if overlay.get("provenance", {}).get("source") != "operator":
        raise ValueError("Criticality must be an explicit operator assertion")
    entries = overlay.get("hosts")
    if not isinstance(entries, list) or not entries:
        raise ValueError("Overlay needs explicit host entries")
    result = deepcopy(inventory)
    seen = set()
    for entry in entries:
        identity, criticality = entry.get("host_id"), entry.get("asset_criticality")
        if identity in seen or not isinstance(identity, str) or not identity.startswith("host:"):
            raise ValueError("Overlay host IDs must be unique explicit host identities")
        seen.add(identity)
        if criticality not in {"low", "normal", "high", "critical"}:
            raise ValueError("Overlay criticality must be explicit and valid")
        matches = [row for row in result["entities"] if row["entity_type"] == "host" and
                   identity in {row["entity_id"], row.get("canonical_id")}]
        if not matches:
            raise ValueError("Overlay host does not match this collected host; no wildcard was applied")
        for row in matches:
            row["asset_criticality"] = criticality
            row.setdefault("field_provenance", {})["asset_criticality"] = {
                "source": "operator", "approved_at": utc_text(approved), "overlay_sha256": sha256_file(overlay_path)}
    result["operator_overlay"] = {"schema_version": 1, "sha256": sha256_file(overlay_path), "approved_at": utc_text(approved)}
    # Operational source paths/import times do not alter the effective fact hash.
    facts = [{key: value for key, value in row.items() if key not in {"provenance", "field_provenance"}}
             for row in result["entities"]]
    inventory_hash = content_hash({"environment": "test", "entities": facts, "overlay_sha256": result["operator_overlay"]["sha256"]})
    result["inventory_sha256"] = inventory_hash
    output = output_dir / "inventory.json"
    write_private(output, result)
    return {"schema_version": 1, "environment": "test", "inventory_path": str(output), "inventory_sha256": inventory_hash,
            "inventory_file_sha256": sha256_file(output), "overlay_sha256": result["operator_overlay"]["sha256"],
            "hash_basis": "canonical normalized inventory facts and exact operator overlay hash; raw source SHA retained separately"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--overlay", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--environment", choices=["test"], required=True)
    args = parser.parse_args(argv)
    print(json.dumps(apply_overlay(args.inventory, args.overlay, args.output_dir), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Validate collected inventory and atomically publish its exact bytes privately."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import uuid

from .contracts import parse_time
from .private_paths import PRIVATE_DIR, private_path


class InventoryUnavailable(ValueError):
    reason = "asset_inventory_unavailable"


class InventoryStale(ValueError):
    reason = "inventory_stale"


def collected_inventory(raw, *, now=None):
    """Fail closed; filesystem mtimes and publication times never imply freshness."""
    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, UnicodeError, TypeError, AttributeError):
        raise InventoryUnavailable() from None
    if not isinstance(document, dict) or document.get("schema_version") != 1 or not isinstance(document.get("entities"), list):
        raise InventoryUnavailable()
    identities = set()
    for entity in document["entities"]:
        if (not isinstance(entity, dict) or not isinstance(entity.get("entity_id"), str) or not entity["entity_id"].strip()
            or entity.get("entity_type") not in {"host", "user", "service"} or entity["entity_id"] in identities):
            raise InventoryUnavailable()
        identities.add(entity["entity_id"])
    try:
        collected = parse_time(document["source"]["collected_at"])
    except (KeyError, TypeError, AttributeError, ValueError):
        raise InventoryStale() from None
    age = ((now or datetime.now(timezone.utc)) - collected).total_seconds()
    if age < 0 or age > 24 * 3600:
        raise InventoryStale()
    return document


def read_inventory(path, *, now=None):
    try:
        raw = Path(path).read_bytes()
    except (OSError, TypeError, ValueError):
        raise InventoryUnavailable() from None
    return raw, collected_inventory(raw, now=now)


def publish_inventory(inventory_path, raw_path, overlay_path, *, destination=None, now=None):
    inventory_path, raw_path, overlay_path = map(private_path, (inventory_path, raw_path, overlay_path))
    destination = private_path(destination or PRIVATE_DIR / "inventory-latest.json")
    raw = inventory_path.read_bytes()
    inventory = collected_inventory(raw, now=now)
    digest = lambda value: hashlib.sha256(value).hexdigest()
    overlay = json.loads(overlay_path.read_text(encoding="utf-8-sig"))
    approved = parse_time(overlay["approved_at"])
    if (inventory.get("environment") != "test" or inventory.get("publishable") is not True or
        overlay.get("schema_version") != 1 or overlay.get("environment") != "test" or
        overlay.get("provenance", {}).get("source") != "operator" or approved > (now or datetime.now(timezone.utc)) or
        inventory["source"].get("source_sha256") != digest(raw_path.read_bytes()) or
        inventory.get("operator_overlay", {}).get("sha256") != digest(overlay_path.read_bytes())):
        raise ValueError("Inventory publication provenance validation failed")
    # Revalidate the actual overlay facts, not just the presence of an overlay hash.
    hosts = overlay.get("hosts")
    if not isinstance(hosts, list) or not hosts:
        raise ValueError("Validated operator overlay required")
    seen = set()
    for host in hosts:
        identity = host.get("host_id")
        matches = [e for e in inventory["entities"] if e.get("entity_type") == "host" and identity in {e.get("entity_id"),e.get("canonical_id")}]
        if (not isinstance(identity, str) or identity in seen or not matches or
            host.get("asset_criticality") not in {"low","normal","high","critical"} or
            any(e.get("asset_criticality") != host["asset_criticality"] for e in matches)):
            raise ValueError("Overlay facts do not match effective inventory")
        seen.add(identity)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name("."+destination.name+"."+uuid.uuid4().hex+".tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # A single same-directory replacement: readers see old or new complete bytes.
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return {"environment":"test", "inventory_file_sha256":digest(raw),
            "source_sha256":inventory["source"]["source_sha256"],
            "overlay_sha256":inventory["operator_overlay"]["sha256"],
            "collected_at":inventory["source"]["collected_at"], "published":True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--raw-export", required=True)
    parser.add_argument("--overlay", required=True)
    args = parser.parse_args(argv)
    try:
        result = publish_inventory(args.inventory, args.raw_export, args.overlay)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        parser.error("Inventory publication failed validation; previous latest inventory retained")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

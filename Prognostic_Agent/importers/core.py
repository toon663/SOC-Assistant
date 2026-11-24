"""Shared offline import boundary: provenance, quarantine and versioned output."""

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import uuid

from ..asset_context import _validate_record
from ..config import AGENT_DIR, ForecastConfig
from ..contracts import parse_time, utc_text
from ..migrations import validate_environment

IMPORTER_VERSION = "1.0.0"
NULL_WORDS = {"", "unknown", "null", "n/a", "not available", "not known"}
ENUMS = {"asset_criticality": {"low", "normal", "high", "critical"},
         "privilege_level": {"none", "user", "admin", "system"},
         "platform": {"windows", "linux", "macos"}, "exposure": {"internal", "internet", "isolated"}}


def nullable_text(value):
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    value = value.strip()
    return None if value.casefold() in NULL_WORDS else value


def _issue(code, locator, detail, **extra):
    return {"code": code, "source_locator": locator, "detail": detail, **extra}


def convert_bytes(raw_bytes, *, adapter_name, source_path, environment, imported_at=None):
    """Adapter-independent normalization; no filesystem writes or live queries."""
    validate_environment(environment)
    if adapter_name != "local_export":
        raise ValueError("Only local_export is implemented; ad_csv is a documented follow-up")
    from .local_export import adapt, RAW_SCHEMA, ADAPTER_VERSION
    imported_at = imported_at or datetime.now(timezone.utc)
    if isinstance(imported_at, str):
        imported_at = parse_time(imported_at)
    if not isinstance(imported_at, datetime) or imported_at.utcoffset() is None:
        raise ValueError("imported_at must be a timezone-aware timestamp")
    imported_at = parse_time(utc_text(imported_at))
    source_hash = hashlib.sha256(raw_bytes).hexdigest()
    source = {"adapter": adapter_name, "adapter_version": ADAPTER_VERSION, "importer_version": IMPORTER_VERSION,
              "source_file": str(source_path), "source_sha256": source_hash, "source_schema": RAW_SCHEMA,
              "imported_at": utc_text(imported_at), "collected_at": None}
    quarantine, warnings, candidates, document = [], [], [], None
    try:
        def reject_constant(value):
            raise ValueError("Non-finite JSON constant: " + value)
        document = json.loads(raw_bytes.decode("utf-8-sig"), parse_constant=reject_constant)
        if not isinstance(document, dict) or document.get("schema") != RAW_SCHEMA:
            raise ValueError("Expected " + RAW_SCHEMA)
        collected_at = parse_time(document["collected_at"])
        if collected_at > imported_at:
            raise ValueError("Source collected_at is future-dated")
        source["collected_at"] = utc_text(collected_at)
        converted = adapt(document)
        candidates = converted["candidates"]
        quarantine.extend(converted["quarantine"])
        warnings.extend(converted["issues"])
    except (UnicodeError, ValueError, KeyError, TypeError, AttributeError) as exc:
        quarantine.append(_issue("document_quarantined", "$", str(exc), kind="document"))
    valid = []
    for candidate in candidates:
        record = deepcopy(candidate["record"])
        locator = candidate["locator"]
        try:
            for key, choices in ENUMS.items():
                original = record.get(key)
                normalized = nullable_text(original)
                normalized = normalized.casefold() if normalized is not None else None
                if normalized is not None and normalized not in choices:
                    warnings.append(_issue("invalid_optional_enum", locator + "." + key, "Unrecognized value retained as null"))
                    normalized = None
                record[key] = normalized
            record["asset_owner"] = nullable_text(record.get("asset_owner"))
            last_updated = candidate.get("last_updated")
            if last_updated is not None:
                try:
                    last_updated = utc_text(parse_time(last_updated))
                    if parse_time(last_updated) > parse_time(source["collected_at"]):
                        raise ValueError("last_updated is later than collection")
                except (AttributeError, TypeError, ValueError):
                    last_updated = None
                    warnings.append(_issue("invalid_last_updated", locator, "Source update time is unknown; collection time is not substituted"))
            record.update(environment=environment, as_of=source["collected_at"], last_updated=last_updated,
                          provenance={**source, "source_locator": locator, "last_updated": last_updated})
            aliases = sorted(set(candidate.get("aliases", [])) | {record["entity_id"]})
            if any(not isinstance(identity, str) or not identity.strip() for identity in aliases):
                raise ValueError("Invalid alias identity")
            for identity in aliases:
                _validate_record({**record, "entity_id": identity}, identity, imported_at, ForecastConfig(environment=environment))
            valid.append({"record": record, "aliases": aliases, "locator": locator})
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            quarantine.append(_issue("record_quarantined", locator, str(exc), kind="record"))
    owners = {}
    for index, candidate in enumerate(valid):
        for identity in candidate["aliases"]:
            owners.setdefault(identity, set()).add(index)
    collisions = {index for indices in owners.values() if len(indices) > 1 for index in indices}
    entities = []
    for index, candidate in enumerate(valid):
        if index in collisions:
            quarantine.append(_issue("identity_collision", candidate["locator"],
                                     "All aliases of this ambiguous source record were quarantined", kind="record"))
        else:
            entities.extend({**deepcopy(candidate["record"]), "entity_id": identity} for identity in candidate["aliases"])
    entities.sort(key=lambda record: record["entity_id"])
    publishable = any(record["entity_type"] == "host" for record in entities)
    inventory = {"schema_version": 1, "environment": environment, "importer_version": IMPORTER_VERSION,
                 "source": source, "publishable": publishable, "entities": entities}
    issues = {"schema_version": 1, "environment": environment, "source": source,
              "status": "complete" if publishable and not quarantine else ("partial" if publishable else "quarantined"),
              "publishable": publishable, "emitted_records": len(entities),
              "canonical_entities": len({record["canonical_id"] for record in entities}),
              "quarantine": quarantine, "issues": warnings}
    return inventory, issues


def import_inventory(input_path, *, adapter_name="local_export", environment, output_root=None, imported_at=None):
    """Read source once; write a new exclusive version directory inside this agent."""
    input_path = Path(input_path).resolve()
    output_root = Path(output_root or AGENT_DIR / "private" / "imports").resolve()
    if not output_root.is_relative_to(AGENT_DIR.resolve()):
        raise ValueError("Inventory outputs must stay inside Prognostic_Agent")
    raw_bytes = input_path.read_bytes()
    inventory, issues = convert_bytes(raw_bytes, adapter_name=adapter_name, source_path=input_path,
                                     environment=environment, imported_at=imported_at)
    if hashlib.sha256(input_path.read_bytes()).hexdigest() != inventory["source"]["source_sha256"]:
        raise ValueError("Source changed during import; no inventory was published")
    stamp = parse_time(inventory["source"]["imported_at"]).strftime("%Y%m%dT%H%M%S%fZ")
    version = adapter_name + "-v1_" + stamp + "_" + inventory["source"]["source_sha256"][:12] + "_" + uuid.uuid4().hex[:8]
    directory = output_root / version
    directory.mkdir(parents=True, exist_ok=False)
    for filename, value in (("inventory.json", inventory), ("issues.json", issues)):
        with (directory / filename).open("x", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
    return {"schema_version": 1, "response_type": "inventory_import_result", "importer_version": IMPORTER_VERSION,
            "adapter": adapter_name, "environment": environment, "status": issues["status"], "publishable": issues["publishable"],
            "inventory_path": str(directory / "inventory.json"), "issues_path": str(directory / "issues.json"),
            "source_sha256": inventory["source"]["source_sha256"], "emitted_records": issues["emitted_records"],
            "canonical_entities": issues["canonical_entities"], "quarantine_count": len(issues["quarantine"])}

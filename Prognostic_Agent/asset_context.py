"""Deadline-bounded asset providers. Child processes stream completed lookups.

Providers must be picklable, importable implementations (Windows spawn). No
backend dependency, privilege escalation, inventory discovery, or IP lookup.
"""

from datetime import datetime
import json
import multiprocessing
from pathlib import Path
import time
from typing import Protocol

from .config import ForecastConfig
from .contracts import canonical_json, parse_time


class AssetProvider(Protocol):
    name: str

    def lookup(self, entity: dict, *, deadline: float) -> dict | None:
        """Return a JSON record or None. deadline is absolute time.monotonic()."""
        ...


class LocalJSONAssetProvider:
    name = "local_json"

    def __init__(self, path: str | Path):
        self.path = str(Path(path).resolve())
        self._records = None

    def lookup(self, entity, *, deadline):
        if self._records is None:
            with open(self.path, encoding="utf-8") as stream:
                document = json.load(stream)
            if document.get("schema_version") != 1 or not isinstance(document.get("entities"), list):
                raise ValueError("Inventory must have schema_version 1 and an entities array")
            self._records = {}
            for record in document["entities"]:
                identity = record["entity_id"]
                if identity in self._records:
                    raise ValueError("Inventory has duplicate entity IDs")
                self._records[identity] = record
        return self._records.get(entity["entity_id"])


def _provider_worker(provider, entities, sender, deadline):
    try:
        for entity in entities:
            if time.monotonic() >= deadline:
                sender.send(("timeout", None, None))
                return
            result = provider.lookup(entity, deadline=deadline)
            # Prevent opaque objects or nonfinite values entering the contract.
            canonical_json(result)
            sender.send(("record", entity["entity_id"], result))
        sender.send(("done", None, None))
    except Exception as exc:
        sender.send(("error", None, type(exc).__name__))
    finally:
        sender.close()


def _validate_record(record, identity, as_of, config):
    if not isinstance(record, dict) or record.get("entity_id") != identity:
        raise ValueError("identity_mismatch")
    if record.get("entity_type") not in {"user", "host", "service"}:
        raise ValueError("invalid_entity_type")
    record = json.loads(canonical_json(record))
    if not isinstance(record.get("canonical_id", identity), str):
        raise ValueError("invalid_canonical_id")
    if record.get("asset_owner") is not None and not isinstance(record["asset_owner"], str):
        raise ValueError("invalid_asset_owner")
    for field, choices in {
        "asset_criticality": {"low", "normal", "high", "critical", None},
        "privilege_level": {"none", "user", "admin", "system", None},
        "exposure": {"internal", "internet", "isolated", None},
        "platform": {"windows", "linux", "macos", None},
    }.items():
        if record.get(field) not in choices:
            raise ValueError("invalid_" + field)
    if "privilege_scope_host_ids" in record:
        scopes = record["privilege_scope_host_ids"]
        if (not isinstance(scopes, list) or not scopes or
            any(not isinstance(identity, str) or not identity.startswith("host:") or not identity[5:] for identity in scopes) or
            len(scopes) != len(set(scopes))):
            raise ValueError("invalid_privilege_scope_host_ids")
    observed = parse_time(record["as_of"])
    age = (as_of - observed).total_seconds()
    if age < 0:
        raise ValueError("future_asset_context")
    stale = age > config.asset_context_freshness_hours * 3600
    related = record.get("related_assets", [])
    if not isinstance(related, list):
        raise ValueError("invalid_related_assets")
    for relation in related:
        if not isinstance(relation, dict) or not isinstance(relation.get("entity_id"), str) or relation.get("entity_type") not in {"user", "host", "service"}:
            raise ValueError("invalid_related_asset")
        if not isinstance(relation.get("relation"), str) or not isinstance(relation.get("evidence_ref"), str):
            raise ValueError("relationship_evidence_required")
        if type(relation.get("reachable")) is not bool:
            raise ValueError("reachable_boolean_required")
    record["stale"] = stale
    return record


def enrich_asset_context(alert: dict, providers: list[AssetProvider], config: ForecastConfig, as_of: datetime) -> dict:
    """Preserve completed per-entity results under hard per-provider deadlines."""
    entities = alert["entities"]
    records, issues, provider_stats = {}, [], []
    fallback_replacements = 0
    names = [provider.name for provider in providers]
    if len(names) != len(set(names)):
        raise ValueError("Asset provider names must be unique")
    total_deadline = time.monotonic() + config.enrichment_timeout_seconds
    context = multiprocessing.get_context("spawn")
    for provider in providers:
        provider_started = time.monotonic()
        completed = 0
        if not entities:
            break
        remaining = total_deadline - time.monotonic()
        if remaining <= 0:
            issues.append({"code": "asset_lookup_timeout", "provider": provider.name, "detail": "Total enrichment deadline exhausted."})
            continue
        deadline = time.monotonic() + min(config.provider_timeout(provider.name), remaining)
        try:
            receiver, sender = context.Pipe(duplex=False)
        except OSError as exc:
            issues.append({"code": "asset_provider_error", "provider": provider.name, "detail": type(exc).__name__})
            continue
        process = context.Process(target=_provider_worker, args=(provider, entities, sender, deadline), daemon=True)
        finished = False
        try:
            process.start()
            sender.close()
            while time.monotonic() < deadline:
                if not receiver.poll(max(0, deadline - time.monotonic())):
                    break
                try:
                    kind, identity, value = receiver.recv()
                except EOFError:
                    break
                if kind == "done":
                    finished = True
                    break
                if kind == "timeout":
                    break
                if kind == "error":
                    issues.append({"code": "asset_provider_error", "provider": provider.name, "detail": value})
                    finished = True
                    break
                if value is not None:
                    try:
                        value = _validate_record(value, identity, as_of, config)
                        expected = next(e["entity_type"] for e in entities if e["entity_id"] == identity)
                        if value["entity_type"] != expected:
                            raise ValueError("entity_type_mismatch")
                    except (KeyError, TypeError, ValueError) as exc:
                        issues.append({"code": "asset_record_invalid", "provider": provider.name, "entity_id": identity, "detail": str(exc)})
                        continue
                    # Provider order determines priority; a fresh fallback may replace stale data.
                    if identity not in records or (records[identity]["stale"] and not value["stale"]):
                        if identity in records:
                            fallback_replacements += 1
                        records[identity] = {**value, "provider": provider.name}
                        completed += 1
            if not finished:
                issues.append({"code": "asset_lookup_timeout", "provider": provider.name, "detail": "Provider deadline exceeded; completed lookups retained."})
        except (OSError, TypeError, AttributeError, RuntimeError) as exc:
            issues.append({"code": "asset_provider_error", "provider": provider.name, "detail": type(exc).__name__})
        finally:
            sender.close()
            receiver.close()
            if process.pid is not None:
                if process.is_alive():
                    process.terminate()
                process.join(timeout=0.2)
                if process.is_alive():
                    process.kill()
                    process.join(timeout=0.2)
                process.close()
            provider_stats.append({"provider": provider.name, "elapsed_ms": round((time.monotonic() - provider_started) * 1000, 3), "accepted_records": completed})
    missing = []
    fields = ("asset_criticality", "asset_owner", "privilege_level", "exposure", "platform")
    for entity in entities:
        identity = entity["entity_id"]
        record = records.get(identity)
        if record is None:
            missing.append({"entity_id": identity, "fields": list(fields)})
        else:
            gaps = [field for field in fields if record.get(field) is None]
            if gaps:
                missing.append({"entity_id": identity, "fields": gaps})
            if record["stale"]:
                issues.append({"code": "asset_context_stale", "entity_id": identity, "detail": "Asset snapshot exceeds its freshness limit."})
    if missing:
        issues.append({"code": "asset_context_incomplete", "detail": "Some supplied entities or context fields are unresolved."})
    fresh_fields = sum(sum(record.get(field) is not None for field in fields) for record in records.values() if not record["stale"])
    return {"entities": [records[key] for key in sorted(records)], "missing_fields": missing,
            "coverage": len(records) / len(entities) if entities else 0.0,
            "fresh_field_coverage": fresh_fields / (len(entities) * len(fields)) if entities else 0.0,
            "issues": issues, "provider_stats": provider_stats, "fallback_replacements": fallback_replacements}

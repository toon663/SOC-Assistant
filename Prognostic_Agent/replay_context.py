"""Counterfactual replay context and redacted host matching diagnostics."""

from collections import Counter, defaultdict
from copy import deepcopy
import socket

from .contracts import parse_time, utc_text


def host_form(value):
    return str(value or "").strip().casefold().removeprefix("host:").rstrip(".")


def host_audit(incidents, inventory):
    hosts = sorted({event.get("host") for item in incidents.values() for event in item["events"] if event.get("host")})
    aliases = sorted({host_form(value) for record in inventory["entities"] if record["entity_type"] == "host"
                      for value in (record["entity_id"], record.get("canonical_id", record["entity_id"]))})
    machine = host_form(socket.gethostname())
    rows = []
    lookup_ids = {str(record["entity_id"]).strip().casefold() for record in inventory["entities"] if record["entity_type"] == "host"}
    for index, host in enumerate(hosts, 1):
        normalized = host_form(host)
        rows.append({"host_alias": "recorded_host_" + str(index), "casefold_exact_match": normalized in aliases,
                     "current_lookup_match": "host:" + str(host).strip().casefold() in lookup_ids,
                     "short_name_match": any(normalized.split(".")[0] == alias.split(".")[0] for alias in aliases),
                     "is_fqdn": "." in normalized, "is_this_machine": normalized == machine,
                     "incident_count": sum(any(host_form(e.get("host")) == normalized for e in item["events"]) for item in incidents.values())})
    return {"inventory_aliases": ["inventory_host_" + str(index) for index in range(1, len(aliases)+1)],
            "machine_matches_inventory": machine in aliases, "machine_appears_in_incidents": any(row["is_this_machine"] for row in rows),
            "rows": rows, "comparison": "Adapter casefolds host IDs; current lookup is exact. Diagnostic also checks trailing-dot and short-name/FQDN forms; it does not assert DNS alias equivalence."}


def causal_inventory(inventory, events, cutoff):
    # Historical criticality is an explicit operator what-if assumption. Never
    # backdate today's observed privileges, platform, account controls or topology.
    result = deepcopy(inventory)
    result["entities"] = [row for row in result["entities"] if parse_time(row["as_of"]) <= cutoff]
    hosts = {host_form(event.get("host")) for event in events if event.get("host")}
    result["entities"] = [row for row in result["entities"] if not (row["entity_type"] == "host" and host_form(row["entity_id"]) in hosts)]
    for host in sorted(hosts):
        result["entities"].append({"entity_id": "host:" + host, "canonical_id": "host:" + host,
            "entity_type": "host", "environment": "test", "source": "operator_replay", "as_of": utc_text(cutoff),
            "asset_criticality": "normal", "asset_owner": None, "privilege_level": None, "exposure": None, "platform": None,
            "provenance": {"source": "operator_replay", "basis": "User-authorized normal criticality for recorded hosts, replay only; historical assumption, not observed inventory"}})
    result["source"] = "operator_replay"
    return result


def verdict_coverage(results):
    hosts = defaultdict(set)
    incidents, techniques = Counter(), Counter()
    for result in results:
        verdict = result["analyst"]["verdict"]
        incidents[verdict] += 1
        hosts[verdict].update(result["recorded_host_aliases"])
        techniques.update(result["analyst"]["mitre_techniques"])
    return {"by_verdict": [{"verdict": verdict, "incidents": count, "distinct_hosts": len(hosts[verdict])} for verdict, count in sorted(incidents.items())],
            "technique_incident_counts": dict(techniques),
            "note": "Hosts are counted distinctly within each verdict and can appear in multiple verdict groups."}

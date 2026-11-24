"""local_context_raw.v1 adapter. No network topology or domain privilege inference."""

from copy import deepcopy
import re

from .core import nullable_text

RAW_SCHEMA = "local_context_raw.v1"
ADAPTER_VERSION = "1.0.1"
SID = re.compile(r"^S-\d+-\d+(?:-\d+)+$", re.I)


def adapt(document):
    candidates, quarantine, issues = [], [], []
    singletons = set()

    def issue(code, locator, detail, *, quarantined=False, kind="record", **extra):
        value = {"code": code, "source_locator": locator, "detail": detail, **extra}
        if quarantined:
            value["kind"] = kind
        (quarantine if quarantined else issues).append(value)

    def collection(value, locator):
        if value is None:
            return None
        if isinstance(value, dict) and "sid" in value:
            singletons.add(locator)
            issue("singleton_collection_normalized", locator, "PowerShell singleton object normalized to a list")
            return [value]
        if not isinstance(value, list):
            issue("invalid_collection", locator, "Expected an array or singleton principal", quarantined=True, kind="section")
            return None
        return value

    def boolean(value, locator):
        if value is None or type(value) is bool:
            return value
        issue("invalid_optional_boolean", locator, "Non-boolean source value retained as null")
        return None

    def valid_identity(row, locator):
        if not isinstance(row, dict) or not nullable_text(row.get("name")) or not isinstance(row.get("sid"), str) or not SID.fullmatch(row["sid"]):
            issue("invalid_principal_identity", locator, "A nonempty name and valid SID are required", quarantined=True)
            return False
        return True

    source_errors = document.get("errors") or []
    singleton_errors = isinstance(source_errors, dict)
    failed_sections = set()
    if isinstance(source_errors, dict):
        source_errors = [source_errors]
    if not isinstance(source_errors, list):
        issue("invalid_collection", "$.errors", "Expected a list of collection errors", quarantined=True, kind="section")
        source_errors = []
    for index, error in enumerate(source_errors):
        if isinstance(error, dict):
            section = nullable_text(error.get("section")) or "unspecified"
            failed_sections.add(section)
            message = str(error.get("message") or "Collection failed")
            group_sid = section[6:] if section.startswith("group:") else None
            missing_group = bool(group_sid and SID.fullmatch(group_sid) and
                re.fullmatch(r"Group\s+" + re.escape(group_sid) + r"\s+was not found\.?", message.strip(), re.I))
            issue("group_not_found" if missing_group else "collection_failed",
                  "$.errors" if singleton_errors else f"$.errors[{index}]", message,
                  quarantined=not missing_group, kind="section", section=section,
                  source_status="not_present" if missing_group else "unavailable")
        else:
            issue("invalid_collection_error", f"$.errors[{index}]", "Error entry must be an object", quarantined=True, kind="section")
    host = document.get("host")
    if not isinstance(host, dict) or not nullable_text(host.get("hostname")) or "host" in failed_sections:
        issue("host_context_unavailable", "$.host", "Local principals cannot be scoped without a collected hostname", quarantined=True, kind="section")
        return {"candidates": [], "quarantine": quarantine, "issues": issues}
    hostname = host["hostname"].strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}", hostname):
        issue("invalid_host_identity", "$.host.hostname", "Unsupported or ambiguous host identifier", quarantined=True, kind="section")
        return {"candidates": [], "quarantine": quarantine, "issues": issues}
    host_id = "host:" + hostname.casefold()
    accounts = collection(document.get("accounts"), "$.accounts")
    if "accounts" in failed_sections:
        accounts = None
    local = {}
    for index, account in enumerate(accounts or []):
        locator = "$.accounts" if "$.accounts" in singletons else f"$.accounts[{index}]"
        if valid_identity(account, locator):
            local.setdefault(account["sid"].casefold(), []).append((account, locator))
    groups = document.get("groups") if isinstance(document.get("groups"), dict) else {}
    administrators = collection(groups.get("administrators"), "$.groups.administrators")
    if "group:S-1-5-32-544" in failed_sections:
        administrators = None
    if administrators is None:
        issue("local_admin_membership_unavailable", "$.groups.administrators", "No local-account admin privilege was inferred")
    admin_sids, conflicted, principals, extra_users = set(), set(), [], []
    for index, member in enumerate(administrators or []):
        locator = "$.groups.administrators" if "$.groups.administrators" in singletons else f"$.groups.administrators[{index}]"
        if not valid_identity(member, locator):
            continue
        identity = member["sid"].casefold()
        source = nullable_text(member.get("source"))
        klass = nullable_text(member.get("object_class"))
        source_kind, object_kind = (source or "").casefold(), (klass or "").casefold()
        is_local = identity in local
        conflict = is_local and source_kind in {"activedirectory", "azuread"}
        if conflict:
            conflicted.add(identity)
            issue("principal_source_conflict", locator, "Local SID and external source disagree; membership cannot establish privilege", quarantined=True)
        known_admin = is_local and not conflict and object_kind == "user"
        if known_admin:
            admin_sids.add(identity)
        principals.append({"name": member["name"], "sid": member["sid"], "object_class": klass,
                           "principal_source": source, "is_local_account": is_local,
                           "privilege_level": "admin" if known_admin else None})
        if not is_local:
            issue("external_principal_privilege_unresolved", locator, "Local group membership does not establish domain/external privilege")
            if object_kind == "user":
                extra_users.append((member, locator))
            elif object_kind == "group":
                issue("group_principal_not_expanded", locator, "Nested group membership was not enumerated; no member privileges were invented")
    for principal in principals:
        if principal["sid"].casefold() in conflicted:
            principal["privilege_level"] = None
    base = {"asset_owner": None, "asset_criticality": None, "exposure": None, "privilege_level": None,
            "platform": host.get("platform")}
    host_record = {**base, "entity_id": host_id, "canonical_id": host_id, "entity_type": "host",
                   "source_attributes": {"hostname": hostname, "os_caption": nullable_text(host.get("os_caption")),
                                         "os_version": nullable_text(host.get("os_version")), "os_build": nullable_text(host.get("os_build")),
                                         "domain_joined": boolean(host.get("domain_joined"), "$.host.domain_joined"),
                                         "domain_or_workgroup": nullable_text(host.get("domain_or_workgroup")),
                                         "addresses": deepcopy(document.get("addresses")), "listeners": deepcopy(document.get("listeners")),
                                         "firewall_profiles": deepcopy(document.get("firewall_profiles")),
                                         "administrator_principals": principals}}
    candidates.append({"record": host_record, "aliases": [host_id], "locator": "$.host"})
    for identity, rows in local.items():
        for account, locator in rows:
            name = account["name"].strip()
            if "\\" in name or any(ord(char) < 32 for char in name):
                issue("invalid_local_account_name", locator, "Expected an unqualified local account name", quarantined=True)
                continue
            canonical = "user:" + identity
            primary = "user:" + hostname.casefold() + "\\" + name.casefold()
            is_admin = identity in admin_sids and identity not in conflicted
            disabled = boolean(account.get("disabled"), locator + ".disabled")
            record = {**base, "entity_id": primary, "canonical_id": canonical, "entity_type": "user",
                      "privilege_level": "admin" if is_admin else None,
                      "source_attributes": {"is_local_account": True, "name": name, "sid": account["sid"],
                                            "host_id": host_id, "last_logon": account.get("last_logon"),
                                            "password_required": boolean(account.get("password_required"), locator + ".password_required")},
                      "account_controls": {"host_id": host_id, "enabled": None if disabled is None else not disabled,
                                           "locked": boolean(account.get("locked_out"), locator + ".locked_out"), "blocked": None}}
            if is_admin:
                record["privilege_scope_host_ids"] = [host_id]
            candidates.append({"record": record, "aliases": [primary, "user:" + name.casefold(), canonical], "locator": locator})
    for member, locator in extra_users:
        name = member["name"].strip().casefold()
        if "\\" not in name and "@" not in name:
            issue("unqualified_external_principal", locator, "External names need a namespace", quarantined=True)
            continue
        canonical = "user:" + member["sid"].casefold()
        primary = "user:" + name
        record = {**base, "platform": None, "entity_id": primary, "canonical_id": canonical, "entity_type": "user",
                  "source_attributes": {"is_local_account": False if (nullable_text(member.get("source")) or "").casefold() in {"activedirectory", "azuread"} else None,
                                        "sid": member["sid"], "name": member["name"],
                                        "principal_source": nullable_text(member.get("source"))},
                  "account_controls": {"enabled": None, "locked": None, "blocked": None}}
        candidates.append({"record": record, "aliases": [primary, canonical], "locator": locator})
    issue("unsupported_facts_unknown", "$", "Owner, business criticality, exposure, source update time, topology and authentication blocking were not inferred. related_assets is omitted.")
    return {"candidates": candidates, "quarantine": quarantine, "issues": issues}

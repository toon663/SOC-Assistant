"""Optional caller-supplied, event-bound guard assertions. No fact discovery."""

from copy import deepcopy
import ipaddress

from .contracts import TECHNIQUE, parse_time, utc_text

ASSERTION_FIELDS = {
    "analyst_correlation": {"activity", "event_count", "window_start", "window_end"},
    "authentication_reachability": {"reachable"},
    "account_authentication": {"enabled", "locked", "blocked"},
}
SUBJECT_FIELDS = {"technique_id", "seed_event_id", "user_id", "host_id", "source_ip", "endpoint_id"}


def canonical_ip(value):
    return str(ipaddress.ip_address(value))


def normalize_guard_context(value, alert):
    """Validate/normalize only explicit assertions, preserving unknown booleans.

    Source labels record provenance; callers must authenticate their upstream
    producers. This pure library cannot authenticate a claim by its source name.
    """
    context = deepcopy(value)

    def require(condition, message):
        if not condition:
            raise ValueError(message)

    def text(obj, key):
        require(isinstance(obj.get(key), str) and bool(obj[key].strip()), "Missing/non-string " + key)
        obj[key] = obj[key].strip()

    def stamp(obj, key):
        try:
            obj[key] = utc_text(parse_time(obj[key]))
        except (KeyError, AttributeError, TypeError, ValueError):
            raise ValueError("Invalid guard timestamp: " + key) from None

    require(isinstance(context, dict), "guard_context must be an object")
    require(set(context) == {"schema_version", "bindings"}, "Unknown/missing guard-context field")
    require(type(context["schema_version"]) is int and context["schema_version"] == 1, "Unsupported guard-context version")
    require(isinstance(context["bindings"], list), "Guard bindings must be an array")
    events = {event["event_id"]: event for event in alert["normalized_events"]}
    entities = {entity["entity_id"]: entity for entity in alert["entities"]}
    techniques = {item["technique_id"]: item for item in alert["observed_techniques"]}
    seen = set()
    for binding in context["bindings"]:
        require(isinstance(binding, dict), "Guard binding must be an object")
        require(SUBJECT_FIELDS <= set(binding) and not (set(binding) - SUBJECT_FIELDS - set(ASSERTION_FIELDS)),
                "Unknown/missing guard-binding field")
        for key in SUBJECT_FIELDS:
            text(binding, key)
        technique, identity = binding["technique_id"], binding["seed_event_id"]
        require(bool(TECHNIQUE.fullmatch(technique)) and technique in techniques, "Guard technique must be supplied")
        require(identity in events and identity in techniques[technique]["evidence_refs"], "Guard seed must support the supplied technique")
        pair = (technique, identity)
        require(pair not in seen, "Ambiguous duplicate guard binding")
        seen.add(pair)
        for key, kind in (("user_id", "user"), ("host_id", "host")):
            reference = binding[key]
            require(reference in entities and entities[reference]["entity_type"] == kind and
                    reference in events[identity]["entity_ids"], "Guard subject must occur in its seed event: " + key)
        try:
            binding["source_ip"] = canonical_ip(binding["source_ip"])
        except ValueError:
            raise ValueError("Invalid guard source_ip") from None
        for name, fields in ASSERTION_FIELDS.items():
            if name not in binding:
                continue
            assertion = binding[name]
            common = {"source", "as_of", "evidence_refs"}
            require(isinstance(assertion, dict), "Guard assertion must be an object")
            require(common <= set(assertion) and not (set(assertion) - common - fields), "Unknown/missing assertion field")
            text(assertion, "source")
            stamp(assertion, "as_of")
            refs = assertion["evidence_refs"]
            require(isinstance(refs, list) and all(isinstance(ref, str) and ref in events for ref in refs),
                    "Guard evidence must reference supplied events")
            require(len(refs) == len(set(refs)), "Duplicate guard evidence reference")
            assertion["evidence_refs"] = sorted(refs)
            if name == "analyst_correlation":
                require(fields <= set(assertion), "Incomplete Analyst correlation assertion")
                require(assertion["activity"] in ("online_authentication_failures", "offline_password_cracking", "unknown"),
                        "Invalid correlation activity")
                require(type(assertion["event_count"]) is int and assertion["event_count"] >= 0, "Invalid correlation count")
                stamp(assertion, "window_start")
                stamp(assertion, "window_end")
                require(parse_time(assertion["window_start"]) <= parse_time(assertion["window_end"]), "Reversed correlation window")
            else:
                for field in fields:
                    require(assertion.get(field) is None or type(assertion[field]) is bool, "Guard state must be boolean or null")
    context["bindings"].sort(key=lambda binding: (binding["technique_id"], binding["seed_event_id"]))
    return context

"""Strict transition-rule contracts. Declarations never manufacture guard facts."""

import math

from .contracts import TECHNIQUE, canonical_json

GUARD_FIELDS = {
    "exact_attribution": {},
    "evidence_freshness": {"max_age_hours": "positive_number"},
    "analyst_correlation": {"minimum_events": "positive_integer", "window_hours": "positive_number"},
    "authentication_reachability": {},
    "account_authentication": {},
    "target_not_observed": {},
}
RULE_FIELDS = {"rule_id", "source", "include_subtechniques", "excluded_subtechniques",
               "target", "target_name", "platform", "minimum_privilege",
               "requires_reachable_target", "rationale", "references"}
REQUIRED_RULE_FIELDS = RULE_FIELDS - {"include_subtechniques", "excluded_subtechniques"}


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_rule_document(document):
    """Validate without mutation; no SDK/JSON-schema dependency or expressions."""
    _require(isinstance(document, dict), "Transition rules must be an object")
    _require(not (set(document) - {"schema_version", "version", "description", "rules"}), "Unknown rule-document field")
    version = document.get("schema_version")
    _require(type(version) is int and version in (1, 2), "Unsupported transition-rule schema")
    _require(isinstance(document.get("version"), str) and bool(document["version"].strip()), "Rules require a nonempty version")
    _require(isinstance(document.get("description", ""), str), "Rule description must be a string")
    _require(isinstance(document.get("rules"), list), "Rules must be an array")
    canonical_json(document)
    seen = set()
    for rule in document["rules"]:
        _require(isinstance(rule, dict), "Each transition rule must be an object")
        allowed = RULE_FIELDS | ({"guards", "terminal"} if version == 2 else set())
        _require(not (set(rule) - allowed), "Unknown rule field or v2 guard field in a v1 document")
        _require(REQUIRED_RULE_FIELDS <= set(rule), "Transition rule is missing required fields")
        for key in ("rule_id", "target_name", "rationale"):
            _require(isinstance(rule[key], str) and bool(rule[key].strip()), "Invalid rule " + key)
        _require(rule["rule_id"] not in seen, "Duplicate rule ID")
        seen.add(rule["rule_id"])
        for key in ("source", "target"):
            _require(isinstance(rule[key], str) and bool(TECHNIQUE.fullmatch(rule[key])), "Invalid rule technique")
        _require(rule["minimum_privilege"] in ("none", "user", "admin", "system"), "Invalid minimum privilege")
        _require(rule["platform"] in ("windows", "linux", "macos"), "Invalid rule platform")
        _require(type(rule["requires_reachable_target"]) is bool, "Invalid reachability prerequisite")
        _require(type(rule.get("include_subtechniques", True)) is bool, "Invalid sub-technique restriction")
        excluded = rule.get("excluded_subtechniques", [])
        _require(isinstance(excluded, list), "Invalid excluded sub-techniques")
        _require(all(isinstance(item, str) and TECHNIQUE.fullmatch(item) for item in excluded), "Invalid excluded sub-technique")
        _require(len(set(excluded)) == len(excluded), "Duplicate excluded sub-technique")
        references = rule["references"]
        _require(isinstance(references, list) and bool(references) and
                 all(isinstance(item, str) and bool(item.strip()) for item in references), "Invalid rule references")
        _require(type(rule.get("terminal", False)) is bool, "terminal must be boolean")
        guards = rule.get("guards", [])
        _require(isinstance(guards, list), "guards must be an array")
        guard_types = set()
        for guard in guards:
            _require(isinstance(guard, dict), "Each guard must be an object")
            kind = guard.get("type")
            _require(isinstance(kind, str) and kind in GUARD_FIELDS, "Unknown guard type")
            _require(kind not in guard_types, "Duplicate guard type")
            guard_types.add(kind)
            fields = GUARD_FIELDS[kind]
            _require(set(guard) == {"type", *fields}, "Missing or unknown guard parameter")
            for name, constraint in fields.items():
                value = guard[name]
                if constraint == "positive_integer":
                    valid = type(value) is int and value > 0
                else:
                    valid = (type(value) in (int, float) and 0 < value <= 1.7976931348623157e308
                             and math.isfinite(value))
                _require(valid, "Guard " + name + " must be a finite positive " + constraint.split("_")[1])
    return document

"""Versioned, shadow-only handoff. No backend imports, SDKs or import-time I/O."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import math
import re

from .contracts import canonical_json, parse_time, utc_text
from .provenance import AGENT_VERSION, CONFIG_VERSION

CONTRACT = "prognostic_forecast_for_orchestrator.v1"
RANKING_MEANING = "candidate_ranking_not_probability_or_severity"
OBSERVED_MEANING = "present_in_evidence_not_proven_compromise"
REACHABLE_MEANING = "potentially_reachable_not_proven_compromise"


class ContractError(ValueError):
    def __init__(self, code, field="$"):
        self.code = code
        self.field = field
        super().__init__(code + ":" + field)  # Never echo rejected values.


def _finite(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def _text(nullable=False, pattern=None):
    result = {"type": ["string", "null"] if nullable else "string", "minLength": 1}
    if pattern:
        result["pattern"] = pattern
    return result


def _number(nullable=True, maximum=None, minimum=0, integer=False):
    kind = "integer" if integer else "number"
    result = {"type": [kind, "null"] if nullable else kind, "minimum": minimum}
    if maximum is not None:
        result["maximum"] = maximum
    return result


def _object(properties, nullable=False):
    return {"type": ["object", "null"] if nullable else "object", "properties": properties,
            "required": list(properties), "additionalProperties": False}


def contract_schema():
    technique = r"^T\d{4}(?:\.\d{3})?$"
    string_list = {"type": "array", "items": _text(), "uniqueItems": True}
    entity = _object({"entity_id": _text(), "entity_type": {"enum": ["user", "host", "service"]},
                      "evidence_refs": string_list, "source_entity_id": _text(True)})
    entities = {"type": ["array", "null"], "items": entity}
    stamp = {**_text(True), "format": "date-time"}
    schema = _object({
        "contract": {"const": CONTRACT}, "contract_version": {"type": "integer", "const": 1},
        "execution_mode": {"const": "shadow_only"},
        "request_id": _text(True), "alert_id": _text(True), "analyst_revision": _text(True),
        "input_fingerprint": _text(True, r"^[a-f0-9]{64}$"),
        "forecast_id": _text(True), "forecast_revision": _number(integer=True, minimum=1),
        "response_type": {"enum": ["risk_forecast", "validation_error", "operational_error", "skipped_benign"]},
        "status": {"enum": ["complete", "partial", "abstained", None]}, "reason": _text(),
        "numeric_assessment_status": {"enum": ["complete", "partial", "unavailable"]},
        "explanation_status": {"enum": ["deterministic", "llm_selected", "unavailable"]},
        "risk_score": _number(maximum=100),
        "risk_score_basis": {"enum": ["contextual_risk_assessment", "impact_assessment_only", None]},
        "risk_score_may_include_asset_impact": {"type": ["boolean", "null"]},
        "behavioral_score_source": {"enum": ["supplied", "unknown"]},
        "selected_path": _object({"candidate_id": _text(), "starting_technique": _text(pattern=technique),
            "steps": {"type": "array", "minItems": 1, "items": _object({"technique_id": _text(pattern=technique), "rule_id": _text()})},
            "source_entity_ids": string_list, "evidence_refs": string_list}, nullable=True),
        "destination_technique": _text(True, technique), "likelihood_index": _number(maximum=1),
        "likelihood_index_meaning": {"const": RANKING_MEANING}, "probability": {"type": "null"},
        "blast_radius": _object({"observed_entities": entities, "potentially_reachable_entities": entities,
            "observed_count": _number(integer=True), "potentially_reachable_count": _number(integer=True),
            "inventory_coverage": _number(maximum=1), "truncated": {"type": ["boolean", "null"]},
            "observed_meaning": {"const": OBSERVED_MEANING}, "reachable_meaning": {"const": REACHABLE_MEANING}}),
        "time_horizon": _object({"start": {**_text(), "format": "date-time"}, "end": {**_text(), "format": "date-time"},
                                  "hours": _number(nullable=False, minimum=0.000001), "method": _text()}, nullable=True),
        "generated_at": stamp, "forecast_as_of": stamp, "heuristic": {"type": "boolean", "const": True},
        "environment": {"enum": ["test", "demo", "production"]},
        "issues": {"type": "array", "items": _object({"code": _text(), "detail": _text()})},
        "versions": _object({k: _text(True) for k in ("agent", "rules", "rules_hash", "weights", "weights_hash", "config", "config_hash")}),
    })
    schema.update({"$schema": "https://json-schema.org/draft/2020-12/schema", "title": CONTRACT,
                   "$comment": "Cross-field consistency, binding, freshness and live-use refusal are additionally enforced by validate_contract/assert_live_usable."})
    props = schema["properties"]
    forecast = {"forecast_id":_text(), "forecast_revision":_number(nullable=False,integer=True,minimum=1),
                "alert_id":_text(),"analyst_revision":_text(),"input_fingerprint":_text(pattern=r"^[a-f0-9]{64}$"),
                "status":{"enum":["complete","partial","abstained"]},
                "time_horizon":{**props["time_horizon"],"type":"object"},
                "generated_at":{**stamp,"type":"string"},"forecast_as_of":{**stamp,"type":"string"},
                "versions":_object({key:_text() for key in props["versions"]["properties"]}),
                "blast_radius":{"properties":{key:{**value,"type":next(t for t in value["type"] if t!="null")} for key,value in props["blast_radius"]["properties"].items() if "type" in value}}}
    null_fields = ("forecast_id","forecast_revision","status","risk_score","risk_score_basis","risk_score_may_include_asset_impact",
                   "selected_path","destination_technique","likelihood_index","time_horizon","generated_at","forecast_as_of")
    schema["allOf"] = [
        {"if":{"properties":{"response_type":{"const":"risk_forecast"}}}, "then":{"properties":forecast},
         "else":{"properties":{**{k:{"type":"null"} for k in null_fields},
             "numeric_assessment_status":{"const":"unavailable"},"explanation_status":{"const":"unavailable"},
             "behavioral_score_source":{"const":"unknown"},"blast_radius":{"properties":{
                 k:{"type":"null"} for k in ("observed_entities","potentially_reachable_entities","observed_count","potentially_reachable_count","inventory_coverage","truncated")}}}}},
        {"if":{"properties":{"status":{"const":"complete"}}},"then":{"properties":{
            "numeric_assessment_status":{"const":"complete"},"risk_score":_number(nullable=False,maximum=100)}}},
        {"if":{"properties":{"status":{"const":"abstained"}}},"then":{"properties":{
            "selected_path":{"type":"null"},"destination_technique":{"type":"null"},"likelihood_index":{"type":"null"},
            "risk_score_basis":{"const":"impact_assessment_only"}}}},
        {"if":{"properties":{"status":{"enum":["complete","partial"]}}},"then":{"properties":{
            "selected_path":{**props["selected_path"],"type":"object"},"destination_technique":_text(pattern=technique),
            "likelihood_index":_number(nullable=False,maximum=1),"risk_score_basis":{"const":"contextual_risk_assessment"}}}},
        {"if":{"properties":{"risk_score":{"type":"number"}}},"then":{"properties":{
            "risk_score_may_include_asset_impact":{"const":True},"behavioral_score_source":{"const":"supplied"}}}},
        {"if":{"properties":{"response_type":{"const":"skipped_benign"}}},"then":{"properties":{"reason":{"const":"skipped_benign"}}}},
    ]
    return schema


def _check(value, schema, path="$"):
    for clause in schema.get("allOf", []):
        _check(value, clause, path)
    if "if" in schema:
        try:
            _check(value, schema["if"], path)
            matched = True
        except ContractError:
            matched = False
        _check(value, schema.get("then" if matched else "else", {}), path)
    kinds = schema.get("type")
    kinds = [kinds] if isinstance(kinds, str) else kinds
    checks = {"null": lambda v: v is None, "string": lambda v: isinstance(v, str), "object": lambda v: isinstance(v, dict),
              "array": lambda v: isinstance(v, list), "boolean": lambda v: type(v) is bool,
              "integer": lambda v: type(v) is int,
              "number": _finite}
    if kinds and not any(checks[k](value) for k in kinds):
        raise ContractError("invalid_type", path)
    if "const" in schema and value != schema["const"] or "enum" in schema and value not in schema["enum"]:
        raise ContractError("invalid_value", path)
    if value is None:
        return
    if isinstance(value, dict):
        props = schema.get("properties", {})
        if not set(schema.get("required", [])) <= value.keys() or schema.get("additionalProperties") is False and set(value) - props.keys():
            raise ContractError("invalid_fields", path)
        for key in value:
            if key in props:
                _check(value[key], props[key], path + "." + key)
    elif isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise ContractError("empty_collection", path)
        if schema.get("uniqueItems") and len({canonical_json(v) for v in value}) != len(value):
            raise ContractError("duplicate_reference", path)
        if "items" in schema:
            for index, item in enumerate(value):
                _check(item, schema["items"], path + f"[{index}]")
    elif isinstance(value, str):
        if len(value.strip()) < schema.get("minLength", 0) or "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            raise ContractError("invalid_string", path)
        if schema.get("format") == "date-time":
            try:
                parse_time(value)
            except (ValueError, TypeError, AttributeError):
                raise ContractError("invalid_timestamp", path) from None
    elif type(value) in (int, float):
        if not _finite(value) or value < schema.get("minimum", -math.inf) or value > schema.get("maximum", math.inf):
            raise ContractError("out_of_range", path)


def empty_record(response_type, reason, *, environment="test", request_id=None, alert_id=None,
                 analyst_revision=None, input_fingerprint=None):
    result = {"contract": CONTRACT, "contract_version": 1, "execution_mode": "shadow_only",
        "request_id": request_id, "alert_id": alert_id, "analyst_revision": analyst_revision, "input_fingerprint": input_fingerprint,
        "forecast_id": None, "forecast_revision": None, "response_type": response_type, "status": None, "reason": reason,
        "numeric_assessment_status": "unavailable", "explanation_status": "unavailable", "risk_score": None,
        "risk_score_basis": None, "risk_score_may_include_asset_impact": None, "behavioral_score_source": "unknown",
        "selected_path": None, "destination_technique": None, "likelihood_index": None,
        "likelihood_index_meaning": RANKING_MEANING, "probability": None,
        "blast_radius": {"observed_entities": None, "potentially_reachable_entities": None,
            "observed_count": None, "potentially_reachable_count": None, "inventory_coverage": None, "truncated": None,
            "observed_meaning": OBSERVED_MEANING, "reachable_meaning": REACHABLE_MEANING},
        "time_horizon": None, "generated_at": None, "forecast_as_of": None, "heuristic": True,
        "environment": environment, "issues": [],
        "versions": {"agent": AGENT_VERSION, "config": CONFIG_VERSION, "rules": None, "rules_hash": None,
                     "weights": None, "weights_hash": None, "config_hash": None}}
    return result


def validate_contract(record, *, expected_alert_id=None, expected_revision=None, expected_fingerprint=None, expected_environment=None, now=None):
    try:
        canonical_json(record)
    except (TypeError, ValueError):
        raise ContractError("invalid_json") from None
    _check(record, contract_schema())
    for key, expected in (("alert_id", expected_alert_id), ("analyst_revision", expected_revision),
                          ("input_fingerprint", expected_fingerprint), ("environment", expected_environment)):
        if expected is not None and record[key] != expected:
            raise ContractError("binding_mismatch", key)
    if record["response_type"] != "risk_forecast":
        if (record["status"] is not None or record["numeric_assessment_status"] != "unavailable" or
            any(record[k] is not None for k in ("forecast_id", "forecast_revision", "risk_score", "risk_score_basis", "risk_score_may_include_asset_impact",
                                                "selected_path", "destination_technique", "likelihood_index", "time_horizon", "forecast_as_of", "generated_at")) or
            record["explanation_status"] != "unavailable" or record["behavioral_score_source"] != "unknown"):
            raise ContractError("non_forecast_has_assessment")
        if any(record["blast_radius"][k] is not None for k in ("observed_entities", "potentially_reachable_entities", "observed_count", "potentially_reachable_count", "inventory_coverage", "truncated")):
            raise ContractError("non_forecast_has_scope")
        if record["response_type"] == "skipped_benign" and record["reason"] != "skipped_benign":
            raise ContractError("invalid_skip_reason")
        return record
    if any(record[k] is None for k in ("forecast_id", "forecast_revision", "alert_id", "analyst_revision", "input_fingerprint", "time_horizon", "forecast_as_of", "generated_at")) or record["status"] is None:
        raise ContractError("forecast_identity_missing")
    if any(v is None for v in record["versions"].values()):
        raise ContractError("forecast_versions_missing")
    radius = record["blast_radius"]
    if any(radius[k] is None for k in ("observed_entities", "potentially_reachable_entities", "observed_count", "potentially_reachable_count", "inventory_coverage", "truncated")):
        raise ContractError("forecast_scope_missing")
    observed = [e["entity_id"] for e in radius["observed_entities"]]
    potential = [e["entity_id"] for e in radius["potentially_reachable_entities"]]
    if (len(observed) != radius["observed_count"] or len(potential) != radius["potentially_reachable_count"] or
        len(set(observed)) != len(observed) or len(set(potential)) != len(potential) or set(observed) & set(potential)):
        raise ContractError("invalid_blast_radius")
    if record["risk_score"] is not None and record["risk_score_may_include_asset_impact"] is not True:
        raise ContractError("asset_impact_flag_required")
    if record["risk_score"] is not None and record["behavioral_score_source"] != "supplied":
        raise ContractError("behavioral_source_inconsistent")
    if record["status"] == "abstained":
        if any(record[k] is not None for k in ("selected_path", "destination_technique", "likelihood_index")) or record["risk_score_basis"] != "impact_assessment_only":
            raise ContractError("invalid_abstention")
    else:
        path = record["selected_path"]
        if path is None or record["likelihood_index"] is None or record["destination_technique"] != path["steps"][-1]["technique_id"]:
            raise ContractError("invalid_selected_path")
        if not set(path["source_entity_ids"]) <= set(observed) or record["risk_score_basis"] != "contextual_risk_assessment":
            raise ContractError("path_scope_inconsistent")
    if record["status"] == "complete" and (record["numeric_assessment_status"] != "complete" or record["risk_score"] is None):
        raise ContractError("incomplete_numeric_assessment")
    horizon = record["time_horizon"]
    start, end = parse_time(horizon["start"]), parse_time(horizon["end"])
    if start != parse_time(record["forecast_as_of"]) or end <= start or abs((end-start).total_seconds() - horizon["hours"]*3600) > 1:
        raise ContractError("invalid_time_horizon")
    if now is not None:
        now = parse_time(now) if isinstance(now, str) else now
        if now.tzinfo is None or now.utcoffset() is None:
            raise ContractError("timezone_required")
        if end <= now:
            raise ContractError("forecast_expired")
        if start > now + timedelta(minutes=5):
            raise ContractError("future_forecast")
    return record


def _serialize_forecast(response, *, request_id=None):
    """Project only the handoff contract; no raw event messages/explanation prose."""
    kind = response.get("response_type")
    if kind not in {"risk_forecast", "validation_error", "operational_error"}:
        raise ContractError("invalid_response_type")
    record = empty_record(kind, response.get("reason", kind), environment=response.get("environment"),
                          request_id=request_id or response.get("request_id"), alert_id=response.get("alert_id"),
                          analyst_revision=response.get("analyst_revision"), input_fingerprint=response.get("input_fingerprint"))
    if kind != "risk_forecast":
        record["issues"] = [{"code": kind, "detail": "No usable forecast; no low-risk inference is permitted."}]
        return validate_contract(record)
    history = response.get("history") or {}
    if history.get("persisted") is not True:
        raise ContractError("forecast_history_required")
    record.update({k: deepcopy(response[k]) for k in ("status", "reason", "numeric_assessment_status", "explanation_status", "risk_score",
        "risk_score_basis", "risk_score_may_include_asset_impact", "behavioral_score_source", "time_horizon", "generated_at", "forecast_as_of", "versions")})
    record.update(forecast_id=history.get("forecast_id"), forecast_revision=history.get("revision"))
    record["issues"] = [{"code": i["code"], "detail": i.get("detail") or "Producer reported a limitation."} for i in response.get("issues", [])]
    canonical = {e["entity_id"]:e.get("canonical_id", e["entity_id"]) for e in response.get("asset_context", {}).get("entities", [])}
    def entity(e):
        return {"entity_id": e["entity_id"], "entity_type": e["entity_type"],
                "evidence_refs": e.get("evidence_refs", [e["evidence_ref"]] if e.get("evidence_ref") else []),
                "source_entity_id": canonical.get(e.get("source_entity_id"), e.get("source_entity_id"))}
    radius = response["blast_radius"]
    record["blast_radius"].update(observed_entities=[entity(e) for e in radius["observed_entities"]],
        potentially_reachable_entities=[entity(e) for e in radius["potential_entities"]],
        observed_count=radius["observed_count"], potentially_reachable_count=radius["potential_count"],
        inventory_coverage=radius["inventory_coverage"], truncated=radius["truncated"])
    path = response.get("predicted_path")
    if path:
        if path not in response.get("candidate_paths", []):
            raise ContractError("selected_path_not_a_candidate")
        likelihood = response.get("likelihood") or {}
        if likelihood.get("probability") is not None or likelihood.get("index") != path["likelihood_index"]:
            raise ContractError("invalid_likelihood")
        record["selected_path"] = {"candidate_id": path["candidate_id"], "starting_technique": path["starting_technique"],
            "steps": [{"technique_id": s["technique_id"], "rule_id": s["rule_id"]} for s in path["steps"]],
            "source_entity_ids": sorted({canonical.get(e, e) for e in path["source_entity_ids"]}), "evidence_refs": path["evidence_refs"]}
        record["destination_technique"] = path["steps"][-1]["technique_id"]
        record["likelihood_index"] = path["likelihood_index"]
    return validate_contract(record)


def serialize_forecast(response, *, request_id=None):
    try:
        return _serialize_forecast(response, request_id=request_id)
    except ContractError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        raise ContractError("malformed_producer_response") from None


def assert_live_usable(record):
    validate_contract(record)
    if record["environment"] != "production":
        raise ContractError("non_production_forecast")
    raise ContractError("shadow_only_contract")  # v1 can never authorize execution.

"""Optional, isolated explanation selection. No SDK import or I/O when disabled.

The model chooses from candidate-bound clauses, never writes free text. This
closed output language makes additions of scores, identities or techniques
rejectable by construction rather than relying on natural-language policing.
"""
from copy import deepcopy
from dataclasses import dataclass
import json
import logging
import math
import multiprocessing
import os
from pathlib import Path
import re
import sys
import time
import uuid

from .contracts import canonical_json, content_hash, TECHNIQUE
from .private_paths import PRIVATE_DIR, private_path, write_private

SYSTEM = ("Explain existing deterministic candidates only. Return JSON with exactly the key "
          "candidate_comments: one object per candidate, containing exactly candidate_id and "
          "comment_ids. Select and order only that candidate's offered comment IDs. Include "
          "scope and transition. Do not return prose, scores, numbers, techniques or any other fields.")


@dataclass(frozen=True)
class ExplanationConfig:
    enabled: bool = False
    model: str = "claude-haiku-5-5"  # Independent low-cost default; caller may override.
    timeout_seconds: float = 10.0
    max_attempts: int = 2
    audit_directory: Path = PRIVATE_DIR / "llm-payloads"

    def __post_init__(self):
        if type(self.enabled) is not bool:
            raise ValueError("enabled must be boolean")
        if not isinstance(self.model, str) or not re.fullmatch(r"claude-[a-z0-9-]{1,80}", self.model):
            raise ValueError("Use a Claude model identifier")
        if (isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, (int, float)) or
            not math.isfinite(self.timeout_seconds) or not 0 < self.timeout_seconds <= 10):
            raise ValueError("Explanation deadline must be positive and at most 10 seconds")
        if type(self.max_attempts) is not int or not 1 <= self.max_attempts <= 2:
            raise ValueError("At most two attempts inside the single deadline")


class PrivacyError(ValueError):
    pass


def _credential_values():
    # Called only inside an explicitly enabled explanation path. Never logged.
    return tuple(value for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")
                 if (value := os.environ.get(name)))


def _contains_credential(value):
    encoded = canonical_json(value)
    # Check JSON-escaped and literal forms without reporting a matched value.
    return any(secret in encoded or canonical_json(secret)[1:-1] in encoded
               for secret in _credential_values())


class Pseudonymizer:
    """Stable within a request, longest-first, case-insensitive substring replacement.

    Placeholders are substituted in one pass, so replacement never reprocesses
    an alias and names embedded in longer strings are covered. The mapping stays
    in the caller, never in the request, logs or provider child process.
    """
    def __init__(self, identities):
        self.forward, self.reverse = {}, {}
        counts = {}
        for kind, raw in sorted(set(identities), key=lambda v: (v[0], v[1].casefold(), v[1])):
            if kind not in {"user", "host", "service", "sid", "ip"} or not isinstance(raw, str) or not raw.strip():
                raise PrivacyError("unrepresentable_identity")
            if raw.casefold() in self.forward:
                continue
            counts[kind] = counts.get(kind, 0) + 1
            alias = f"{kind}_{counts[kind]}"
            self.forward[raw.casefold()] = alias
            self.reverse[alias] = raw
        # Refuse ambiguous source strings that already contain our alias tokens.
        if any(re.search(r"\b(?:user|host|service|sid|ip)_\d+\b", raw, re.I) for raw in self.forward):
            raise PrivacyError("alias_collision")

    def redact(self, text):
        if not isinstance(text, str):
            raise PrivacyError("nontext_field")
        if not self.forward:
            return text
        pattern = "|".join(re.escape(s) for s in sorted(self.forward, key=len, reverse=True))
        return re.sub(pattern, lambda m: self.forward[m.group().casefold()], text, flags=re.I)

    def restore(self, text):
        return re.sub(r"\b(?:user|host|service|sid|ip)_\d+\b", lambda m: self.reverse.get(m.group(), m.group()), text)

    def __getstate__(self):
        raise TypeError("Alias maps are memory-only and must not be serialized")

    def audit(self, body):
        text = canonical_json(body).casefold()
        return {"clean": not any(raw in text for raw in self.forward),
                "identity_count": len(self.forward),
                "raw_event_fields_present": any(key in text for key in ('"message":', '"command_line":', '"normalized_events":'))}


def prepare(response, alert):
    """Project allowlisted data only. Raw evidence and arbitrary metadata never enter."""
    identities = []
    entities = {}
    for item in alert.get("entities", []):
        raw, kind = item.get("entity_id"), item.get("entity_type")
        if not isinstance(raw, str) or kind not in {"user", "host", "service"}:
            raise PrivacyError("unrepresentable_entity")
        entities[raw] = kind
        identities.append((kind, raw))
        # Also guard against bare names appearing inside another string.
        if ":" in raw:
            identities.append((kind, raw.split(":", 1)[1]))
    for key, kind in (("user_id", "user"), ("host_id", "host"), ("source_ip", "ip")):
        if alert.get(key) is not None:
            if not isinstance(alert[key], str):
                raise PrivacyError("unrepresentable_identity")
            identities.append((kind, alert[key]))
    # SID/IP/name fields may exist in metadata, but metadata is never projected.
    # Gather them too for a final independent substring leak check.
    def collect(value):
        if isinstance(value, dict):
            for key, item in value.items():
                lower = key.lower()
                kind = ("sid" if "sid" in lower else ("ip" if lower.endswith(("_ip", "ipaddress")) else
                        ("host" if lower in {"hostname", "host_name", "computername"} else None)))
                if kind and item is not None:
                    if not isinstance(item, str):
                        raise PrivacyError("unrepresentable_identity")
                    if item:
                        identities.append((kind, item))
                elif isinstance(item, (dict, list)):
                    collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)
    collect(alert)
    aliases = Pseudonymizer(identities)
    candidates, render = [], {}
    for index, path in enumerate(response["candidate_paths"], 1):
        ref = f"candidate_{index}"
        techniques = [path["starting_technique"]] + [s["technique_id"] for s in path["steps"]]
        if not all(isinstance(t, str) and TECHNIQUE.fullmatch(t) for t in techniques):
            raise PrivacyError("unrepresentable_technique")
        bound = path["source_entity_ids"]
        if not bound or any(raw not in entities for raw in bound):
            raise PrivacyError("unresolved_entity")
        clauses = {
            "scope": "This is a conditional hypothesis, not observed compromise.",
            "transition": "Existing candidate sequence: " + " -> ".join(techniques) + ".",
            "entities": "Observed candidate context: " + ", ".join(aliases.redact(raw) for raw in bound) + ".",
            "uncertainty": "The candidate ranking is heuristic and is not a probability or severity measure.",
        }
        candidates.append({"candidate_id": ref, "techniques": techniques, "comments": clauses})
        render[ref] = {"path": path, "clauses": clauses}
    projection = {"candidates": candidates}
    audit = aliases.audit(projection)
    if not audit["clean"] or audit["raw_event_fields_present"]:
        raise PrivacyError("pseudonymization_incomplete")
    return projection, render, aliases


def validate_selection(value, render):
    if not isinstance(value, dict) or set(value) != {"candidate_comments"} or not isinstance(value["candidate_comments"], list):
        raise ValueError("invalid_output_shape")
    seen = set()
    for row in value["candidate_comments"]:
        if not isinstance(row, dict) or set(row) != {"candidate_id", "comment_ids"}:
            raise ValueError("extra_or_missing_fields")
        ref, selected = row["candidate_id"], row["comment_ids"]
        if not isinstance(ref, str) or ref not in render or ref in seen:
            raise ValueError("unknown_or_duplicate_candidate")
        seen.add(ref)
        if (not isinstance(selected, list) or not all(isinstance(s, str) for s in selected) or
            len(set(selected)) != len(selected) or not {"scope", "transition"} <= set(selected) or
            not set(selected) <= render[ref]["clauses"].keys()):
            raise ValueError("unknown_or_missing_comment")
    if seen != render.keys():
        raise ValueError("candidate_set_mismatch")
    return value


class AnthropicExplanationProvider:
    """Same SDK/provider/auth as the backend; no triage tools or backend imports."""
    def complete(self, request, *, deadline, attempt):
        import anthropic  # Optional; only imported in an explicitly enabled child.
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        # Same SDK credential resolution as llm_analyst.py, normally
        # ANTHROPIC_API_KEY. No credentials are copied into payloads or logs.
        with anthropic.Anthropic(timeout=remaining, max_retries=0) as client:
            reply = client.messages.create(**request)
            text = "".join(block.text for block in reply.content if block.type == "text")
        if len(text) > 65536:
            raise ValueError("output_too_large")
        return json.loads(text)


def _worker(provider, request, deadline, attempt, sender):
    # Silence native stdout/stderr as well as Python logging before SDK imports.
    # Raw SDK diagnostics are not a supported output channel; parent receives
    # only validated JSON or a fixed error marker. No redirected file is kept.
    try:
        with open(os.devnull, "w") as sink:
            for stream in (sys.stdout, sys.stderr):
                os.dup2(sink.fileno(), stream.fileno())
            sys.stdout.flush()
            sys.stderr.flush()
            logging.disable(sys.maxsize)
        result = provider.complete(request, deadline=deadline, attempt=attempt)
        encoded = canonical_json(result)
        if len(encoded) > 65536 or _contains_credential(result):
            raise ValueError("output_too_large")
        sender.send(("ok", encoded))
    except Exception:
        # Provider error text can contain credentials/response bodies: never log it.
        sender.send(("error", None))
    finally:
        sender.close()


def _invoke(provider, request, deadline, attempt):
    ctx = multiprocessing.get_context("spawn")
    receiver, sender = ctx.Pipe(duplex=False)
    process = ctx.Process(target=_worker, args=(provider, request, deadline, attempt, sender), daemon=True)
    try:
        process.start()
        sender.close()
        # Reserve time for termination/reaping inside the total deadline.
        if not receiver.poll(max(0, deadline - time.monotonic() - 0.15)):
            return "timeout", None
        try:
            kind, encoded = receiver.recv()
        except EOFError:
            return "error", None
        return kind, json.loads(encoded) if kind == "ok" else None
    finally:
        receiver.close()
        sender.close()
        if process.pid is not None:
            if process.is_alive():
                process.terminate()
            process.join(timeout=max(0, min(0.1, deadline - time.monotonic())))
            if process.is_alive():
                process.kill()
                process.join(timeout=max(0, min(0.05, deadline - time.monotonic())))
            if not process.is_alive():
                process.close()


def explain_forecast(response, alert, *, config=None, provider=None):
    """Only explanation/explanation_status may change, plus issues on fallback."""
    if config is None or not config.enabled:
        return response
    if response.get("response_type") != "risk_forecast" or not response.get("candidate_paths"):
        return response
    started = time.monotonic()
    deadline = started + config.timeout_seconds
    result = deepcopy(response)
    audit_refs = []

    def fallback(code):
        result["explanation_status"] = "deterministic"
        result["issues"].append({"code": code, "detail": "Deterministic explanation retained; numeric assessment unchanged."})
        return result

    try:
        projection, render, aliases = prepare(response, alert)
        request = {"model": config.model, "max_tokens": 1024, "system": SYSTEM,
                   "messages": [{"role": "user", "content": canonical_json(projection)}]}
        if _contains_credential(request):
            return fallback("llm_credential_skipped")
        audit = aliases.audit(request)
        if not audit["clean"] or audit["raw_event_fields_present"]:
            return fallback("llm_privacy_skipped")
    except (PrivacyError, ValueError, KeyError, TypeError, AttributeError):
        return fallback("llm_privacy_skipped")
    for attempt in range(1, config.max_attempts + 1):
        if time.monotonic() >= deadline - 0.2:
            return fallback("llm_timeout")
        try:
            directory = private_path(config.audit_directory)
            if _contains_credential(str(directory)):
                return fallback("llm_credential_skipped")
            path = directory / (uuid.uuid4().hex + ".json")
            # Fail closed: journal the exact application request before starting
            # any provider. This is an attempted-send journal, not proof of delivery.
            write_private(path, {"schema_version": 1, "attempt": attempt,
                                "transport": "injected" if provider is not None else "anthropic",
                                "request": request, "request_sha256": content_hash(request), "privacy_audit": audit})
            audit_refs.append(path.relative_to(PRIVATE_DIR).as_posix())
        except (OSError, ValueError, TypeError):
            return fallback("llm_audit_unavailable")
        if time.monotonic() >= deadline - 0.2:
            return fallback("llm_timeout")
        try:
            kind, value = _invoke(provider or AnthropicExplanationProvider(), request, deadline, attempt)
        except Exception:
            kind, value = "error", None
        if kind == "timeout":
            return fallback("llm_timeout")
        if kind != "ok":
            if attempt < config.max_attempts:
                continue
            return fallback("llm_provider_error")
        try:
            selection = validate_selection(value, render)
        except (ValueError, TypeError, KeyError):
            return fallback("llm_output_rejected")
        if time.monotonic() >= deadline:
            return fallback("llm_timeout")
        comments = []
        for row in selection["candidate_comments"]:
            info = render[row["candidate_id"]]
            comments.append({"candidate_id": info["path"]["candidate_id"],
                             "evidence_refs": info["path"]["evidence_refs"],
                             "text": aliases.restore(" ".join(info["clauses"][key] for key in row["comment_ids"])),
                             "assumptions": sorted({a for s in info["path"]["steps"] for a in s["assumptions"]})})
        result["explanation"] = {"summary": "LLM-selected explanations of existing deterministic candidates; no assessment fields were changed.",
                                 "candidate_explanations": comments,
                                 "llm": {"provider": "anthropic" if provider is None else "injected", "model": config.model,
                                         "mode": "validated_clause_selection", "attempts": attempt, "payload_audit_refs": audit_refs}}
        if _contains_credential(result["explanation"]):
            # Do not return a newly rendered explanation containing a credential.
            result["explanation"] = deepcopy(response["explanation"])
            return fallback("llm_credential_skipped")
        result["explanation_status"] = "llm_selected"
        return result
    return fallback("llm_provider_error")


def audit_logged_payloads(directory, *, forbidden_strings=()):
    """Audit exact journal bodies, including the entire SDK application payload.

    No identities or offending content are returned. This is a structural audit
    plus an optional caller-owned identity/content denylist, not a general PII
    classifier. It never modifies journals.
    """
    checked, failures = 0, []
    for path in sorted(private_path(directory).glob("*.json")):
        if not re.fullmatch(r"[a-f0-9]{32}\.json", path.name):
            continue
        checked += 1
        try:
            journal = json.loads(path.read_text(encoding="utf-8"))
            if set(journal) != {"schema_version", "attempt", "transport", "request", "request_sha256", "privacy_audit"}:
                raise ValueError()
            if set(journal["privacy_audit"]) != {"clean", "identity_count", "raw_event_fields_present"}:
                raise ValueError()
            if _contains_credential(journal):
                raise ValueError()
            body = journal["request"]
            if set(body) != {"model", "max_tokens", "system", "messages"} or body["system"] != SYSTEM or body["max_tokens"] != 1024:
                raise ValueError()
            if not re.fullmatch(r"claude-[a-z0-9-]{1,80}", body["model"]):
                raise ValueError()
            if len(body["messages"]) != 1 or set(body["messages"][0]) != {"role", "content"} or body["messages"][0]["role"] != "user":
                raise ValueError()
            projection = json.loads(body["messages"][0]["content"])
            if set(projection) != {"candidates"}:
                raise ValueError()
            for row in projection["candidates"]:
                if set(row) != {"candidate_id", "techniques", "comments"} or not re.fullmatch(r"candidate_\d+", row["candidate_id"]):
                    raise ValueError()
                if not row["techniques"] or not all(TECHNIQUE.fullmatch(t) for t in row["techniques"]):
                    raise ValueError()
                comments = row["comments"]
                if set(comments) != {"scope", "transition", "entities", "uncertainty"}:
                    raise ValueError()
                if (comments["scope"] != "This is a conditional hypothesis, not observed compromise." or
                    comments["uncertainty"] != "The candidate ranking is heuristic and is not a probability or severity measure." or
                    comments["transition"] != "Existing candidate sequence: " + " -> ".join(row["techniques"]) + "." or
                    not re.fullmatch(r"Observed candidate context: (?:user|host|service)_\d+(?:, (?:user|host|service)_\d+)*\.", comments["entities"])):
                    raise ValueError()
            if journal["request_sha256"] != content_hash(body):
                raise ValueError()
            text = canonical_json(journal).casefold()
            if any(secret.casefold() in text for secret in forbidden_strings if secret):
                raise ValueError()
        except (ValueError, KeyError, TypeError, OSError):
            failures.append(path.name)
    return {"clean": not failures, "payloads_checked": checked, "failed_files": failures,
            "scope": "Exact application request bodies; closed projection structure, journal hashes, and caller-supplied forbidden strings. No authorization headers or credentials logged."}

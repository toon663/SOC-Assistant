"""Version metadata for every response, including failures before inference."""

import json

SCHEMA_VERSION = 1
AGENT_VERSION = "0.4.0a1"
CONFIG_VERSION = "3"


def provenance(config=None, *, rules_path=None, weights_path=None):
    # Imports are lazy to avoid a contracts/config dependency cycle.
    from dataclasses import asdict
    from .config import ForecastConfig
    from .contracts import content_hash
    config = config or ForecastConfig()
    values = {key: str(value) if key.endswith("_path") else value for key, value in asdict(config).items()}
    versions = {"agent": AGENT_VERSION, "config": config.config_version, "config_hash": content_hash(values),
                "rules": None, "rules_hash": None, "weights": None, "weights_hash": None}
    issues = []
    for name, path in (("rules", rules_path or config.rules_path), ("weights", weights_path or config.weights_path)):
        try:
            with open(path, encoding="utf-8") as stream:
                document = json.load(stream)
            versions[name] = document.get("version")
            versions[name + "_hash"] = content_hash(document)
            if not isinstance(versions[name], str) or not versions[name]:
                raise ValueError("version missing")
        except (OSError, ValueError, TypeError, AttributeError):
            versions[name] = None
            issues.append({"code": "version_unavailable", "artifact": name})
    return {"schema_version": SCHEMA_VERSION, "agent_version": AGENT_VERSION, "environment": config.environment,
            "behavioral_score_source": "unknown", "risk_score_may_include_asset_impact": None,
            "config_version": config.config_version, "versions": versions, "provenance_issues": issues}


def operational_error(reason, detail, *, config=None, metadata=None):
    return {**(metadata or provenance(config)), "response_type": "operational_error",
            "reason": reason, "reason_detail": detail}

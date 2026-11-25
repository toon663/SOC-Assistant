"""Environment-backed configuration for the cybersecurity agent service."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_name: str = "SOC Multi-Agent Platform"
    environment: str = "development"
    database_path: str = "soc_agents.db"
    require_human_approval: bool = True
    api_key: str = ""
    log_level: str = "INFO"
    memory_limit: int = 1000
    retrieval_top_k: int = 5
    # Enables /dev endpoints (synthetic scenarios, malware demo, resets). Never enable in production.
    dev_mode: bool = False
    # Claude review of incidents the triage rules leave unresolved: off, auto, or all.
    # Sends incident evidence (log messages, usernames, hosts, IPs) to the Claude API.
    llm_triage: str = "off"
    llm_model: str = "claude-opus-5-5"
    llm_effort: str = "medium"
    llm_max_reviews_per_hour: int = 30

    # Parse optional observer bounds only inside the guarded API initializer.
    # Bad observer settings must not prevent legacy ingestion from starting.
    prognostic_mode: str = "off"
    prognostic_environment: str = "test"
    prognostic_inventory_path: str = ""
    prognostic_timeout_seconds: float | str = 3.0
    prognostic_queue_size: int | str = 64

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            app_name=os.getenv("SOC_APP_NAME", cls.app_name),
            environment=os.getenv("SOC_ENVIRONMENT", cls.environment),
            database_path=os.getenv("SOC_DATABASE_PATH", cls.database_path),
            require_human_approval=_bool("SOC_REQUIRE_HUMAN_APPROVAL", True),
            api_key=os.getenv("SOC_API_KEY", ""),
            log_level=os.getenv("SOC_LOG_LEVEL", "INFO"),
            memory_limit=int(os.getenv("SOC_MEMORY_LIMIT", "1000")),
            retrieval_top_k=int(os.getenv("SOC_RETRIEVAL_TOP_K", "5")),
            dev_mode=_bool("SOC_DEV_MODE", False),
            llm_triage=os.getenv("SOC_LLM_TRIAGE", cls.llm_triage).strip().lower(),
            llm_model=os.getenv("SOC_LLM_MODEL", cls.llm_model),
            llm_effort=os.getenv("SOC_LLM_EFFORT", cls.llm_effort),
            llm_max_reviews_per_hour=int(os.getenv("SOC_LLM_MAX_REVIEWS_PER_HOUR", "30")),
            prognostic_mode=os.getenv("SOC_PROGNOSTIC_MODE", "off").strip().lower(),
            prognostic_environment=os.getenv("SOC_PROGNOSTIC_ENVIRONMENT", "test").strip().lower(),
            prognostic_inventory_path=os.getenv("SOC_PROGNOSTIC_INVENTORY_PATH", ""),
            prognostic_timeout_seconds=os.getenv("SOC_PROGNOSTIC_TIMEOUT_SECONDS", "3"),
            prognostic_queue_size=os.getenv("SOC_PROGNOSTIC_QUEUE_SIZE", "64"),
        )


settings = Settings.from_env()

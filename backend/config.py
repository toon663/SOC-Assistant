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
        )


settings = Settings.from_env()

"""Explicit, independent forecast settings; no environment or network side effects."""

from dataclasses import dataclass, field
import math
from pathlib import Path
from .provenance import CONFIG_VERSION
from .migrations import validate_environment

AGENT_DIR = Path(__file__).resolve().parent


@dataclass(frozen=True)
class ForecastConfig:
    config_version: str = CONFIG_VERSION
    environment: str = "demo"
    evidence_freshness_limit_hours: float = 24.0
    forecast_horizon_hours: float = 24.0
    asset_context_freshness_hours: float = 24.0
    asset_provider_timeout_seconds: float = 2.0
    asset_provider_deadlines: dict[str, float] = field(default_factory=dict)
    enrichment_timeout_seconds: float = 5.0
    min_candidate_score: float = 0.50
    max_path_steps: int = 3
    max_candidates: int = 3
    max_related_assets: int = 100
    history_retention_days: int = 90
    sqlite_busy_timeout_ms: int = 5000
    store_full_evidence: bool = False
    rules_path: Path = AGENT_DIR / "rules" / "attack_transitions.json"
    weights_path: Path = AGENT_DIR / "rules" / "scoring_weights.json"

    def __post_init__(self):
        validate_environment(self.environment)
        if not isinstance(self.config_version, str) or not self.config_version.strip():
            raise ValueError("config_version must be a nonempty string")
        for name in (
            "evidence_freshness_limit_hours", "forecast_horizon_hours",
            "asset_context_freshness_hours", "asset_provider_timeout_seconds",
            "enrichment_timeout_seconds",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be finite and positive")
            object.__setattr__(self, name, float(value))
        if isinstance(self.min_candidate_score, bool) or not isinstance(self.min_candidate_score, (int, float)) or not 0 <= self.min_candidate_score <= 1 or not math.isfinite(self.min_candidate_score):
            raise ValueError("min_candidate_score must be in [0, 1]")
        object.__setattr__(self, "min_candidate_score", float(self.min_candidate_score))
        for name in ("max_path_steps", "max_candidates", "max_related_assets", "history_retention_days"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError(f"{name} must be a positive integer")
        if type(self.sqlite_busy_timeout_ms) is not int or self.sqlite_busy_timeout_ms < 0 or type(self.store_full_evidence) is not bool:
            raise ValueError("Invalid history settings")
        for name, seconds in self.asset_provider_deadlines.items():
            if not isinstance(name, str) or not name or isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or seconds <= 0 or not math.isfinite(seconds):
                raise ValueError("provider deadlines must be finite positive seconds")
        object.__setattr__(self, "asset_provider_deadlines", {name: float(value) for name, value in self.asset_provider_deadlines.items()})

    def provider_timeout(self, name: str) -> float:
        return self.asset_provider_deadlines.get(name, self.asset_provider_timeout_seconds)

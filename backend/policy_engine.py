"""Deterministic safety and approval policies for agent actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Set

from models import ActionRequest, ActionType, PolicyDecision


@dataclass(frozen=True)
class PolicyConfig:
    """Thresholds controlling when an action may be executed."""

    approval_required_actions: Set[ActionType] = frozenset(
        {
            ActionType.ISOLATE_ENDPOINT,
            ActionType.DISABLE_USER,
            ActionType.BLOCK_IP,
        }
    )
    minimum_confidence_for_approval: float = 60.0
    minimum_risk_for_approval: float = 50.0
    prohibited_actions: Set[ActionType] = frozenset({ActionType.DELETE_DATA})

    def __post_init__(self) -> None:
        if not 0 <= self.minimum_confidence_for_approval <= 100:
            raise ValueError("minimum_confidence_for_approval must be 0..100")
        if not 0 <= self.minimum_risk_for_approval <= 100:
            raise ValueError("minimum_risk_for_approval must be 0..100")


class PolicyEngine:
    """Evaluate proposed actions before any external side effect occurs.

    The engine is intentionally deterministic. Model output can recommend an
    action, but it cannot override these rules.
    """

    POLICY_ID = "soc-safety-v1"

    def __init__(self, config: PolicyConfig | None = None):
        self.config = config or PolicyConfig()

    def evaluate(self, request: ActionRequest) -> PolicyDecision:
        action = request.action
        if action in self.config.prohibited_actions:
            return self._deny(request, "action is prohibited by policy")

        if action in {ActionType.ISOLATE_ENDPOINT, ActionType.DISABLE_USER, ActionType.BLOCK_IP}:
            if request.target.strip().lower() in {"unknown", "none", "null", "*"}:
                return self._deny(request, "dangerous action requires a specific target")
            if request.risk_score < self.config.minimum_risk_for_approval:
                return self._deny(request, "risk score is below the action threshold")
            if request.confidence < self.config.minimum_confidence_for_approval:
                return self._deny(request, "confidence is below the action threshold")
            return self._decision(
                request,
                allowed=True,
                requires_approval=action in self.config.approval_required_actions,
                reason="action is eligible but requires human approval",
            )

        return self._decision(
            request,
            allowed=True,
            requires_approval=False,
            reason="low-risk action permitted",
        )

    def evaluate_many(self, requests: Iterable[ActionRequest]) -> list[PolicyDecision]:
        return [self.evaluate(request) for request in requests]

    def approve(self, request: ActionRequest, approver: str) -> PolicyDecision:
        """Re-evaluate a request after recording a human approver."""
        if not approver or not approver.strip():
            raise ValueError("approver is required")
        if request.approved_by != approver:
            return self._deny(request, "request does not contain the approving identity")
        decision = self.evaluate(request)
        if decision.allowed and decision.requires_approval:
            return self._decision(
                request,
                allowed=True,
                requires_approval=False,
                reason=f"approved by {approver}",
            )
        return decision

    def _decision(
        self,
        request: ActionRequest,
        *,
        allowed: bool,
        requires_approval: bool,
        reason: str,
    ) -> PolicyDecision:
        return PolicyDecision(
            allowed=allowed,
            requires_approval=requires_approval,
            reason=reason,
            policy_id=self.POLICY_ID,
            action=request.action.value,
            incident_id=request.incident_id,
        )

    def _deny(self, request: ActionRequest, reason: str) -> PolicyDecision:
        return self._decision(request, allowed=False, requires_approval=False, reason=reason)
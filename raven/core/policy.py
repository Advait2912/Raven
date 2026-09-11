# Deterministic policy gate.
# Design choice: hard code-level enforcement. A prompt is not a firewall.
# All proposed attack executions must pass this gate before touching the target.

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Scope:
    """Explicit boundaries for authorized testing."""
    allowed_domains: list[str] = field(default_factory=lambda: ["localhost", "127.0.0.1", "lab.local"])
    allowed_paths: list[str] = field(default_factory=lambda: ["/api/auth/login", "/api/orders/"])
    max_requests: int = 50
    current_requests: int = 0


@dataclass
class PolicyDecision:
    """Outcome of evaluating an action against security policy."""
    allowed: bool
    reason: str
    action_id: str


class PolicyGate:
    """Deterministic evaluator for actions and attack module runs."""

    def __init__(self, scope: Optional[Scope] = None) -> None:
        self.scope = scope or Scope()

    def evaluate(
        self,
        action_id: str,
        target_path: str,
        target_domain: str,
        prerequisites: list[str],
        satisfied_prerequisites: list[str],
    ) -> PolicyDecision:
        # Check domain scope
        if target_domain not in self.scope.allowed_domains:
            return PolicyDecision(
                allowed=False,
                reason=f"Domain '{target_domain}' is out of authorized scope.",
                action_id=action_id,
            )

        # Check path scope
        if not any(target_path.startswith(p) for p in self.scope.allowed_paths):
            return PolicyDecision(
                allowed=False,
                reason=f"Path '{target_path}' is outside declared permitted paths.",
                action_id=action_id,
            )

        # Check request budget
        if self.scope.current_requests >= self.scope.max_requests:
            return PolicyDecision(
                allowed=False,
                reason=f"Request budget exceeded ({self.scope.max_requests} requests max).",
                action_id=action_id,
            )

        # Check prerequisites
        missing = [p for p in prerequisites if p not in satisfied_prerequisites]
        if missing:
            return PolicyDecision(
                allowed=False,
                reason=f"Unsatisfied prerequisites: {', '.join(missing)}",
                action_id=action_id,
            )

        self.scope.current_requests += 1
        return PolicyDecision(
            allowed=True,
            reason="Policy check passed. Target in scope and prerequisites met.",
            action_id=action_id,
        )

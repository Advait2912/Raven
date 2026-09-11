# Base target abstraction.
# Design choice: uniform interface for targets, whether simulated in-process
# or running as external HTTP services.

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class TargetRequest:
    """Incoming request to a target application."""
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[Any] = None


@dataclass
class TargetResponse:
    """Outgoing response from a target application."""
    status_code: int
    headers: dict[str, str]
    body: Any

    def get_json(self) -> Optional[dict[str, Any]]:
        if isinstance(self.body, dict):
            return self.body
        return None


class BaseTarget(ABC):
    """Abstract interface for all security targets."""
    id: str
    name: str
    base_url: str

    @abstractmethod
    def handle_request(self, request: TargetRequest) -> TargetResponse:
        """Process an HTTP request and return a structured response."""
        pass

    @abstractmethod
    def reset_state(self) -> None:
        """Reset the target state back to pristine baseline."""
        pass

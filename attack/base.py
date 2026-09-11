# Define the base class for attack modules.
# Design choice: keep the abstraction relatively simple
# so attacks are easy to execute while hiding their internal complexity.

from abc import ABC, abstractmethod
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from raven.core.models import AttackResult
    from raven.core.store import EvidenceStore
    from raven.target.base import BaseTarget


class AttackModule(ABC):
    id: str
    name: str
    category: str
    description: str
    prerequisite: list[str]
    capabilities: list[str]

    @abstractmethod
    def execute(
        self,
        target: "BaseTarget",
        store: Optional["EvidenceStore"] = None,
    ) -> "AttackResult":
        """Execute attack logic against the specified target and record evidence."""
        pass

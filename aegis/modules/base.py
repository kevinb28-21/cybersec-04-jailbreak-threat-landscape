"""Security module plugin interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator

from aegis.core.schema import Alert, HealthStatus, NormalizedEvent, RemediationResult


class SecurityModule(ABC):
    """Contract every detection module must implement."""

    name: str
    version: str = "1.0.0"

    @abstractmethod
    def collect(self) -> Iterator[NormalizedEvent]:
        """Yield telemetry events from sensors."""

    @abstractmethod
    def detect(self, events: list[NormalizedEvent]) -> list[Alert]:
        """Run module-specific detection on a batch of events."""

    @abstractmethod
    def remediate(self, alert: Alert, playbook_id: str) -> RemediationResult:
        """Execute a response playbook for an alert."""

    @abstractmethod
    def health(self) -> HealthStatus:
        """Return module health for watchdog."""

    def process_event(self, event: NormalizedEvent) -> list[Alert]:
        """Default: detect on single event."""
        return self.detect([event])

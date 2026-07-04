"""Platform orchestrator — wires modules, detection, correlation, SOAR."""

from __future__ import annotations

import logging
from typing import Any

from aegis.core.audit import AuditLedger
from aegis.core.correlation import CorrelationEngine
from aegis.core.event_bus import get_event_bus
from aegis.core.schema import Alert, Incident, NormalizedEvent, RemediationResult
from aegis.engine.detectors.tiered import TieredDetector
from aegis.engine.soar.playbook import PlaybookEngine
from aegis.modules.aisec_guard.module import AISecGuardModule
from aegis.modules.base import SecurityModule
from aegis.modules.host_shield.module import HostShieldModule
from aegis.modules.net_sentinel.module import NetSentinelModule

logger = logging.getLogger(__name__)


class AegisPlatform:
    """Central security operations engine."""

    def __init__(self) -> None:
        self.bus = get_event_bus()
        self.detector = TieredDetector()
        self.correlator = CorrelationEngine()
        self.soar = PlaybookEngine()
        self.audit = AuditLedger()
        self.modules: dict[str, SecurityModule] = {
            "aisec-guard": AISecGuardModule(),
            "net-sentinel": NetSentinelModule(),
            "host-shield": HostShieldModule(),
        }
        self._remediations: list[RemediationResult] = []

    def get_module(self, name: str) -> SecurityModule:
        if name not in self.modules:
            raise KeyError(f"Unknown module: {name}")
        return self.modules[name]

    async def ingest(self, event: NormalizedEvent) -> dict[str, Any]:
        """Full pipeline: detect → correlate → respond → audit."""
        enriched = self.detector.analyze(event)
        await self.bus.publish_event(enriched)

        module = self.modules.get(enriched.source_module)
        module_alerts = module.detect([enriched]) if module else []

        if enriched.confidence >= 0.5 and not module_alerts:
            module_alerts = [
                self.correlator.event_to_alert(
                    enriched,
                    title=f"Threat detected by tiered engine: {enriched.source_module}",
                )
            ]

        incidents: list[Incident] = []
        remediations: list[RemediationResult] = []

        for alert in module_alerts:
            await self.bus.publish_alert(alert)
            incident = self.correlator.correlate(alert)
            incidents.append(incident)

            self.audit.append(
                actor="platform",
                action="alert_created",
                resource_type="alert",
                resource_id=alert.alert_id,
                payload={"title": alert.title, "severity": alert.severity.value},
            )

            for pb_id in alert.recommended_playbooks:
                result = self.soar.execute(pb_id, alert)
                remediations.append(result)
                self._remediations.append(result)
                if result.status.value in ("success", "rolled_back"):
                    self.audit.append(
                        actor="soar-engine",
                        action=f"remediation_{result.status.value}",
                        resource_type="alert",
                        resource_id=alert.alert_id,
                        payload={"playbook": pb_id, "actions": result.actions_taken},
                    )

        return {
            "event_id": enriched.event_id,
            "confidence": enriched.confidence,
            "severity": enriched.severity.value,
            "alerts": [a.alert_id for a in module_alerts],
            "incidents": [i.incident_id for i in incidents],
            "remediations": [r.status.value for r in remediations],
        }

    def health_all(self) -> dict[str, Any]:
        return {name: mod.health().model_dump() for name, mod in self.modules.items()}

    def status(self) -> dict[str, Any]:
        from aegis.core.knowledge import get_knowledge_base
        kb = get_knowledge_base()
        chain_ok, chain_msg = self.audit.verify_chain()
        return {
            "modules": self.health_all(),
            "knowledge_base": kb.statistics(),
            "playbooks": self.soar.list_playbooks(),
            "audit_chain": {"valid": chain_ok, "message": chain_msg},
            "recent_alerts": len(self.correlator.list_alerts(10)),
            "recent_incidents": len(self.correlator.list_incidents(10)),
            "remediations_executed": len(self._remediations),
        }

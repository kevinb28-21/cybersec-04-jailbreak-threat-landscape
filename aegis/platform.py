"""Platform orchestrator — wires all cyber project modules."""

from __future__ import annotations

import logging
import time
from typing import Any

from aegis.config import settings
from aegis.core.audit import AuditLedger
from aegis.core.correlation import CorrelationEngine
from aegis.core.event_bus import get_event_bus
from aegis.core.schema import Alert, Incident, NormalizedEvent, RemediationResult
from aegis.engine.detectors.tiered import TieredDetector
from aegis.engine.soar.playbook import PlaybookEngine
from aegis.modules.adversarial_ml.module import AdversarialMLModule
from aegis.modules.agent_guard.module import AgentGuardModule
from aegis.modules.aisec_guard.module import AISecGuardModule
from aegis.modules.base import SecurityModule
from aegis.modules.host_shield.module import HostShieldModule
from aegis.modules.net_sentinel.module import NetSentinelModule
from aegis.modules.rag_guard.module import RAGGuardModule
from aegis.modules.red_team_engine.module import RedTeamEngineModule
from aegis.modules.runtime_guard.module import RuntimeGuardModule
from aegis.modules.vlm_guard.module import VLMGuardModule

logger = logging.getLogger(__name__)


class AegisPlatform:
    """Central security operations engine — integrates projects 04-10."""

    def __init__(self) -> None:
        self.bus = get_event_bus()
        self.detector = TieredDetector(
            max_tier=settings.detection_tier_max,
            ml_enabled=settings.ml_enabled,
        )
        self.correlator = CorrelationEngine()
        self.soar = PlaybookEngine()
        self.audit = AuditLedger()
        self._soar_last_run: dict[str, float] = {}
        self._alert_dedup: dict[str, float] = {}

        self.modules: dict[str, SecurityModule] = {
            "aisec-guard": AISecGuardModule(self.soar),       # Project 04
            "agent-guard": AgentGuardModule(self.soar),       # Project 05
            "rag-guard": RAGGuardModule(self.soar),           # Project 06
            "vlm-guard": VLMGuardModule(self.soar),           # Project 07
            "runtime-guard": RuntimeGuardModule(self.soar),   # Project 08
            "adversarial-ml": AdversarialMLModule(self.soar), # Project 09
            "red-team-engine": RedTeamEngineModule(self.soar),# Project 10
            "net-sentinel": NetSentinelModule(self.soar),
            "host-shield": HostShieldModule(self.soar),
        }

        red_team = self.modules["red-team-engine"]
        if isinstance(red_team, RedTeamEngineModule):
            red_team.import_atlas_mapping()

    def get_module(self, name: str) -> SecurityModule:
        if name not in self.modules:
            raise KeyError(f"Unknown module: {name}")
        return self.modules[name]

    def _should_dedup_alert(self, alert: Alert) -> bool:
        key = f"{alert.source_module}:{alert.entity.id}:{alert.title}"
        now = time.monotonic()
        last = self._alert_dedup.get(key, 0)
        if now - last < settings.alert_dedup_window_seconds:
            return True
        self._alert_dedup[key] = now
        return False

    def _should_run_playbook(self, entity_id: str, playbook_id: str) -> bool:
        key = f"{entity_id}:{playbook_id}"
        now = time.monotonic()
        last = self._soar_last_run.get(key, 0)
        if now - last < settings.soar_cooldown_seconds:
            return False
        self._soar_last_run[key] = now
        return True

    async def ingest(self, event: NormalizedEvent, auto_respond: bool = False) -> dict[str, Any]:
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
        alert_ids: list[str] = []

        for alert in module_alerts:
            if self._should_dedup_alert(alert):
                continue
            await self.bus.publish_alert(alert)
            alert_ids.append(alert.alert_id)
            incident = self.correlator.correlate(alert)
            incidents.append(incident)
            self.audit.append(
                actor="platform", action="alert_created",
                resource_type="alert", resource_id=alert.alert_id,
                payload={"title": alert.title, "severity": alert.severity.value},
            )
            if auto_respond or settings.auto_response_enabled:
                for pb_id in alert.recommended_playbooks[:1]:
                    if not self._should_run_playbook(alert.entity.id, pb_id):
                        continue
                    result = self.soar.execute(pb_id, alert)
                    remediations.append(result)
                    self.audit.append(
                        actor="soar-engine", action=f"remediation_{result.status.value}",
                        resource_type="alert", resource_id=alert.alert_id,
                        payload={"playbook": pb_id, "actions": result.actions_taken},
                    )

        return {
            "event_id": enriched.event_id,
            "confidence": enriched.confidence,
            "severity": enriched.severity.value,
            "alerts": alert_ids,
            "incidents": [i.incident_id for i in incidents],
            "remediations": [r.status.value for r in remediations],
            "auto_respond": auto_respond or settings.auto_response_enabled,
        }

    async def ingest_log_line(self, host_id: str, log_line: str, auto_respond: bool = False) -> dict[str, Any]:
        mod = self.get_module("host-shield")
        assert isinstance(mod, HostShieldModule)
        return await self.ingest(mod.ingest_log_line(host_id, log_line), auto_respond)

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
            "auto_response_enabled": settings.auto_response_enabled,
            "soar_simulation_mode": settings.soar_simulation_mode,
            "cyber_projects_integrated": ["04", "05", "06", "07", "08", "09", "10"],
        }

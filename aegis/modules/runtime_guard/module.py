"""Container runtime security guard — Project 08 integration."""

from __future__ import annotations

import re
from collections.abc import Iterator

from aegis.core.schema import (
    Alert, EntityRef, EntityType, HealthStatus, MitreFramework, MitreRef,
    NormalizedEvent, Observable, ObservableType, RemediationResult, Severity,
)
from aegis.engine.soar.playbook import PlaybookEngine
from aegis.modules.base import SecurityModule

DOCKER_SOCKET_PATHS = ("/var/run/docker.sock", "/run/docker.sock")
SENSITIVE_FILES = ("/etc/shadow", "/etc/passwd", "/etc/sudoers", "/proc/sysrq-trigger")


class RuntimeGuardModule(SecurityModule):
    name = "runtime-guard"
    version = "1.0.0"

    def __init__(self, soar: PlaybookEngine | None = None) -> None:
        self.playbooks = soar or PlaybookEngine()

    def collect(self) -> Iterator[NormalizedEvent]:
        return iter([])

    def ingest_falco_alert(self, rule: str, output: str, container: str = "", priority: str = "HIGH") -> NormalizedEvent:
        return self._analyze(rule, output, container, priority)

    def ingest_runtime_event(self, process: str, path: str, container: str = "") -> NormalizedEvent:
        text = f"process={process} path={path} container={container}"
        return self._analyze("runtime_event", text, container, "MEDIUM", process=process, path=path)

    def _analyze(self, rule: str, output: str, container: str, priority: str, **meta) -> NormalizedEvent:
        confidence = 0.0
        severity = Severity.INFO
        tags: list[str] = []
        kb_refs: list[str] = []
        mitre = None
        path = meta.get("path", "")

        if any(sock in output or sock in path for sock in DOCKER_SOCKET_PATHS):
            confidence = 0.98
            severity = Severity.CRITICAL
            tags.extend(["container_escape", "docker_socket"])
            kb_refs.append("RT-001")
            mitre = MitreRef(framework=MitreFramework.ATTACK, id="T1611", tactic="Privilege Escalation", technique="Escape to Host")

        if "privileged" in output.lower() or "cap_sys_admin" in output.lower():
            confidence = max(confidence, 0.95)
            severity = Severity.CRITICAL
            tags.append("privileged_container")
            kb_refs.append("RT-002")
            mitre = mitre or MitreRef(framework=MitreFramework.ATTACK, id="T1611")

        if any(sf in output or sf in path for sf in SENSITIVE_FILES):
            confidence = max(confidence, 0.9)
            severity = Severity.HIGH
            tags.append("sensitive_file_access")
            kb_refs.append("RT-003")
            mitre = mitre or MitreRef(framework=MitreFramework.ATTACK, id="T1005", tactic="Collection")

        if priority.upper() == "CRITICAL" and confidence < 0.5:
            confidence = 0.85
            severity = Severity.CRITICAL

        return NormalizedEvent(
            source_module=self.name,
            entity=EntityRef(type=EntityType.SERVICE, id=container or "host"),
            observable=Observable(type=ObservableType.LOG_LINE, value=output[:2000], metadata={"rule": rule, **meta}),
            severity=severity, confidence=confidence, mitre=mitre, kb_refs=kb_refs, tags=tags,
        )

    def detect(self, events: list[NormalizedEvent]) -> list[Alert]:
        alerts = []
        for e in events:
            if e.confidence < 0.5:
                continue
            alerts.append(Alert(
                source_module=self.name,
                title=f"Runtime threat: {e.tags[0] if e.tags else 'suspicious activity'}",
                description=e.observable.value[:300],
                severity=e.severity, mitre=e.mitre, kb_refs=e.kb_refs,
                confidence=e.confidence, entity=e.entity, events=[e.event_id],
                attack_chain_stage="execution",
                recommended_playbooks=["isolate_host", "alert_soc_generic"],
                tags=e.tags,
            ))
        return alerts

    def remediate(self, alert: Alert, playbook_id: str) -> RemediationResult:
        return self.playbooks.execute(playbook_id, alert)

    def health(self) -> HealthStatus:
        return HealthStatus(module=self.name, healthy=True)

"""Endpoint / host protection module."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone

from aegis.core.schema import (
    Alert,
    EntityRef,
    EntityType,
    HealthStatus,
    MitreFramework,
    MitreRef,
    NormalizedEvent,
    Observable,
    ObservableType,
    RemediationResult,
    Severity,
)
from aegis.engine.soar.playbook import PlaybookEngine
from aegis.modules.base import SecurityModule


class HostShieldModule(SecurityModule):
    name = "host-shield"
    version = "1.0.0"

    SUSPICIOUS_PROCESSES = re.compile(
        r"(mimikatz|powershell\s+-enc|cmd\.exe\s+/c|wget\s+http|curl\s+.*\|\s*bash)",
        re.I,
    )

    def __init__(self) -> None:
        self.playbooks = PlaybookEngine()
        self._auth_failures: dict[str, list[datetime]] = defaultdict(list)
        self._failure_threshold = 5
        self._window = timedelta(minutes=5)

    def collect(self) -> Iterator[NormalizedEvent]:
        return iter([])

    def ingest_log_line(self, host_id: str, log_line: str) -> NormalizedEvent:
        severity = Severity.INFO
        confidence = 0.0
        tags: list[str] = []
        kb_refs: list[str] = []
        mitre = None

        if self.SUSPICIOUS_PROCESSES.search(log_line):
            severity = Severity.CRITICAL
            confidence = 0.9
            tags = ["execution", "malware"]
            kb_refs = ["HOST-001"]
            mitre = MitreRef(framework=MitreFramework.ATTACK, id="T1059", tactic="Execution", technique="Command and Scripting Interpreter")

        if re.search(r"failed\s+password|authentication\s+failure", log_line, re.I):
            now = datetime.now(timezone.utc)
            self._auth_failures[host_id].append(now)
            self._auth_failures[host_id] = [
                t for t in self._auth_failures[host_id] if now - t <= self._window
            ]
            if len(self._auth_failures[host_id]) >= self._failure_threshold:
                severity = Severity.HIGH
                confidence = 0.85
                tags = ["brute_force", "credential_access"]
                kb_refs = ["HOST-002"]
                mitre = MitreRef(framework=MitreFramework.ATTACK, id="T1110", tactic="Credential Access", technique="Brute Force")

        return NormalizedEvent(
            source_module=self.name,
            entity=EntityRef(type=EntityType.HOST, id=host_id),
            observable=Observable(type=ObservableType.LOG_LINE, value=log_line[:1000]),
            severity=severity,
            confidence=confidence,
            mitre=mitre,
            kb_refs=kb_refs,
            tags=tags,
        )

    def ingest_file_hash(self, host_id: str, file_hash: str, file_path: str = "") -> NormalizedEvent:
        from aegis.core.knowledge import get_knowledge_base
        kb = get_knowledge_base()
        match = kb.match_ioc("hash", file_hash)
        if match:
            return NormalizedEvent(
                source_module=self.name,
                entity=EntityRef(type=EntityType.HOST, id=host_id),
                observable=Observable(type=ObservableType.FILE_HASH, value=file_hash, metadata={"path": file_path}),
                severity=Severity.CRITICAL,
                confidence=0.98,
                mitre=MitreRef(framework=MitreFramework.ATTACK, id=match.mitre_id or "T1204"),
                kb_refs=["HOST-003"],
                tags=["malware"],
            )
        return NormalizedEvent(
            source_module=self.name,
            entity=EntityRef(type=EntityType.HOST, id=host_id),
            observable=Observable(type=ObservableType.FILE_HASH, value=file_hash, metadata={"path": file_path}),
        )

    def detect(self, events: list[NormalizedEvent]) -> list[Alert]:
        alerts = []
        for e in events:
            if e.confidence < 0.5:
                continue
            alerts.append(
                Alert(
                    source_module=self.name,
                    title=f"Host threat on {e.entity.id}",
                    description=e.observable.value[:300],
                    severity=e.severity,
                    mitre=e.mitre,
                    kb_refs=e.kb_refs,
                    confidence=e.confidence,
                    entity=e.entity,
                    events=[e.event_id],
                    attack_chain_stage="execution",
                    recommended_playbooks=["isolate_host", "kill_process"],
                    tags=e.tags,
                )
            )
        return alerts

    def remediate(self, alert: Alert, playbook_id: str) -> RemediationResult:
        return self.playbooks.execute(playbook_id, alert)

    def health(self) -> HealthStatus:
        return HealthStatus(module=self.name, healthy=True)

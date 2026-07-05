"""Network intrusion detection module."""

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


class NetSentinelModule(SecurityModule):
    name = "net-sentinel"
    version = "1.0.0"

    def __init__(self, soar: PlaybookEngine | None = None) -> None:
        self.playbooks = soar or PlaybookEngine()
        self._connection_counts: dict[str, list[datetime]] = defaultdict(list)
        self._scan_threshold = 20
        self._window = timedelta(seconds=60)

    def collect(self) -> Iterator[NormalizedEvent]:
        return iter([])

    def ingest_flow(
        self,
        src_ip: str,
        dst_port: int,
        protocol: str = "tcp",
        bytes_sent: int = 0,
        metadata: dict | None = None,
    ) -> NormalizedEvent:
        now = datetime.now(timezone.utc)
        self._connection_counts[src_ip].append(now)
        self._connection_counts[src_ip] = [
            t for t in self._connection_counts[src_ip] if now - t <= self._window
        ]
        count = len(self._connection_counts[src_ip])
        severity = Severity.INFO
        confidence = 0.0
        tags: list[str] = []
        kb_refs: list[str] = []

        if count >= self._scan_threshold:
            severity = Severity.HIGH
            confidence = min(0.95, 0.5 + count / 100)
            tags = ["recon", "scan", "port_scan"]
            kb_refs = ["NET-001"]

        return NormalizedEvent(
            source_module=self.name,
            entity=EntityRef(type=EntityType.IP, id=src_ip),
            observable=Observable(
                type=ObservableType.FLOW,
                value=f"{protocol} {src_ip} -> *:{dst_port} ({bytes_sent}B)",
                metadata=metadata or {},
            ),
            severity=severity,
            confidence=confidence,
            mitre=MitreRef(
                framework=MitreFramework.ATTACK,
                id="T1046",
                tactic="Discovery",
                technique="Network Service Discovery",
            ) if confidence > 0 else None,
            kb_refs=kb_refs,
            tags=tags,
        )

    def ingest_dns(self, src_ip: str, domain: str) -> NormalizedEvent:
        from aegis.core.knowledge import get_knowledge_base
        kb = get_knowledge_base()

        suspicious = bool(re.search(r"(bit\.ly|ngrok|pastebin|tor2web)", domain, re.I))
        tunnel = len(domain) > 80 or domain.count(".") > 6
        ioc = kb.match_ioc("domain", domain)
        confidence = 0.0
        severity = Severity.INFO
        tags: list[str] = []
        kb_refs: list[str] = []
        mitre = None

        if ioc:
            confidence = 0.95
            severity = Severity.CRITICAL
            tags.append("ioc_match")
            kb_refs.append("NET-002")
            mitre = MitreRef(framework=MitreFramework.ATTACK, id=ioc.mitre_id or "T1071.004")
        elif suspicious:
            confidence = 0.85
            severity = Severity.HIGH
            tags.append("c2")
            kb_refs.append("NET-002")
            mitre = MitreRef(framework=MitreFramework.ATTACK, id="T1071.004")
        elif tunnel:
            confidence = 0.7
            severity = Severity.MEDIUM
            tags.append("dns_tunnel")
            kb_refs.append("NET-002")
            mitre = MitreRef(framework=MitreFramework.ATTACK, id="T1071.004")

        return NormalizedEvent(
            source_module=self.name,
            entity=EntityRef(type=EntityType.IP, id=src_ip),
            observable=Observable(type=ObservableType.DNS_QUERY, value=domain),
            severity=severity,
            confidence=confidence,
            mitre=mitre,
            kb_refs=kb_refs,
            tags=tags,
        )

    def detect(self, events: list[NormalizedEvent]) -> list[Alert]:
        alerts = []
        for e in events:
            if e.confidence < 0.5:
                continue
            alerts.append(
                Alert(
                    source_module=self.name,
                    title=f"Network threat from {e.entity.id}",
                    description=e.observable.value,
                    severity=e.severity,
                    mitre=e.mitre,
                    kb_refs=e.kb_refs,
                    confidence=e.confidence,
                    entity=e.entity,
                    events=[e.event_id],
                    attack_chain_stage="reconnaissance" if "scan" in e.tags else "execution",
                    recommended_playbooks=["block_ip", "rate_limit_scanner"],
                    tags=e.tags,
                )
            )
        return alerts

    def remediate(self, alert: Alert, playbook_id: str) -> RemediationResult:
        return self.playbooks.execute(playbook_id, alert)

    def health(self) -> HealthStatus:
        return HealthStatus(
            module=self.name,
            healthy=True,
            metrics={"tracked_ips": len(self._connection_counts)},
        )

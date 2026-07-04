"""AI agent security guard — Project 05 integration."""

from __future__ import annotations

import re
from collections.abc import Iterator

from aegis.core.schema import (
    Alert, EntityRef, EntityType, HealthStatus, MitreFramework, MitreRef,
    NormalizedEvent, Observable, ObservableType, RemediationResult, Severity,
)
from aegis.engine.soar.playbook import PlaybookEngine
from aegis.modules.base import SecurityModule

TOOL_POISON_PATTERNS = [
    re.compile(r"ignore (your|previous|all) (instructions|rules)", re.I),
    re.compile(r"new instruction[s]?:", re.I),
    re.compile(r"system prompt.*override", re.I),
    re.compile(r"execute.*command", re.I),
    re.compile(r"forward.*to\s+https?://", re.I),
]

MEMORY_INJECTION_PATTERNS = [
    re.compile(r"remember (this|that|forever)", re.I),
    re.compile(r"store in memory", re.I),
    re.compile(r"your (true|real) (identity|purpose)", re.I),
    re.compile(r"from now on you (will|must|should)", re.I),
]


class AgentGuardModule(SecurityModule):
    name = "agent-guard"
    version = "1.0.0"

    def __init__(self, soar: PlaybookEngine | None = None) -> None:
        self.playbooks = soar or PlaybookEngine()

    def collect(self) -> Iterator[NormalizedEvent]:
        return iter([])

    def ingest_tool_output(self, agent_id: str, tool_name: str, output: str, session_id: str = "") -> NormalizedEvent:
        return self._analyze(agent_id, f"tool:{tool_name}", output, session_id, "tool_output")

    def ingest_agent_message(self, agent_id: str, message: str, session_id: str = "") -> NormalizedEvent:
        return self._analyze(agent_id, "user_message", message, session_id, "message")

    def _analyze(self, agent_id: str, source: str, text: str, session_id: str, kind: str) -> NormalizedEvent:
        confidence = 0.0
        severity = Severity.INFO
        tags: list[str] = []
        kb_refs: list[str] = []
        mitre = None

        for pat in TOOL_POISON_PATTERNS:
            if pat.search(text):
                confidence = max(confidence, 0.9)
                severity = Severity.CRITICAL
                tags.extend(["tool_poisoning", "indirect_injection"])
                kb_refs.append("AGT-001")
                mitre = MitreRef(framework=MitreFramework.ATLAS, id="AML.T0054.002", technique="Indirect Prompt Injection")
                break

        for pat in MEMORY_INJECTION_PATTERNS:
            if pat.search(text):
                confidence = max(confidence, 0.85)
                if severity != Severity.CRITICAL:
                    severity = Severity.HIGH
                tags.append("memory_injection")
                if "AGT-002" not in kb_refs:
                    kb_refs.append("AGT-002")
                mitre = mitre or MitreRef(framework=MitreFramework.ATLAS, id="AML.T0054.002")

        if "http://" in text.lower() or "https://" in text.lower():
            if "exfil" in text.lower() or "forward" in text.lower():
                confidence = max(confidence, 0.8)
                severity = Severity.HIGH
                tags.append("data_exfil")
                kb_refs.append("AGT-003")

        return NormalizedEvent(
            source_module=self.name,
            entity=EntityRef(type=EntityType.SERVICE, id=agent_id, display_name=session_id),
            observable=Observable(type=ObservableType.LOG_LINE, value=text[:2000], metadata={"source": source, "kind": kind}),
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
            alerts.append(Alert(
                source_module=self.name,
                title=f"Agent threat on {e.entity.id}: {', '.join(e.kb_refs)}",
                description=e.observable.value[:300],
                severity=e.severity, mitre=e.mitre, kb_refs=e.kb_refs,
                confidence=e.confidence, entity=e.entity, events=[e.event_id],
                attack_chain_stage="access",
                recommended_playbooks=["block_llm_request", "alert_soc_llm"],
                tags=e.tags,
            ))
        return alerts

    def remediate(self, alert: Alert, playbook_id: str) -> RemediationResult:
        return self.playbooks.execute(playbook_id, alert)

    def health(self) -> HealthStatus:
        return HealthStatus(module=self.name, healthy=True)

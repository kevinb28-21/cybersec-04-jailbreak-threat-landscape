"""RAG pipeline security guard — Project 06 integration."""

from __future__ import annotations

import re
from collections.abc import Iterator

from aegis.core.schema import (
    Alert, EntityRef, EntityType, HealthStatus, MitreFramework, MitreRef,
    NormalizedEvent, Observable, ObservableType, RemediationResult, Severity,
)
from aegis.engine.soar.playbook import PlaybookEngine
from aegis.modules.base import SecurityModule

POISON_PATTERNS = [
    re.compile(r"ignore\s+.*instructions", re.I),
    re.compile(r"disregard (your|previous|all)", re.I),
    re.compile(r"(you are|you're) now (an?|the)\s+\w+", re.I),
    re.compile(r"new instruction[s]?:", re.I),
    re.compile(r"hidden instruction", re.I),
    re.compile(r"do not (mention|reveal|tell)", re.I),
]

FALSE_AUTHORITY = [
    "nist has confirmed", "cisa officially states", "secret backdoor",
    "government mandated weaknesses", "classified directive",
]


class RAGGuardModule(SecurityModule):
    name = "rag-guard"
    version = "1.0.0"

    def __init__(self, soar: PlaybookEngine | None = None) -> None:
        self.playbooks = soar or PlaybookEngine()

    def collect(self) -> Iterator[NormalizedEvent]:
        return iter([])

    def ingest_chunk(self, collection: str, source: str, chunk: str, trust_level: int = 1) -> NormalizedEvent:
        confidence = 0.0
        severity = Severity.INFO
        tags: list[str] = []
        kb_refs: list[str] = []
        mitre = None
        lower = chunk.lower()

        for pat in POISON_PATTERNS:
            if pat.search(chunk):
                confidence = max(confidence, 0.9)
                severity = Severity.CRITICAL
                tags.append("rag_poisoning")
                kb_refs.append("RAG-002")
                mitre = MitreRef(framework=MitreFramework.ATLAS, id="AML.T0020", technique="Poison Training Data")
                break

        for phrase in FALSE_AUTHORITY:
            if phrase in lower:
                confidence = max(confidence, 0.8)
                severity = Severity.HIGH
                tags.append("false_authority")
                kb_refs.append("RAG-003")
                mitre = mitre or MitreRef(framework=MitreFramework.ATLAS, id="AML.T0043")
                break

        if trust_level < 2 and confidence > 0:
            confidence = min(1.0, confidence + 0.1)

        if len(chunk) > 5000:
            confidence = max(confidence, 0.6)
            tags.append("oversized_chunk")
            kb_refs.append("RAG-001")

        return NormalizedEvent(
            source_module=self.name,
            entity=EntityRef(type=EntityType.SERVICE, id=collection),
            observable=Observable(type=ObservableType.LOG_LINE, value=chunk[:2000], metadata={"source": source, "trust": trust_level}),
            severity=severity, confidence=confidence, mitre=mitre, kb_refs=kb_refs, tags=tags,
        )

    def detect(self, events: list[NormalizedEvent]) -> list[Alert]:
        alerts = []
        for e in events:
            if e.confidence < 0.5:
                continue
            alerts.append(Alert(
                source_module=self.name,
                title=f"RAG poisoning in {e.entity.id}",
                description=e.observable.value[:300],
                severity=e.severity, mitre=e.mitre, kb_refs=e.kb_refs,
                confidence=e.confidence, entity=e.entity, events=[e.event_id],
                attack_chain_stage="staging",
                recommended_playbooks=["block_llm_request", "alert_soc_llm"],
                tags=e.tags,
            ))
        return alerts

    def remediate(self, alert: Alert, playbook_id: str) -> RemediationResult:
        return self.playbooks.execute(playbook_id, alert)

    def health(self) -> HealthStatus:
        return HealthStatus(module=self.name, healthy=True)

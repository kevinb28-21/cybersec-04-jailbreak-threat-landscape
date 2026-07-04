"""AI / LLM security guard — migrated from Project 04."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict, deque
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

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
    RemediationStatus,
    Severity,
)
from aegis.engine.soar.playbook import PlaybookEngine
from aegis.modules.base import SecurityModule
from aegis.modules.aisec_guard.taxonomy import JailbreakTaxonomy, get_taxonomy


@dataclass
class ConversationState:
    entity_id: str
    turns: deque[str]
    risk_score: float = 0.0


class AISecGuardModule(SecurityModule):
    """Detects LLM jailbreak, injection, and multi-turn escalation attacks."""

    name = "aisec-guard"
    version = "1.0.0"

    ESCALATION_KEYWORDS = [
        "synthesis route", "step by step", "ignore previous", "without restrictions",
        "in this fictional", "pretend you are", "maintenance mode",
    ]

    def __init__(self) -> None:
        self.taxonomy = get_taxonomy()
        self.playbooks = PlaybookEngine()
        self._conversations: dict[str, ConversationState] = defaultdict(
            lambda: ConversationState(entity_id="", turns=deque(maxlen=20))
        )
        self._blocked_requests = 0

    def collect(self) -> Iterator[NormalizedEvent]:
        return iter([])

    def ingest_prompt(
        self,
        prompt: str,
        entity_id: str = "llm-gateway",
        session_id: str = "default",
        metadata: dict[str, Any] | None = None,
    ) -> NormalizedEvent:
        """Primary entry point for inline LLM gateway integration."""
        event = NormalizedEvent(
            source_module=self.name,
            entity=EntityRef(type=EntityType.API_KEY, id=entity_id, display_name=session_id),
            observable=Observable(type=ObservableType.PROMPT, value=prompt, metadata=metadata or {}),
            tags=["llm", "prompt"],
        )
        enriched = self._analyze_prompt(event)
        return enriched

    def _analyze_prompt(self, event: NormalizedEvent) -> NormalizedEvent:
        prompt = event.observable.value
        lower = prompt.lower()
        matched_ids: list[str] = []
        max_severity = Severity.INFO
        confidence = 0.0

        for tech in self.taxonomy.techniques:
            if self._matches_technique(prompt, lower, tech):
                matched_ids.append(tech.id)
                sev_name = tech.severity.lower()
                try:
                    sev = Severity(sev_name)
                except ValueError:
                    sev = Severity.MEDIUM
                if list(Severity).index(sev) < list(Severity).index(max_severity):
                    max_severity = sev
                confidence = max(confidence, tech.effectiveness_rating / 5.0)

        # Multi-turn crescendo scoring
        conv_key = event.entity.display_name or event.entity.id
        state = self._conversations[conv_key]
        state.entity_id = event.entity.id
        state.turns.append(prompt)
        escalation_hits = sum(1 for kw in self.ESCALATION_KEYWORDS if kw in lower)
        if len(state.turns) >= 3:
            state.risk_score += escalation_hits * 0.15
            if state.risk_score > 0.5:
                matched_ids.append("JBT-002")
                confidence = max(confidence, state.risk_score)
                max_severity = Severity.HIGH
                event.tags.append("crescendo")

        if matched_ids:
            event.kb_refs = list(dict.fromkeys(matched_ids))
            event.severity = max_severity
            event.confidence = min(1.0, confidence)
            event.mitre = MitreRef(
                framework=MitreFramework.ATLAS,
                id="AML.T0054",
                tactic="ML Model Access",
                technique="LLM Prompt Injection",
            )
            event.tags.extend(["jailbreak", "injection"])

        return event

    def _matches_technique(self, prompt: str, lower: str, tech: Any) -> bool:
        for tag in tech.tags:
            if tag.replace("-", " ") in lower or tag in lower:
                return True
        name_tokens = tech.name.lower().split()
        if len(name_tokens) >= 2 and all(t in lower for t in name_tokens[:2]):
            return True
        if "dan" in tech.name.lower() and re.search(r"\bdan\b", lower):
            return True
        if "base64" in tech.name.lower() and re.search(r"[A-Za-z0-9+/]{40,}={0,2}", prompt):
            return True
        example = tech.example_prompt.lower()[:80]
        if len(example) > 20 and example in lower:
            return True
        return False

    def detect(self, events: list[NormalizedEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        for event in events:
            if event.confidence < 0.5:
                continue
            alerts.append(
                Alert(
                    source_module=self.name,
                    title=f"LLM threat detected: {', '.join(event.kb_refs) or 'suspicious prompt'}",
                    description=event.observable.value[:300],
                    severity=event.severity,
                    mitre=event.mitre,
                    kb_refs=event.kb_refs,
                    confidence=event.confidence,
                    entity=event.entity,
                    events=[event.event_id],
                    attack_chain_stage="access",
                    recommended_playbooks=["block_llm_request", "alert_soc_llm"],
                    tags=event.tags,
                )
            )
        return alerts

    def remediate(self, alert: Alert, playbook_id: str) -> RemediationResult:
        result = self.playbooks.execute(playbook_id, alert)
        if result.status == RemediationStatus.SUCCESS:
            self._blocked_requests += 1
        return result

    def health(self) -> HealthStatus:
        return HealthStatus(
            module=self.name,
            healthy=True,
            message="operational",
            metrics={
                "techniques_loaded": len(self.taxonomy.techniques),
                "active_conversations": len(self._conversations),
                "blocked_requests": self._blocked_requests,
            },
        )

    def probe_hash(self, prompt: str) -> str:
        return hashlib.sha256(prompt.encode()).hexdigest()[:16]

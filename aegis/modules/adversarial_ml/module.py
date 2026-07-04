"""Adversarial ML evasion detector — Project 09 integration."""

from __future__ import annotations

import math
from collections import defaultdict, deque
from collections.abc import Iterator
from datetime import datetime, timezone

from aegis.core.schema import (
    Alert, EntityRef, EntityType, HealthStatus, MitreFramework, MitreRef,
    NormalizedEvent, Observable, ObservableType, RemediationResult, Severity,
)
from aegis.engine.soar.playbook import PlaybookEngine
from aegis.modules.base import SecurityModule


class AdversarialMLModule(SecurityModule):
    name = "adversarial-ml"
    version = "1.0.0"

    def __init__(self, soar: PlaybookEngine | None = None) -> None:
        self.playbooks = soar or PlaybookEngine()
        self._query_history: dict[str, deque[list[float]]] = defaultdict(lambda: deque(maxlen=20))

    def collect(self) -> Iterator[NormalizedEvent]:
        return iter([])

    def ingest_features(self, source_ip: str, features: list[float], ml_score: float = 0.0) -> NormalizedEvent:
        """Detect adversarial evasion via feature perturbation patterns."""
        confidence = 0.0
        severity = Severity.INFO
        tags: list[str] = []
        kb_refs: list[str] = []
        mitre = None

        history = self._query_history[source_ip]
        if history:
            prev = history[-1]
            if len(prev) == len(features):
                perturbation = math.sqrt(sum((a - b) ** 2 for a, b in zip(features, prev)))
                if 0.01 < perturbation < 2.0 and ml_score < 0.3:
                    confidence = 0.75
                    severity = Severity.HIGH
                    tags.append("adversarial_evasion")
                    kb_refs.append("ADV-001")
                    mitre = MitreRef(framework=MitreFramework.ATLAS, id="AML.T0015", technique="Evade ML Model")

        history.append(features)

        if len(history) >= 10:
            norms = [math.sqrt(sum(f ** 2 for f in vec)) for vec in history]
            if max(norms) - min(norms) > 2.0:
                confidence = max(confidence, 0.7)
                severity = Severity.MEDIUM
                tags.append("query_pattern_anomaly")
                kb_refs.append("ADV-003")

        return NormalizedEvent(
            source_module=self.name,
            entity=EntityRef(type=EntityType.IP, id=source_ip),
            observable=Observable(
                type=ObservableType.FLOW,
                value=f"ml_features dim={len(features)} score={ml_score:.3f}",
                metadata={"feature_count": len(features), "ml_score": ml_score},
            ),
            severity=severity, confidence=confidence, mitre=mitre, kb_refs=kb_refs, tags=tags,
        )

    def detect(self, events: list[NormalizedEvent]) -> list[Alert]:
        alerts = []
        for e in events:
            if e.confidence < 0.5:
                continue
            alerts.append(Alert(
                source_module=self.name,
                title=f"Adversarial ML evasion from {e.entity.id}",
                description=e.observable.value,
                severity=e.severity, mitre=e.mitre, kb_refs=e.kb_refs,
                confidence=e.confidence, entity=e.entity, events=[e.event_id],
                attack_chain_stage="execution",
                recommended_playbooks=["rate_limit_scanner", "alert_soc_generic"],
                tags=e.tags,
            ))
        return alerts

    def remediate(self, alert: Alert, playbook_id: str) -> RemediationResult:
        return self.playbooks.execute(playbook_id, alert)

    def health(self) -> HealthStatus:
        return HealthStatus(module=self.name, healthy=True, metrics={"tracked_ips": len(self._query_history)})

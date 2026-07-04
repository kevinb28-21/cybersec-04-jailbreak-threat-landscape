"""Tiered detection pipeline."""

from __future__ import annotations

import logging
import hashlib
import re
from typing import Any

from aegis.core.knowledge import get_knowledge_base
from aegis.core.schema import (
    EntityRef,
    EntityType,
    MitreFramework,
    MitreRef,
    NormalizedEvent,
    Observable,
    ObservableType,
    Severity,
)
from aegis.engine.ml.infer import AnomalyScorer

logger = logging.getLogger(__name__)


class TieredDetector:
    """
    Tier 0: dedup/allowlist
    Tier 1: IOC + signature rules
    Tier 2: heuristics
    Tier 3: ML anomaly scoring
    """

    SCAN_PATTERNS = [
        re.compile(r"port\s*scan", re.I),
        re.compile(r"syn\s*flood", re.I),
        re.compile(r"nmap", re.I),
    ]
    INJECTION_PATTERNS = [
        re.compile(r"ignore\s+(all\s+)?prior\s+instructions", re.I),
        re.compile(r"do\s+anything\s+now", re.I),
        re.compile(r"jailbreak", re.I),
        re.compile(r"developer\s+mode", re.I),
        re.compile(r"you\s+are\s+now\s+dan", re.I),
    ]
    BRUTE_FORCE_PATTERNS = [
        re.compile(r"failed\s+password", re.I),
        re.compile(r"authentication\s+failure", re.I),
    ]

    def __init__(self, max_tier: int = 3, ml_enabled: bool = True) -> None:
        self.max_tier = max_tier
        self.ml_enabled = ml_enabled
        self._scorer = AnomalyScorer() if ml_enabled else None
        self._seen: set[str] = set()

    def analyze(self, event: NormalizedEvent) -> NormalizedEvent:
        """Enrich event with detection tier results; may elevate severity/confidence."""
        kb = get_knowledge_base()

        # Tier 0 — dedup key (collision-safe)
        dedup_key = hashlib.sha256(
            f"{event.source_module}:{event.entity.id}:{event.observable.type}:{event.observable.value}".encode()
        ).hexdigest()
        if dedup_key in self._seen:
            event.tags.append("deduplicated")
            return event
        self._seen.add(dedup_key)
        if len(self._seen) > 50_000:
            self._seen.clear()

        if self.max_tier < 1:
            return event

        # Tier 1 — IOC match
        ioc_types = {
            ObservableType.CONNECTION: "ip",
            ObservableType.FLOW: "ip",
            ObservableType.DNS_QUERY: "domain",
            ObservableType.FILE_HASH: "hash",
        }
        ioc_type = ioc_types.get(event.observable.type)
        ioc_value = event.observable.value
        if ioc_type == "ip" and event.observable.type == ObservableType.FLOW:
            ioc_value = event.entity.id
        if ioc_type:
            match = kb.match_ioc(ioc_type, ioc_value)
            if match:
                event.confidence = max(event.confidence, 0.95)
                try:
                    event.severity = Severity(match.severity.lower())
                except ValueError:
                    event.severity = Severity.HIGH
                event.tags.append("ioc_match")
                if match.mitre_id:
                    event.mitre = MitreRef(framework=MitreFramework.ATTACK, id=match.mitre_id)

        if self.max_tier < 2:
            return event

        # Tier 2 — heuristics
        text = event.observable.value
        for pat in self.INJECTION_PATTERNS:
            if pat.search(text):
                event.confidence = max(event.confidence, 0.85)
                event.severity = Severity.HIGH
                event.tags.extend(["jailbreak", "injection"])
                event.mitre = event.mitre or MitreRef(
                    framework=MitreFramework.ATLAS,
                    id="AML.T0054",
                    tactic="ML Model Access",
                    technique="LLM Prompt Injection",
                )
                if not event.kb_refs:
                    event.kb_refs.append("JBT-001")
                break

        for pat in self.SCAN_PATTERNS:
            if pat.search(text):
                event.confidence = max(event.confidence, 0.8)
                event.severity = Severity.MEDIUM
                event.tags.extend(["recon", "scan"])
                event.mitre = event.mitre or MitreRef(
                    framework=MitreFramework.ATTACK,
                    id="T1046",
                    tactic="Discovery",
                    technique="Network Service Discovery",
                )
                break

        for pat in self.BRUTE_FORCE_PATTERNS:
            if pat.search(text):
                event.confidence = max(event.confidence, 0.75)
                event.severity = Severity.MEDIUM
                event.tags.append("brute_force")
                event.mitre = event.mitre or MitreRef(
                    framework=MitreFramework.ATTACK,
                    id="T1110",
                    tactic="Credential Access",
                    technique="Brute Force",
                )
                break

        if self.max_tier < 3 or not self.ml_enabled or not self._scorer:
            return event

        # Tier 3 — ML anomaly
        features = self._extract_features(event)
        score = self._scorer.score(features)
        if score > 0.7:
            event.confidence = max(event.confidence, score)
            if event.severity in (Severity.INFO, Severity.LOW):
                event.severity = Severity.MEDIUM
            event.tags.append("ml_anomaly")

        return event

    def _extract_features(self, event: NormalizedEvent) -> list[float]:
        text = event.observable.value
        return [
            float(len(text)),
            float(text.count("\n")),
            float(sum(1 for c in text if not c.isalnum() and not c.isspace())),
            float(len(text.encode("utf-8"))),
            float(event.confidence),
        ]

    @staticmethod
    def build_event(
        source_module: str,
        entity_type: EntityType,
        entity_id: str,
        observable_type: ObservableType,
        value: str,
        **kwargs: Any,
    ) -> NormalizedEvent:
        return NormalizedEvent(
            source_module=source_module,
            entity=EntityRef(type=entity_type, id=entity_id),
            observable=Observable(type=observable_type, value=value),
            **kwargs,
        )

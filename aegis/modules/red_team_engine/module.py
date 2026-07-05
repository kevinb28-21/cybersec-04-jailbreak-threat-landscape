"""Red team findings importer — Project 10 integration."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from aegis.core.knowledge import get_knowledge_base
from aegis.core.schema import (
    Alert, EntityRef, EntityType, HealthStatus,
    NormalizedEvent, Observable, ObservableType, RemediationResult, Severity,
)
from aegis.engine.soar.playbook import PlaybookEngine
from aegis.modules.base import SecurityModule

CYBER_PROJECTS = Path(__file__).resolve().parent.parent.parent.parent / "cyber-projects"
DEFAULT_ATLAS = Path(__file__).resolve().parent.parent.parent.parent / "knowledge-base" / "red_team_atlas_mapping.json"


class RedTeamEngineModule(SecurityModule):
    """Imports red team findings and ATLAS mappings into the knowledge base."""

    name = "red-team-engine"
    version = "1.0.0"

    def __init__(self, soar: PlaybookEngine | None = None) -> None:
        self.playbooks = soar or PlaybookEngine()
        self._imported = 0

    def collect(self) -> Iterator[NormalizedEvent]:
        return iter([])

    def import_atlas_mapping(self, path: Path | None = None) -> int:
        mapping_path = path or CYBER_PROJECTS / "10-ai-red-team-full-exercise" / "mitre_atlas" / "attack_mapping.json"
        if not mapping_path.exists():
            mapping_path = DEFAULT_ATLAS
        if not mapping_path.exists():
            return 0
        with open(mapping_path, encoding="utf-8") as fh:
            data = json.load(fh)
        techniques = data.get("techniques", [])
        kb = get_knowledge_base()
        count = kb.import_atlas_techniques(techniques, source=self.name)
        self._imported = count
        return count

    def ingest_finding(self, finding_id: str, title: str, severity: str, description: str, atlas_id: str = "") -> NormalizedEvent:
        sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
        return NormalizedEvent(
            source_module=self.name,
            entity=EntityRef(type=EntityType.SERVICE, id="red-team"),
            observable=Observable(type=ObservableType.LOG_LINE, value=description[:2000], metadata={"finding_id": finding_id}),
            severity=sev_map.get(severity.upper(), Severity.MEDIUM),
            confidence=0.9,
            kb_refs=[finding_id] if finding_id else [],
            tags=["red_team", "finding"],
        )

    def detect(self, events: list[NormalizedEvent]) -> list[Alert]:
        alerts = []
        for e in events:
            if e.confidence < 0.5:
                continue
            alerts.append(Alert(
                source_module=self.name,
                title=f"Red team finding: {e.observable.metadata.get('finding_id', 'unknown')}",
                description=e.observable.value[:300],
                severity=e.severity, kb_refs=e.kb_refs,
                confidence=e.confidence, entity=e.entity, events=[e.event_id],
                recommended_playbooks=["alert_soc_generic"],
                tags=e.tags,
            ))
        return alerts

    def remediate(self, alert: Alert, playbook_id: str) -> RemediationResult:
        return self.playbooks.execute(playbook_id, alert)

    def health(self) -> HealthStatus:
        return HealthStatus(
            module=self.name, healthy=True,
            metrics={"atlas_techniques_imported": self._imported},
        )

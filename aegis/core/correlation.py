"""Alert correlation and incident management."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from aegis.config import settings
from aegis.core.database import get_connection
from aegis.core.schema import (
    Alert,
    AlertStatus,
    EntityRef,
    Incident,
    IncidentStatus,
    NormalizedEvent,
    Severity,
    new_id,
    utc_now,
)


class CorrelationEngine:
    """Links related alerts into incidents using entity + time window + MITRE stage."""

    STAGE_ORDER = ["reconnaissance", "staging", "access", "execution", "exfiltration", "impact"]

    def __init__(self, db_path=None, window_seconds: int | None = None) -> None:
        self.db_path = db_path or settings.sqlite_path
        self.window_seconds = window_seconds or settings.correlation_window_seconds
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return get_connection(self.db_path)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    correlation_id TEXT NOT NULL,
                    data TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    correlation_id TEXT NOT NULL UNIQUE,
                    data TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def event_to_alert(self, event: NormalizedEvent, title: str, description: str = "") -> Alert:
        from aegis.core.knowledge import get_knowledge_base

        kb = get_knowledge_base()
        playbooks: list[str] = []
        for ref in event.kb_refs:
            playbooks.extend(kb.playbooks_for_technique(ref))
        playbooks = list(dict.fromkeys(playbooks))

        severity = event.severity
        if event.confidence >= 0.9 and severity == Severity.MEDIUM:
            severity = Severity.HIGH

        return Alert(
            source_module=event.source_module,
            title=title,
            description=description or event.observable.value[:500],
            severity=severity,
            mitre=event.mitre,
            kb_refs=event.kb_refs,
            confidence=event.confidence,
            entity=event.entity,
            events=[event.event_id],
            attack_chain_stage=self._infer_stage(event),
            recommended_playbooks=playbooks,
        )

    def _infer_stage(self, event: NormalizedEvent) -> str:
        tags = {t.lower() for t in event.tags}
        if "recon" in tags or "scan" in tags:
            return "reconnaissance"
        if "injection" in tags or "jailbreak" in tags:
            return "access"
        if "exfil" in tags:
            return "exfiltration"
        if event.mitre and event.mitre.id.startswith("AML.T005"):
            return "access"
        return "execution"

    def correlate(self, alert: Alert) -> Incident:
        import json

        cutoff = (utc_now() - timedelta(seconds=self.window_seconds)).isoformat()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT data FROM alerts
                WHERE json_extract(data, '$.entity.id') = ?
                  AND created_at >= ?
                ORDER BY created_at DESC LIMIT 50
                """,
                (alert.entity.id, cutoff),
            ).fetchall()

        correlation_id = alert.correlation_id
        related_alerts: list[Alert] = [alert]
        for row in rows:
            existing = Alert.model_validate_json(row["data"])
            if self._should_merge(alert, existing):
                correlation_id = existing.correlation_id
                related_alerts.append(existing)

        incident = self._build_incident(correlation_id, related_alerts)
        self._persist(alert, incident)
        return incident

    def _should_merge(self, a: Alert, b: Alert) -> bool:
        if a.entity.id != b.entity.id:
            return False
        if a.mitre and b.mitre and a.mitre.id == b.mitre.id:
            return True
        overlap = set(a.kb_refs) & set(b.kb_refs)
        if overlap:
            return True
        stages = {a.attack_chain_stage, b.attack_chain_stage}
        if len(stages) > 1:
            ordered = self.STAGE_ORDER
            try:
                idx = sorted(stages, key=lambda s: ordered.index(s) if s in ordered else 99)
                if len(idx) == 2 and abs(ordered.index(idx[0]) - ordered.index(idx[1])) <= 1:
                    return True
            except ValueError:
                pass
        return False

    def _build_incident(self, correlation_id: str, alerts: list[Alert]) -> Incident:
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        max_sev = Severity.INFO
        for a in alerts:
            if severity_order.index(a.severity) < severity_order.index(max_sev):
                max_sev = a.severity
        entities = list({a.entity.id: a.entity for a in alerts}.values())
        techniques = list({
            a.mitre.id for a in alerts if a.mitre
        })
        return Incident(
            correlation_id=correlation_id,
            title=f"Correlated incident on {entities[0].id if entities else 'unknown'}",
            severity=max_sev,
            alerts=[a.alert_id for a in alerts],
            entities=entities,
            mitre_techniques=techniques,
            updated_at=utc_now(),
        )

    def _persist(self, alert: Alert, incident: Incident) -> None:
        import json

        alert.correlation_id = incident.correlation_id
        now = utc_now().isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO alerts (alert_id, correlation_id, data, created_at) VALUES (?, ?, ?, ?)",
                (alert.alert_id, alert.correlation_id, alert.model_dump_json(), now),
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO incidents
                (incident_id, correlation_id, data, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    incident.incident_id,
                    incident.correlation_id,
                    incident.model_dump_json(),
                    incident.created_at.isoformat(),
                    incident.updated_at.isoformat(),
                ),
            )
            conn.commit()

    def list_incidents(self, limit: int = 50) -> list[Incident]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT data FROM incidents ORDER BY updated_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [Incident.model_validate_json(r["data"]) for r in rows]

    def list_alerts(self, limit: int = 50) -> list[Alert]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT data FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [Alert.model_validate_json(r["data"]) for r in rows]

    def alert_exists(self, alert_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM alerts WHERE alert_id = ?", (alert_id,)
            ).fetchone()
        return row is not None

    def get_alert(self, alert_id: str) -> Alert | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT data FROM alerts WHERE alert_id = ?", (alert_id,)
            ).fetchone()
        if not row:
            return None
        return Alert.model_validate_json(row["data"])

    def update_alert_status(self, alert_id: str, status: AlertStatus) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT data FROM alerts WHERE alert_id = ?", (alert_id,)
            ).fetchone()
            if not row:
                return False
            alert = Alert.model_validate_json(row["data"])
            alert.status = status
            conn.execute(
                "UPDATE alerts SET data = ? WHERE alert_id = ?",
                (alert.model_dump_json(), alert_id),
            )
            conn.commit()
        return True

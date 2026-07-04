"""Unified event and alert schemas shared by all security modules."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid.uuid4())


class EntityType(str, Enum):
    USER = "user"
    HOST = "host"
    IP = "ip"
    DOMAIN = "domain"
    API_KEY = "api_key"
    PROCESS = "process"
    FILE = "file"
    SERVICE = "service"


class ObservableType(str, Enum):
    PROMPT = "prompt"
    RESPONSE = "response"
    FLOW = "flow"
    LOG_LINE = "log_line"
    FILE_HASH = "file_hash"
    DNS_QUERY = "dns_query"
    HTTP_REQUEST = "http_request"
    CONNECTION = "connection"


class MitreFramework(str, Enum):
    ATTACK = "ATTACK"
    ATLAS = "ATLAS"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EntityRef(BaseModel):
    type: EntityType
    id: str
    display_name: str = ""


class Observable(BaseModel):
    type: ObservableType
    value: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class MitreRef(BaseModel):
    framework: MitreFramework
    id: str
    tactic: str = ""
    technique: str = ""


class NormalizedEvent(BaseModel):
    """Canonical telemetry unit emitted by every security module."""

    event_id: str = Field(default_factory=new_id)
    timestamp: datetime = Field(default_factory=utc_now)
    source_module: str
    entity: EntityRef
    observable: Observable
    severity: Severity = Severity.INFO
    mitre: MitreRef | None = None
    kb_refs: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("confidence")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        return max(0.0, min(1.0, v))


class AlertStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Alert(BaseModel):
    alert_id: str = Field(default_factory=new_id)
    correlation_id: str = Field(default_factory=new_id)
    timestamp: datetime = Field(default_factory=utc_now)
    source_module: str
    title: str
    description: str = ""
    severity: Severity
    mitre: MitreRef | None = None
    kb_refs: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    entity: EntityRef
    events: list[str] = Field(default_factory=list)
    attack_chain_stage: str = ""
    recommended_playbooks: list[str] = Field(default_factory=list)
    status: AlertStatus = AlertStatus.OPEN
    tags: list[str] = Field(default_factory=list)


class IncidentStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CONTAINED = "contained"
    CLOSED = "closed"


class Incident(BaseModel):
    incident_id: str = Field(default_factory=new_id)
    correlation_id: str
    title: str
    severity: Severity
    status: IncidentStatus = IncidentStatus.OPEN
    alerts: list[str] = Field(default_factory=list)
    entities: list[EntityRef] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    playbook_runs: list[str] = Field(default_factory=list)


class RemediationStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    SKIPPED = "skipped"
    PENDING_APPROVAL = "pending_approval"


class RemediationResult(BaseModel):
    playbook_id: str
    alert_id: str
    status: RemediationStatus
    actions_taken: list[str] = Field(default_factory=list)
    rollback_actions: list[str] = Field(default_factory=list)
    message: str = ""
    timestamp: datetime = Field(default_factory=utc_now)


class HealthStatus(BaseModel):
    module: str
    healthy: bool
    message: str = ""
    last_check: datetime = Field(default_factory=utc_now)
    metrics: dict[str, Any] = Field(default_factory=dict)

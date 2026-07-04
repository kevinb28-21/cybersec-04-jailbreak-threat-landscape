"""REST API and SOC dashboard backend."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from aegis import __version__
from aegis.config import settings
from aegis.core.correlation import CorrelationEngine
from aegis.core.knowledge import get_knowledge_base
from aegis.core.schema import AlertStatus, EntityType, ObservableType
from aegis.platform import AegisPlatform

logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.app_name,
    version=__version__,
    description="Unified cybersecurity platform API",
)

_platform: AegisPlatform | None = None


def get_platform() -> AegisPlatform:
    global _platform
    if _platform is None:
        _platform = AegisPlatform()
    return _platform


def verify_api_key(x_api_key: str = Header(default="")) -> None:
    if settings.api_key and x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")


class IngestPromptRequest(BaseModel):
    prompt: str
    entity_id: str = "llm-gateway"
    session_id: str = "default"


class IngestFlowRequest(BaseModel):
    src_ip: str
    dst_port: int
    protocol: str = "tcp"
    bytes_sent: int = 0


class IngestLogRequest(BaseModel):
    host_id: str
    log_line: str


class FeedbackRequest(BaseModel):
    alert_id: str
    label: str = Field(pattern="^(true_positive|false_positive)$")
    notes: str = ""


@app.get("/health")
async def health() -> dict[str, Any]:
    platform = get_platform()
    return {"status": "ok", "version": __version__, "profile": settings.deployment_profile}


@app.get("/status", dependencies=[Depends(verify_api_key)] if False else [])
async def status() -> dict[str, Any]:
    return get_platform().status()


@app.get("/modules")
async def list_modules() -> dict[str, Any]:
    return get_platform().health_all()


@app.post("/ingest/prompt")
async def ingest_prompt(req: IngestPromptRequest) -> dict[str, Any]:
    platform = get_platform()
    mod = platform.get_module("aisec-guard")
    from aegis.modules.aisec_guard.module import AISecGuardModule
    assert isinstance(mod, AISecGuardModule)
    event = mod.ingest_prompt(req.prompt, req.entity_id, req.session_id)
    return await platform.ingest(event)


@app.post("/ingest/flow")
async def ingest_flow(req: IngestFlowRequest) -> dict[str, Any]:
    platform = get_platform()
    mod = platform.get_module("net-sentinel")
    from aegis.modules.net_sentinel.module import NetSentinelModule
    assert isinstance(mod, NetSentinelModule)
    event = mod.ingest_flow(req.src_ip, req.dst_port, req.protocol, req.bytes_sent)
    return await platform.ingest(event)


@app.post("/ingest/log")
async def ingest_log(req: IngestLogRequest) -> dict[str, Any]:
    platform = get_platform()
    mod = platform.get_module("host-shield")
    from aegis.modules.host_shield.module import HostShieldModule
    assert isinstance(mod, HostShieldModule)
    event = mod.ingest_log_line(req.host_id, req.log_line)
    return await platform.ingest(event)


@app.get("/alerts")
async def list_alerts(limit: int = 50) -> list[dict]:
    correlator = CorrelationEngine()
    return [a.model_dump(mode="json") for a in correlator.list_alerts(limit)]


@app.get("/incidents")
async def list_incidents(limit: int = 50) -> list[dict]:
    correlator = CorrelationEngine()
    return [i.model_dump(mode="json") for i in correlator.list_incidents(limit)]


@app.get("/knowledge/techniques")
async def list_techniques(q: str = "", category: str = "", severity: str = "") -> list[dict]:
    kb = get_knowledge_base()
    return [
        {
            "id": t.id,
            "name": t.name,
            "category": t.category,
            "severity": t.severity,
            "source": t.source,
            "mitre_id": t.mitre_id,
            "tags": t.tags,
        }
        for t in kb.search_techniques(q, category, severity)
    ]


@app.get("/knowledge/stats")
async def knowledge_stats() -> dict:
    return get_knowledge_base().statistics()


@app.get("/playbooks")
async def list_playbooks() -> list[str]:
    return get_platform().soar.list_playbooks()


@app.post("/feedback")
async def submit_feedback(req: FeedbackRequest) -> dict:
    kb = get_knowledge_base()
    kb.add_feedback(req.alert_id, req.label, req.notes)
    return {"status": "recorded"}


@app.patch("/alerts/{alert_id}/status")
async def update_alert_status(alert_id: str, status: AlertStatus) -> dict:
    correlator = CorrelationEngine()
    ok = correlator.update_alert_status(alert_id, status)
    if not ok:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"alert_id": alert_id, "status": status.value}

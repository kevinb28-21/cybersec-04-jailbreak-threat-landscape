"""REST API and SOC dashboard backend."""

from __future__ import annotations

import logging
import secrets
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from aegis import __version__
from aegis.config import settings
from aegis.core.schema import AlertStatus
from aegis.platform import AegisPlatform

logger = logging.getLogger(__name__)

_rate_buckets: dict[str, list[float]] = defaultdict(list)
_watchdog_task = None


def _rate_limit_check(client_id: str) -> None:
    now = time.monotonic()
    window = 60.0
    bucket = _rate_buckets[client_id]
    _rate_buckets[client_id] = [t for t in bucket if now - t < window]
    if len(_rate_buckets[client_id]) >= settings.rate_limit_per_minute:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    _rate_buckets[client_id].append(now)


def verify_api_key(x_api_key: str = Header(default="")) -> None:
    settings.require_api_key_in_production()
    if not secrets.compare_digest(x_api_key, settings.api_key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


async def rate_limit_dependency(
    request: Request,
    _: None = Depends(verify_api_key),
) -> None:
    client_id = request.client.host if request.client else "unknown"
    _rate_limit_check(client_id)


_platform: AegisPlatform | None = None


def get_platform() -> AegisPlatform:
    global _platform
    if _platform is None:
        _platform = AegisPlatform()
    return _platform


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    import asyncio

    global _watchdog_task
    settings.require_api_key_in_production()
    platform = get_platform()

    if settings.watchdog_enabled:
        from aegis.agents.watchdog import SelfHealingWatchdog

        watchdog = SelfHealingWatchdog()
        for name, mod in platform.modules.items():
            watchdog.register(
                name,
                mod.health,
                restart_fn=lambda n=name: logger.info("Restart requested for %s", n),
            )
        _watchdog_task = asyncio.create_task(watchdog.run())
        logger.info("Watchdog started")

    yield

    if _watchdog_task:
        from aegis.agents.watchdog import SelfHealingWatchdog
        _watchdog_task.cancel()


app = FastAPI(
    title=settings.app_name,
    version=__version__,
    description="Unified cybersecurity platform API",
    lifespan=lifespan,
    docs_url="/docs" if settings.environment == "development" else None,
    redoc_url="/redoc" if settings.environment == "development" else None,
    openapi_url="/openapi.json" if settings.environment == "development" else None,
)


class IngestPromptRequest(BaseModel):
    prompt: str = Field(..., max_length=32_000)
    entity_id: str = "llm-gateway"
    session_id: str = "default"
    auto_respond: bool = False


class IngestFlowRequest(BaseModel):
    src_ip: str
    dst_port: int = Field(..., ge=1, le=65535)
    protocol: str = "tcp"
    bytes_sent: int = Field(default=0, ge=0)
    auto_respond: bool = False


class IngestLogRequest(BaseModel):
    host_id: str
    log_line: str = Field(..., max_length=16_000)
    auto_respond: bool = False


class IngestDnsRequest(BaseModel):
    src_ip: str
    domain: str = Field(..., max_length=253)
    auto_respond: bool = False


class IngestHashRequest(BaseModel):
    host_id: str
    file_hash: str = Field(..., max_length=128)
    file_path: str = ""
    auto_respond: bool = False


class FeedbackRequest(BaseModel):
    alert_id: str
    label: str = Field(pattern="^(true_positive|false_positive)$")
    notes: str = Field(default="", max_length=2000)


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "version": __version__, "profile": settings.deployment_profile}


@app.get("/status", dependencies=[Depends(verify_api_key)])
async def status() -> dict[str, Any]:
    return get_platform().status()


@app.get("/modules", dependencies=[Depends(verify_api_key)])
async def list_modules() -> dict[str, Any]:
    return get_platform().health_all()


@app.post("/ingest/prompt", dependencies=[Depends(rate_limit_dependency)])
async def ingest_prompt(req: IngestPromptRequest) -> dict[str, Any]:
    platform = get_platform()
    mod = platform.get_module("aisec-guard")
    from aegis.modules.aisec_guard.module import AISecGuardModule
    if not isinstance(mod, AISecGuardModule):
        raise HTTPException(status_code=500, detail="aisec-guard module unavailable")
    event = mod.ingest_prompt(req.prompt, req.entity_id, req.session_id)
    return await platform.ingest(event, auto_respond=req.auto_respond)


@app.post("/ingest/flow", dependencies=[Depends(rate_limit_dependency)])
async def ingest_flow(req: IngestFlowRequest) -> dict[str, Any]:
    platform = get_platform()
    mod = platform.get_module("net-sentinel")
    from aegis.modules.net_sentinel.module import NetSentinelModule
    if not isinstance(mod, NetSentinelModule):
        raise HTTPException(status_code=500, detail="net-sentinel module unavailable")
    event = mod.ingest_flow(req.src_ip, req.dst_port, req.protocol, req.bytes_sent)
    return await platform.ingest(event, auto_respond=req.auto_respond)


@app.post("/ingest/log", dependencies=[Depends(rate_limit_dependency)])
async def ingest_log(req: IngestLogRequest) -> dict[str, Any]:
    platform = get_platform()
    mod = platform.get_module("host-shield")
    from aegis.modules.host_shield.module import HostShieldModule
    if not isinstance(mod, HostShieldModule):
        raise HTTPException(status_code=500, detail="host-shield module unavailable")
    event = mod.ingest_log_line(req.host_id, req.log_line)
    return await platform.ingest(event, auto_respond=req.auto_respond)


@app.post("/ingest/dns", dependencies=[Depends(rate_limit_dependency)])
async def ingest_dns(req: IngestDnsRequest) -> dict[str, Any]:
    platform = get_platform()
    mod = platform.get_module("net-sentinel")
    from aegis.modules.net_sentinel.module import NetSentinelModule
    if not isinstance(mod, NetSentinelModule):
        raise HTTPException(status_code=500, detail="net-sentinel module unavailable")
    event = mod.ingest_dns(req.src_ip, req.domain)
    return await platform.ingest(event, auto_respond=req.auto_respond)


@app.post("/ingest/hash", dependencies=[Depends(rate_limit_dependency)])
async def ingest_hash(req: IngestHashRequest) -> dict[str, Any]:
    platform = get_platform()
    mod = platform.get_module("host-shield")
    from aegis.modules.host_shield.module import HostShieldModule
    if not isinstance(mod, HostShieldModule):
        raise HTTPException(status_code=500, detail="host-shield module unavailable")
    event = mod.ingest_file_hash(req.host_id, req.file_hash, req.file_path)
    return await platform.ingest(event, auto_respond=req.auto_respond)


@app.get("/alerts", dependencies=[Depends(verify_api_key)])
async def list_alerts(limit: int = 50) -> list[dict]:
    platform = get_platform()
    alerts = platform.correlator.list_alerts(limit)
    return [_redact_alert(a.model_dump(mode="json")) for a in alerts]


@app.get("/incidents", dependencies=[Depends(verify_api_key)])
async def list_incidents(limit: int = 50) -> list[dict]:
    platform = get_platform()
    return [i.model_dump(mode="json") for i in platform.correlator.list_incidents(limit)]


@app.get("/knowledge/techniques", dependencies=[Depends(verify_api_key)])
async def list_techniques(q: str = "", category: str = "", severity: str = "") -> list[dict]:
    from aegis.core.knowledge import get_knowledge_base
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


@app.get("/knowledge/stats", dependencies=[Depends(verify_api_key)])
async def knowledge_stats() -> dict:
    from aegis.core.knowledge import get_knowledge_base
    return get_knowledge_base().statistics()


@app.get("/playbooks", dependencies=[Depends(verify_api_key)])
async def list_playbooks() -> list[str]:
    return get_platform().soar.list_playbooks()


@app.post("/feedback", dependencies=[Depends(verify_api_key)])
async def submit_feedback(req: FeedbackRequest) -> dict:
    platform = get_platform()
    if not any(a.alert_id == req.alert_id for a in platform.correlator.list_alerts(500)):
        raise HTTPException(status_code=404, detail="Alert not found")
    from aegis.core.knowledge import get_knowledge_base
    get_knowledge_base().add_feedback(req.alert_id, req.label, req.notes)
    return {"status": "recorded"}


@app.patch("/alerts/{alert_id}/status", dependencies=[Depends(verify_api_key)])
async def update_alert_status(alert_id: str, status: AlertStatus) -> dict:
    platform = get_platform()
    ok = platform.correlator.update_alert_status(alert_id, status)
    if not ok:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"alert_id": alert_id, "status": status.value}


def _redact_alert(alert: dict) -> dict:
    desc = alert.get("description", "")
    if len(desc) > 120:
        alert["description"] = desc[:120] + "… [redacted]"
    return alert

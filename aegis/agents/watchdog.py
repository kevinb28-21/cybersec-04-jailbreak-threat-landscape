"""Self-healing watchdog — monitors module health and restarts failed components."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Callable

from aegis.config import settings
from aegis.core.audit import AuditLedger
from aegis.core.schema import HealthStatus

logger = logging.getLogger(__name__)


@dataclass
class WatchdogTarget:
    name: str
    health_fn: Callable[[], HealthStatus]
    restart_fn: Callable[[], None] | None = None
    consecutive_failures: int = 0
    last_restart: float = 0.0


class SelfHealingWatchdog:
    """Monitors registered modules; restarts on failure with cooldown."""

    MAX_FAILURES = 3
    RESTART_COOLDOWN_SECONDS = 60

    def __init__(self) -> None:
        self.targets: dict[str, WatchdogTarget] = {}
        self.audit = AuditLedger()
        self._running = False

    def register(
        self,
        name: str,
        health_fn: Callable[[], HealthStatus],
        restart_fn: Callable[[], None] | None = None,
    ) -> None:
        self.targets[name] = WatchdogTarget(name=name, health_fn=health_fn, restart_fn=restart_fn)

    async def run(self, interval: int | None = None) -> None:
        interval = interval or settings.watchdog_interval_seconds
        self._running = True
        logger.info("Watchdog started (interval=%ds)", interval)
        while self._running:
            await self.check_all()
            await asyncio.sleep(interval)

    def stop(self) -> None:
        self._running = False

    async def check_all(self) -> list[HealthStatus]:
        results: list[HealthStatus] = []
        for target in self.targets.values():
            try:
                status = target.health_fn()
            except Exception as exc:
                status = HealthStatus(module=target.name, healthy=False, message=str(exc))
            results.append(status)
            if status.healthy:
                target.consecutive_failures = 0
            else:
                target.consecutive_failures += 1
                logger.warning(
                    "Module %s unhealthy (%d/%d): %s",
                    target.name,
                    target.consecutive_failures,
                    self.MAX_FAILURES,
                    status.message,
                )
                if target.consecutive_failures >= self.MAX_FAILURES:
                    await self._attempt_restart(target)
        return results

    async def _attempt_restart(self, target: WatchdogTarget) -> None:
        now = time.monotonic()
        if now - target.last_restart < self.RESTART_COOLDOWN_SECONDS:
            return
        if not target.restart_fn:
            logger.error("No restart function for %s", target.name)
            return
        logger.info("Restarting module: %s", target.name)
        try:
            target.restart_fn()
            target.consecutive_failures = 0
            target.last_restart = now
            self.audit.append(
                actor="watchdog",
                action="module_restarted",
                resource_type="module",
                resource_id=target.name,
                payload={"reason": "consecutive health check failures"},
            )
        except Exception:
            logger.exception("Failed to restart %s", target.name)

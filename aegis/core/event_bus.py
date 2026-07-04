"""Event bus abstraction — in-memory default, Redis optional."""

from __future__ import annotations

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import AsyncIterator, Callable
from typing import Any

from aegis.config import settings
from aegis.core.schema import Alert, NormalizedEvent

logger = logging.getLogger(__name__)

EventHandler = Callable[[NormalizedEvent], Any]
AlertHandler = Callable[[Alert], Any]


class EventBus(ABC):
    @abstractmethod
    async def publish_event(self, event: NormalizedEvent) -> None: ...

    @abstractmethod
    async def publish_alert(self, alert: Alert) -> None: ...

    @abstractmethod
    def subscribe_events(self, handler: EventHandler) -> None: ...

    @abstractmethod
    def subscribe_alerts(self, handler: AlertHandler) -> None: ...

    @abstractmethod
    async def drain_events(self, limit: int = 100) -> list[NormalizedEvent]: ...

    @abstractmethod
    async def drain_alerts(self, limit: int = 100) -> list[Alert]: ...


class InMemoryEventBus(EventBus):
    """Thread-safe in-process bus for personal/SMB deployments."""

    def __init__(self, maxsize: int | None = None) -> None:
        self._maxsize = maxsize or settings.event_queue_maxsize
        self._events: deque[NormalizedEvent] = deque(maxlen=self._maxsize)
        self._alerts: deque[Alert] = deque(maxlen=self._maxsize)
        self._event_handlers: list[EventHandler] = []
        self._alert_handlers: list[AlertHandler] = []
        self._lock = asyncio.Lock()

    def subscribe_events(self, handler: EventHandler) -> None:
        self._event_handlers.append(handler)

    def subscribe_alerts(self, handler: AlertHandler) -> None:
        self._alert_handlers.append(handler)

    async def publish_event(self, event: NormalizedEvent) -> None:
        async with self._lock:
            self._events.append(event)
        for handler in self._event_handlers:
            try:
                result = handler(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception("Event handler failed for %s", event.event_id)

    async def publish_alert(self, alert: Alert) -> None:
        async with self._lock:
            self._alerts.append(alert)
        for handler in self._alert_handlers:
            try:
                result = handler(alert)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception("Alert handler failed for %s", alert.alert_id)

    async def drain_events(self, limit: int = 100) -> list[NormalizedEvent]:
        async with self._lock:
            items = list(self._events)[-limit:]
        return items

    async def drain_alerts(self, limit: int = 100) -> list[Alert]:
        async with self._lock:
            items = list(self._alerts)[-limit:]
        return items


class RedisEventBus(EventBus):
    """Redis Streams backend for scaled deployments."""

    EVENTS_STREAM = "aegis:events"
    ALERTS_STREAM = "aegis:alerts"

    def __init__(self, redis_url: str | None = None) -> None:
        try:
            import redis.asyncio as aioredis
        except ImportError as exc:
            raise ImportError("Install redis: pip install aegis-sentinel[redis]") from exc
        self._redis = aioredis.from_url(redis_url or settings.redis_url)
        self._event_handlers: list[EventHandler] = []
        self._alert_handlers: list[AlertHandler] = []

    def subscribe_events(self, handler: EventHandler) -> None:
        self._event_handlers.append(handler)

    def subscribe_alerts(self, handler: AlertHandler) -> None:
        self._alert_handlers.append(handler)

    async def publish_event(self, event: NormalizedEvent) -> None:
        payload = event.model_dump_json()
        await self._redis.xadd(self.EVENTS_STREAM, {"data": payload})
        for handler in self._event_handlers:
            result = handler(event)
            if asyncio.iscoroutine(result):
                await result

    async def publish_alert(self, alert: Alert) -> None:
        payload = alert.model_dump_json()
        await self._redis.xadd(self.ALERTS_STREAM, {"data": payload})
        for handler in self._alert_handlers:
            result = handler(alert)
            if asyncio.iscoroutine(result):
                await result

    async def drain_events(self, limit: int = 100) -> list[NormalizedEvent]:
        entries = await self._redis.xrevrange(self.EVENTS_STREAM, count=limit)
        events: list[NormalizedEvent] = []
        for _id, fields in entries:
            data = fields.get(b"data") or fields.get("data")
            if data:
                if isinstance(data, bytes):
                    data = data.decode()
                events.append(NormalizedEvent.model_validate_json(data))
        return list(reversed(events))

    async def drain_alerts(self, limit: int = 100) -> list[Alert]:
        entries = await self._redis.xrevrange(self.ALERTS_STREAM, count=limit)
        alerts: list[Alert] = []
        for _id, fields in entries:
            data = fields.get(b"data") or fields.get("data")
            if data:
                if isinstance(data, bytes):
                    data = data.decode()
                alerts.append(Alert.model_validate_json(data))
        return list(reversed(alerts))


_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    global _bus
    if _bus is None:
        if settings.event_bus_backend == "redis":
            _bus = RedisEventBus()
        else:
            _bus = InMemoryEventBus()
    return _bus


def reset_event_bus() -> None:
    """Reset singleton — for tests."""
    global _bus
    _bus = None

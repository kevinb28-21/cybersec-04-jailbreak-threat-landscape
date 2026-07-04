"""Syslog and file-based telemetry collector."""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path
from typing import Callable, Awaitable

from aegis.config import settings

logger = logging.getLogger(__name__)

IngestCallback = Callable[[object], Awaitable[dict]]


class SyslogCollector:
    """Tail syslog/auth.log style files and forward to platform ingest."""

    def __init__(
        self,
        log_paths: list[Path] | None = None,
        poll_interval: float = 2.0,
    ) -> None:
        self.log_paths = log_paths or self._default_paths()
        self.poll_interval = poll_interval
        self._offsets: dict[str, int] = {}
        self._running = False

    def _default_paths(self) -> list[Path]:
        candidates = [
            Path("/var/log/auth.log"),
            Path("/var/log/syslog"),
            settings.data_dir / "sample_auth.log",
        ]
        return [p for p in candidates if p.exists()]

    async def run(self, on_log_line: Callable[[str, str], Awaitable[None]]) -> None:
        self._running = True
        logger.info("Syslog collector started, watching %d path(s)", len(self.log_paths))
        while self._running:
            for path in self.log_paths:
                await self._tail_file(path, on_log_line)
            await asyncio.sleep(self.poll_interval)

    def stop(self) -> None:
        self._running = False

    async def _tail_file(self, path: Path, on_log_line: Callable[[str, str], Awaitable[None]]) -> None:
        key = str(path)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                fh.seek(self._offsets.get(key, 0))
                for line in fh:
                    line = line.strip()
                    if line:
                        host_id = self._extract_host(line) or "local-host"
                        await on_log_line(host_id, line)
                self._offsets[key] = fh.tell()
        except FileNotFoundError:
            pass
        except Exception:
            logger.exception("Error tailing %s", path)

    @staticmethod
    def _extract_host(line: str) -> str | None:
        m = re.search(r"on (\S+)", line)
        return m.group(1) if m else None


class SampleLogGenerator:
    """Generate sample auth.log for personal profile demo."""

    @staticmethod
    def ensure_sample_log() -> Path:
        path = settings.data_dir / "sample_auth.log"
        if not path.exists():
            path.write_text(
                "Jan  1 00:00:01 server sshd[100]: Failed password for root from 203.0.113.50\n",
                encoding="utf-8",
            )
        return path

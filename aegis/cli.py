"""Aegis Sentinel CLI."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from aegis import __version__
from aegis.config import settings
from aegis.platform import AegisPlatform


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


async def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn
    uvicorn.run(
        "aegis.api.app:app",
        host=args.host or settings.api_host,
        port=args.port or settings.api_port,
        log_level=settings.log_level.lower(),
    )
    return 0


async def cmd_status(_: argparse.Namespace) -> int:
    platform = AegisPlatform()
    print(json.dumps(platform.status(), indent=2, default=str))
    return 0


async def cmd_test_prompt(args: argparse.Namespace) -> int:
    platform = AegisPlatform()
    from aegis.modules.aisec_guard.module import AISecGuardModule
    mod = platform.get_module("aisec-guard")
    assert isinstance(mod, AISecGuardModule)
    event = mod.ingest_prompt(args.prompt)
    result = await platform.ingest(event)
    print(json.dumps(result, indent=2))
    return 0


async def cmd_test_scan(args: argparse.Namespace) -> int:
    platform = AegisPlatform()
    from aegis.modules.net_sentinel.module import NetSentinelModule
    mod = platform.get_module("net-sentinel")
    assert isinstance(mod, NetSentinelModule)
    total_alerts = 0
    last = None
    for i in range(args.count):
        event = mod.ingest_flow(args.ip, args.port + (i % 10))
        last = await platform.ingest(event)
        total_alerts += len(last.get("alerts", []))
    summary = {
        **(last or {}),
        "scan_count": args.count,
        "total_alerts": total_alerts,
    }
    print(json.dumps(summary, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aegis", description="Aegis Sentinel unified security platform")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--log-level", default=settings.log_level)

    sub = p.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Start API server")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)

    sub.add_parser("status", help="Show platform status")

    tp = sub.add_parser("test-prompt", help="Test LLM prompt through pipeline")
    tp.add_argument("prompt", help="Prompt text to analyze")

    ts = sub.add_parser("test-scan", help="Simulate port scan detection")
    ts.add_argument("--ip", default="10.0.0.99")
    ts.add_argument("--port", type=int, default=22)
    ts.add_argument("--count", type=int, default=25)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.log_level)

    commands = {
        "serve": cmd_serve,
        "status": cmd_status,
        "test-prompt": cmd_test_prompt,
        "test-scan": cmd_test_scan,
    }
    fn = commands[args.command]
    if asyncio.iscoroutinefunction(fn):
        raise SystemExit(asyncio.run(fn(args)))
    raise SystemExit(fn(args))


if __name__ == "__main__":
    main()

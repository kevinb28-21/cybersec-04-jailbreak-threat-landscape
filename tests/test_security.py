"""Security and hardening regression tests."""

from __future__ import annotations

import concurrent.futures

import pytest

from aegis.core.audit import AuditLedger
from aegis.core.schema import EntityType, ObservableType, Severity
from aegis.engine.detectors.tiered import TieredDetector
from aegis.modules.host_shield.module import HostShieldModule
from aegis.modules.net_sentinel.module import NetSentinelModule


def test_audit_chain_concurrent_writes(tmp_path):
    db = tmp_path / "audit.db"
    ledger = AuditLedger(db_path=db)

    def write(i: int) -> str:
        return ledger.append("test", f"action-{i}", "alert", f"id-{i}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(write, range(50)))

    ok, msg = ledger.verify_chain()
    assert ok, msg


def test_ioc_match_on_flow_observable(tmp_path, monkeypatch):
    from aegis import config
    from aegis.core.knowledge import KnowledgeBase, reset_knowledge_base

    reset_knowledge_base()
    db = tmp_path / "kb.db"
    config.settings.sqlite_path = db
    kb = KnowledgeBase(db_path=db)
    kb.add_ioc("ip", "192.0.2.100", "high", "test", "T1071")

    det = TieredDetector(max_tier=1, ml_enabled=False)
    event = det.build_event(
        "net-sentinel",
        EntityType.IP,
        "192.0.2.100",
        ObservableType.FLOW,
        "tcp 192.0.2.100 -> *:22 (64B)",
    )
    enriched = det.analyze(event)
    assert enriched.confidence >= 0.9
    assert "ioc_match" in enriched.tags


def test_host_shield_merges_multiple_detections():
    mod = HostShieldModule()
    for _ in range(5):
        mod.ingest_log_line("host-1", "Failed password for root")
    event = mod.ingest_log_line(
        "host-1",
        "mimikatz executed via powershell -enc ABC failed password for root",
    )
    assert "malware" in event.tags
    assert "brute_force" in event.tags
    assert event.severity == Severity.CRITICAL


def test_net_sentinel_ioc_dns(tmp_path, monkeypatch):
    from aegis import config
    from aegis.core.knowledge import KnowledgeBase, reset_knowledge_base

    reset_knowledge_base()
    db = tmp_path / "kb.db"
    config.settings.sqlite_path = db
    KnowledgeBase(db_path=db)

    mod = NetSentinelModule()
    event = mod.ingest_dns("10.0.0.1", "evil-c2.example.com")
    assert event.confidence >= 0.9

"""Central knowledge base — techniques, IOCs, playbooks, MITRE mappings."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis.config import settings
from aegis.core.database import get_connection


@dataclass
class TechniqueRecord:
    id: str
    name: str
    category: str
    severity: str
    description: str
    mitre_id: str
    mitre_framework: str
    defense_recommendations: list[str]
    tags: list[str]
    effectiveness: int
    source: str


@dataclass
class IOCRecord:
    ioc_type: str
    value: str
    severity: str
    source: str
    mitre_id: str = ""


class KnowledgeBase:
    """Unified threat intelligence and technique store."""

    def __init__(
        self,
        knowledge_dir: Path | None = None,
        db_path: Path | None = None,
    ) -> None:
        self.knowledge_dir = knowledge_dir or settings.knowledge_dir
        self.db_path = db_path or settings.sqlite_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._techniques: dict[str, TechniqueRecord] = {}
        self._init_db()
        self.reload()

    def _connect(self) -> sqlite3.Connection:
        return get_connection(self.db_path)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_type TEXT NOT NULL,
                    value TEXT NOT NULL UNIQUE,
                    severity TEXT NOT NULL,
                    source TEXT NOT NULL,
                    mitre_id TEXT DEFAULT '',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    label TEXT NOT NULL,
                    notes TEXT DEFAULT '',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.commit()

    def reload(self) -> None:
        self._techniques.clear()
        self._load_jailbreak_techniques()
        self._load_network_techniques()
        kb = self.knowledge_dir
        self._load_json_techniques(kb / "agent_techniques.json", "agent-guard", "ATLAS")
        self._load_json_techniques(kb / "rag_techniques.json", "rag-guard", "ATLAS")
        self._load_json_techniques(kb / "vlm_techniques.json", "vlm-guard", "ATLAS")
        self._load_json_techniques(kb / "runtime_techniques.json", "runtime-guard", "ATTACK")
        self._load_json_techniques(kb / "adversarial_techniques.json", "adversarial-ml", "ATLAS")
        self._load_seed_iocs()

    def _load_json_techniques(self, path: Path, source: str, framework: str) -> None:
        if not path.exists():
            return
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        for t in data.get("techniques", []):
            rec = TechniqueRecord(
                id=t["id"],
                name=t["name"],
                category=t.get("category", ""),
                severity=t.get("severity", "MEDIUM"),
                description=t.get("description", ""),
                mitre_id=t.get("mitre_atlas_id") or t.get("mitre_attack_id", ""),
                mitre_framework=framework,
                defense_recommendations=t.get("defense_recommendations", []),
                tags=t.get("tags", []),
                effectiveness=int(t.get("effectiveness_rating", 3)),
                source=source,
            )
            self._techniques[rec.id] = rec

    def _load_jailbreak_techniques(self) -> None:
        path = self.knowledge_dir / "jailbreak_techniques.json"
        if not path.exists():
            legacy = Path(__file__).resolve().parent.parent.parent / "techniques" / "jailbreak_techniques.json"
            if legacy.exists():
                path = legacy
        self._load_json_techniques(path, "aisec-guard", "ATLAS")

    def _load_network_techniques(self) -> None:
        path = self.knowledge_dir / "network_techniques.json"
        self._load_json_techniques(path, "net-sentinel", "ATTACK")

    def _load_seed_iocs(self) -> None:
        seed_path = self.knowledge_dir / "seed_iocs.json"
        if not seed_path.exists():
            return
        with open(seed_path, encoding="utf-8") as fh:
            data = json.load(fh)
        for ioc in data.get("iocs", []):
            self.add_ioc(
                ioc_type=ioc["type"],
                value=ioc["value"],
                severity=ioc.get("severity", "high"),
                source=ioc.get("source", "seed"),
                mitre_id=ioc.get("mitre_id", ""),
                skip_if_exists=True,
            )

    def get_technique(self, technique_id: str) -> TechniqueRecord | None:
        return self._techniques.get(technique_id.upper()) or self._techniques.get(technique_id)

    def search_techniques(
        self,
        query: str = "",
        category: str = "",
        severity: str = "",
        source: str = "",
    ) -> list[TechniqueRecord]:
        results = list(self._techniques.values())
        if query:
            q = query.lower()
            results = [
                t for t in results
                if q in t.name.lower() or q in t.description.lower() or any(q in tag for tag in t.tags)
            ]
        if category:
            c = category.lower()
            results = [t for t in results if c in t.category.lower()]
        if severity:
            results = [t for t in results if t.severity.upper() == severity.upper()]
        if source:
            results = [t for t in results if t.source == source]
        return results

    def mitigations_for(self, technique_id: str) -> list[str]:
        tech = self.get_technique(technique_id)
        return tech.defense_recommendations if tech else []

    def playbooks_for_technique(self, technique_id: str) -> list[str]:
        tech = self.get_technique(technique_id)
        if not tech:
            return []
        mapping = {
            "aisec-guard": ["block_llm_request", "alert_soc_llm"],
            "net-sentinel": ["block_ip", "rate_limit_scanner"],
            "host-shield": ["isolate_host", "kill_process"],
            "agent-guard": ["block_llm_request", "alert_soc_llm"],
            "rag-guard": ["block_llm_request", "alert_soc_llm"],
            "vlm-guard": ["block_llm_request", "alert_soc_llm"],
            "runtime-guard": ["isolate_host", "alert_soc_generic"],
            "adversarial-ml": ["rate_limit_scanner", "alert_soc_generic"],
            "red-team-engine": ["alert_soc_generic"],
        }
        return mapping.get(tech.source, ["alert_soc_generic"])

    def add_ioc(
        self,
        ioc_type: str,
        value: str,
        severity: str,
        source: str,
        mitre_id: str = "",
        skip_if_exists: bool = False,
    ) -> bool:
        with self._connect() as conn:
            if skip_if_exists:
                existing = conn.execute(
                    "SELECT 1 FROM iocs WHERE value = ?", (value,)
                ).fetchone()
                if existing:
                    return False
            conn.execute(
                """
                INSERT OR REPLACE INTO iocs (ioc_type, value, severity, source, mitre_id)
                VALUES (?, ?, ?, ?, ?)
                """,
                (ioc_type, value, severity, source, mitre_id),
            )
            conn.commit()
        return True

    def match_ioc(self, ioc_type: str, value: str) -> IOCRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM iocs WHERE ioc_type = ? AND value = ?",
                (ioc_type, value),
            ).fetchone()
        if not row:
            return None
        return IOCRecord(
            ioc_type=row["ioc_type"],
            value=row["value"],
            severity=row["severity"],
            source=row["source"],
            mitre_id=row["mitre_id"] or "",
        )

    def add_feedback(self, alert_id: str, label: str, notes: str = "") -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO feedback (alert_id, label, notes) VALUES (?, ?, ?)",
                (alert_id, label, notes),
            )
            conn.commit()

    def statistics(self) -> dict[str, Any]:
        by_source: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for t in self._techniques.values():
            by_source[t.source] = by_source.get(t.source, 0) + 1
            by_severity[t.severity] = by_severity.get(t.severity, 0) + 1
        with self._connect() as conn:
            ioc_count = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        return {
            "total_techniques": len(self._techniques),
            "by_source": by_source,
            "by_severity": by_severity,
            "ioc_count": ioc_count,
        }


_kb: KnowledgeBase | None = None


def get_knowledge_base() -> KnowledgeBase:
    global _kb
    if _kb is None:
        _kb = KnowledgeBase()
    return _kb


def reset_knowledge_base() -> None:
    global _kb
    _kb = None

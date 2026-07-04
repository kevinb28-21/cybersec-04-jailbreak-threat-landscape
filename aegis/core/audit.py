"""Tamper-evident audit ledger with hash chaining."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegis.config import settings


class AuditLedger:
    """Append-only hash-chained audit log for compliance and forensics."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or settings.sqlite_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_chain (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_chain(resource_type, resource_id)"
            )
            conn.commit()

    def _last_hash(self, conn: sqlite3.Connection) -> str:
        row = conn.execute(
            "SELECT entry_hash FROM audit_chain ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row["entry_hash"] if row else "0" * 64

    def append(
        self,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str,
        payload: dict[str, Any] | None = None,
    ) -> str:
        ts = datetime.now(timezone.utc).isoformat()
        body = {
            "timestamp": ts,
            "actor": actor,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "payload": payload or {},
        }
        with self._connect() as conn:
            prev_hash = self._last_hash(conn)
            canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
            entry_hash = hashlib.sha256(f"{prev_hash}:{canonical}".encode()).hexdigest()
            conn.execute(
                """
                INSERT INTO audit_chain
                (timestamp, actor, action, resource_type, resource_id, payload, prev_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    actor,
                    action,
                    resource_type,
                    resource_id,
                    json.dumps(payload or {}),
                    prev_hash,
                    entry_hash,
                ),
            )
            conn.commit()
        return entry_hash

    def verify_chain(self) -> tuple[bool, str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_chain ORDER BY id ASC"
            ).fetchall()
        prev = "0" * 64
        for row in rows:
            body = {
                "timestamp": row["timestamp"],
                "actor": row["actor"],
                "action": row["action"],
                "resource_type": row["resource_type"],
                "resource_id": row["resource_id"],
                "payload": json.loads(row["payload"]),
            }
            canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
            expected = hashlib.sha256(f"{prev}:{canonical}".encode()).hexdigest()
            if expected != row["entry_hash"]:
                return False, f"Chain broken at id={row['id']}"
            if row["prev_hash"] != prev:
                return False, f"Prev hash mismatch at id={row['id']}"
            prev = row["entry_hash"]
        return True, "OK"

    def query(
        self,
        resource_type: str | None = None,
        resource_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if resource_type:
            clauses.append("resource_type = ?")
            params.append(resource_type)
        if resource_id:
            clauses.append("resource_id = ?")
            params.append(resource_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM audit_chain {where} ORDER BY id DESC LIMIT ?",
                params,
            ).fetchall()
        return [dict(r) for r in rows]

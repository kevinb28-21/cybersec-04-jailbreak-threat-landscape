"""Shared SQLite connection helpers with WAL and concurrency safety."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from aegis.config import settings

_init_lock = threading.Lock()
_initialized: set[str] = set()


def get_connection(db_path: Path | None = None) -> sqlite3.Connection:
    path = str(db_path or settings.sqlite_path)
    conn = sqlite3.connect(path, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    with _init_lock:
        if path not in _initialized:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA synchronous=NORMAL")
            _initialized.add(path)
    return conn

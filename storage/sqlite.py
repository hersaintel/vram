"""SQLite-backed storage for observations and hypotheses."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from config import DB_PATH
from models.observation import Observation


class SQLiteStorage:
    """SQLite storage implementing the MemoryBackend protocol.

    Uses a shared in-memory database by default for reliability in
    constrained environments. Pass a file path for persistence.
    """

    # Class-level shared connection for in-memory mode so all instances
    # see the same data within a process.
    _memory_conn: sqlite3.Connection | None = None

    def __init__(self, db_path: Path | str | None = None, in_memory: bool = True) -> None:
        self.in_memory = in_memory
        if in_memory:
            if SQLiteStorage._memory_conn is None:
                SQLiteStorage._memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
                SQLiteStorage._memory_conn.row_factory = sqlite3.Row
            self.conn = SQLiteStorage._memory_conn
            self.db_path = Path(":memory:")
        else:
            self.db_path = Path(db_path) if db_path else DB_PATH
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        return self.conn

    def _init_schema(self) -> None:
        conn = self._connect()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS observations (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source TEXT,
                event_type TEXT,
                user TEXT,
                host TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                action TEXT,
                severity INTEGER,
                tags TEXT,
                metadata TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_obs_user ON observations(user)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_obs_host ON observations(host)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_obs_type ON observations(event_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_obs_ts ON observations(timestamp)")
        conn.commit()

    def add(self, observation: Observation) -> None:
        conn = self._connect()
        conn.execute(
            """
            INSERT OR REPLACE INTO observations
            (id, timestamp, source, event_type, user, host, source_ip,
             destination_ip, action, severity, tags, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                observation.id,
                observation.timestamp.isoformat(),
                observation.source,
                observation.event_type,
                observation.user,
                observation.host,
                observation.source_ip,
                observation.destination_ip,
                observation.action,
                observation.severity,
                json.dumps(observation.tags),
                json.dumps(observation.metadata),
            ),
        )
        conn.commit()

    def get_by_id(self, obs_id: str) -> Observation | None:
        conn = self._connect()
        row = conn.execute(
            "SELECT * FROM observations WHERE id = ?", (obs_id,)
        ).fetchone()
        return self._row_to_obs(row) if row else None

    def get_recent(self, limit: int = 50) -> list[Observation]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM observations ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [self._row_to_obs(r) for r in rows]

    def get_by_user(self, user: str, limit: int = 50) -> list[Observation]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM observations WHERE user = ? ORDER BY timestamp DESC LIMIT ?",
            (user, limit),
        ).fetchall()
        return [self._row_to_obs(r) for r in rows]

    def get_by_host(self, host: str, limit: int = 50) -> list[Observation]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM observations WHERE host = ? ORDER BY timestamp DESC LIMIT ?",
            (host, limit),
        ).fetchall()
        return [self._row_to_obs(r) for r in rows]

    def get_by_event_type(self, event_type: str, limit: int = 50) -> list[Observation]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM observations WHERE event_type = ? ORDER BY timestamp DESC LIMIT ?",
            (event_type, limit),
        ).fetchall()
        return [self._row_to_obs(r) for r in rows]

    def get_in_time_window(self, start: datetime, end: datetime) -> list[Observation]:
        conn = self._connect()
        rows = conn.execute(
            """
            SELECT * FROM observations
            WHERE timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp ASC
            """,
            (start.isoformat(), end.isoformat()),
        ).fetchall()
        return [self._row_to_obs(r) for r in rows]

    def get_related(self, observation: Observation, limit: int = 20) -> list[Observation]:
        """Return observations sharing user, host, or source_ip."""
        conn = self._connect()
        rows = conn.execute(
            """
            SELECT * FROM observations
            WHERE id != ?
              AND (
                (user IS NOT NULL AND user = ?)
                OR (host IS NOT NULL AND host = ?)
                OR (source_ip IS NOT NULL AND source_ip = ?)
              )
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (
                observation.id,
                observation.user,
                observation.host,
                observation.source_ip,
                limit,
            ),
        ).fetchall()
        return [self._row_to_obs(r) for r in rows]

    @staticmethod
    def _row_to_obs(row: sqlite3.Row) -> Observation:
        return Observation.from_dict(
            {
                "id": row["id"],
                "timestamp": row["timestamp"],
                "source": row["source"],
                "event_type": row["event_type"],
                "user": row["user"],
                "host": row["host"],
                "source_ip": row["source_ip"],
                "destination_ip": row["destination_ip"],
                "action": row["action"],
                "severity": row["severity"],
                "tags": json.loads(row["tags"] or "[]"),
                "metadata": json.loads(row["metadata"] or "{}"),
            }
        )

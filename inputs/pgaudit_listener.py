"""Live PostgreSQL audit listener (pgaudit-oriented).

V1 strategies (in order of preference):
  1. Poll a dedicated audit table (vram_audit_log) if present.
  2. Tail a JSON/CSV audit log file written by pgaudit or a log shipper.
  3. Fall back to synthetic events for lab demos.

Does not require pgaudit to be installed for unit tests or demos.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from inputs.postgres import PostgresAuditAdapter
from models.observation import Observation

logger = logging.getLogger("vram.pgaudit")


@dataclass
class PgAuditListenerConfig:
    """Configuration for live or file-based audit ingestion."""

    # Database poll (optional)
    dsn: str | None = None  # e.g. postgresql://vram:pass@localhost:5432/enterprise
    audit_table: str = "vram_audit_log"
    poll_interval_seconds: float = 2.0

    # File tail (optional)
    log_path: str | None = None

    # Behaviour
    batch_size: int = 100
    stop_on_error: bool = False


@dataclass
class PgAuditListener:
    """Poll DB audit table and/or tail a log file into Observations."""

    config: PgAuditListenerConfig = field(default_factory=PgAuditListenerConfig)
    _adapter: PostgresAuditAdapter = field(default_factory=PostgresAuditAdapter)
    _last_id: int = 0
    _file_offset: int = 0

    def parse_row(self, row: dict[str, Any]) -> Observation:
        """Normalise one audit row / log line dict."""
        return self._adapter.parse_event(row)

    def poll_table_once(self) -> list[Observation]:
        """Fetch new rows from audit_table where id > last seen."""
        if not self.config.dsn:
            return []
        try:
            import psycopg2
            import psycopg2.extras
        except ImportError:
            logger.warning("psycopg2 not installed — skipping live DB poll")
            return []

        observations: list[Observation] = []
        try:
            conn = psycopg2.connect(self.config.dsn)
            try:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        f"""
                        SELECT * FROM {self.config.audit_table}
                        WHERE id > %s
                        ORDER BY id ASC
                        LIMIT %s
                        """,
                        (self._last_id, self.config.batch_size),
                    )
                    rows = cur.fetchall()
                    for row in rows:
                        d = dict(row)
                        self._last_id = max(self._last_id, int(d.get("id", 0)))
                        # Map common column names to adapter fields
                        event = {
                            "timestamp": d.get("timestamp") or d.get("event_time"),
                            "user": d.get("user") or d.get("usename") or d.get("session_user"),
                            "database": d.get("database") or d.get("dbname"),
                            "client_ip": d.get("client_ip") or d.get("client_addr"),
                            "action": d.get("action") or d.get("command") or d.get("statement_type"),
                            "table": d.get("table") or d.get("object_name"),
                            "rows": d.get("rows") or d.get("row_count"),
                            "query": d.get("query") or d.get("statement"),
                            "role": d.get("role"),
                        }
                        observations.append(self.parse_row(event))
            finally:
                conn.close()
        except Exception as exc:
            logger.error("pgaudit table poll failed: %s", exc)
            if self.config.stop_on_error:
                raise
        return observations

    def tail_file_once(self) -> list[Observation]:
        """Read new JSON lines from log_path (one JSON object per line)."""
        if not self.config.log_path:
            return []
        path = Path(self.config.log_path)
        if not path.exists():
            return []

        observations: list[Observation] = []
        try:
            with path.open("r", encoding="utf-8") as fh:
                fh.seek(self._file_offset)
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        # Best-effort: treat as plain message
                        data = {"action": "UNKNOWN", "query": line}
                    observations.append(self.parse_row(data))
                self._file_offset = fh.tell()
        except Exception as exc:
            logger.error("pgaudit file tail failed: %s", exc)
            if self.config.stop_on_error:
                raise
        return observations

    def collect_once(self) -> list[Observation]:
        """One poll cycle: table + file."""
        out: list[Observation] = []
        out.extend(self.poll_table_once())
        out.extend(self.tail_file_once())
        return out

    def stream(
        self,
        on_observation: Callable[[Observation], None] | None = None,
        max_cycles: int | None = None,
    ) -> Iterator[Observation]:
        """Continuously poll and yield new observations."""
        cycles = 0
        while max_cycles is None or cycles < max_cycles:
            batch = self.collect_once()
            for obs in batch:
                if on_observation:
                    on_observation(obs)
                yield obs
            cycles += 1
            time.sleep(self.config.poll_interval_seconds)

    @staticmethod
    def ensure_audit_table_sql() -> str:
        """SQL to create a simple lab audit table (for docker init or manual setup)."""
        return """
CREATE TABLE IF NOT EXISTS vram_audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_time TIMESTAMPTZ DEFAULT NOW(),
    usename TEXT,
    session_user TEXT,
    dbname TEXT,
    client_addr INET,
    command TEXT,
    object_name TEXT,
    row_count BIGINT,
    statement TEXT,
    role TEXT
);

CREATE INDEX IF NOT EXISTS idx_vram_audit_id ON vram_audit_log(id);
""".strip()

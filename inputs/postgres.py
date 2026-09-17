"""PostgreSQL audit event adapter.

Normalises database activity events into VRAM Observation objects.
V1 supports synthetic audit JSON; live streaming is future work.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from models.observation import Observation


# Sensitive tables that raise severity
_SENSITIVE_TABLES = {
    "payroll", "salaries", "customers", "credit_cards",
    "ssn", "pii", "secrets", "credentials", "tokens",
    "patient_records", "patients", "encounters", "phi",
    "clinical", "ehr", "medical_records", "lab_results",
}

# Action → (event_type, base_severity, tags)
_ACTION_MAP: dict[str, tuple[str, int, list[str]]] = {
    "SELECT": ("database_query", 2, ["database"]),
    "INSERT": ("database_write", 2, ["database", "write"]),
    "UPDATE": ("database_write", 3, ["database", "write"]),
    "DELETE": ("database_write", 4, ["database", "write", "destructive"]),
    "CREATE": ("database_ddl", 3, ["database", "ddl"]),
    "ALTER": ("database_ddl", 3, ["database", "ddl"]),
    "DROP": ("database_ddl", 5, ["database", "ddl", "destructive"]),
    "COPY": ("database_export", 5, ["database", "export"]),
    "TRUNCATE": ("database_write", 5, ["database", "destructive"]),
    "GRANT": ("database_privilege", 4, ["database", "privilege"]),
    "REVOKE": ("database_privilege", 3, ["database", "privilege"]),
    "AUTH_SUCCESS": ("authentication_success", 1, ["database", "authentication"]),
    "AUTH_FAILURE": ("authentication_failure", 3, ["database", "authentication", "failure"]),
    "CONNECT": ("database_connect", 1, ["database"]),
    "DISCONNECT": ("database_disconnect", 1, ["database"]),
}


def _parse_timestamp(raw: Any) -> datetime:
    if raw is None:
        return datetime.now(timezone.utc)
    if isinstance(raw, (int, float)):
        if raw > 1e12:
            raw = raw / 1000.0
        return datetime.fromtimestamp(raw, tz=timezone.utc)
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _is_sensitive(table: str | None, database: str | None) -> bool:
    candidates = []
    if table:
        candidates.append(table.lower())
    if database:
        candidates.append(database.lower())
    return any(s in c for c in candidates for s in _SENSITIVE_TABLES)


class PostgresAuditAdapter:
    """Convert PostgreSQL audit-style events into normalised Observations."""

    SOURCE = "postgresql"

    def parse_event(self, event: dict[str, Any]) -> Observation:
        """Parse a single audit event dict into an Observation."""
        action = str(event.get("action") or event.get("command") or "UNKNOWN").upper()
        mapped = _ACTION_MAP.get(action)

        if mapped:
            event_type, base_severity, tags = mapped
        else:
            event_type = "database_activity"
            base_severity = 2
            tags = ["database"]

        table = event.get("table") or event.get("object_name") or event.get("relation")
        database = event.get("database") or event.get("db") or event.get("dbname")
        rows = event.get("rows") or event.get("row_count") or event.get("n_rows")
        try:
            rows_n = int(rows) if rows is not None else 0
        except (TypeError, ValueError):
            rows_n = 0

        severity = base_severity
        tags = list(tags)

        if _is_sensitive(str(table) if table else None, str(database) if database else None):
            severity = min(10, severity + 2)
            if "sensitive_data" not in tags:
                tags.append("sensitive_data")

        if rows_n >= 10000 or action in ("COPY",):
            severity = min(10, max(severity, 7))
            event_type = "database_export" if action in ("SELECT", "COPY") else event_type
            if "export" not in tags:
                tags.append("export")
            if "large_query" not in tags:
                tags.append("large_query")
        elif rows_n >= 1000:
            severity = min(10, severity + 1)
            if "large_query" not in tags:
                tags.append("large_query")

        role = event.get("role") or event.get("session_user")
        if role and str(role).lower() in ("postgres", "superuser", "admin", "rds_superuser"):
            severity = min(10, severity + 1)
            if "privilege" not in tags:
                tags.append("privilege")

        user = event.get("user") or event.get("usename") or event.get("session_user")
        client_ip = (
            event.get("client_ip")
            or event.get("client_addr")
            or event.get("remote_addr")
            or event.get("ip")
        )
        host = event.get("host") or event.get("server") or database

        metadata: dict[str, Any] = {
            "database": database,
            "table": table,
            "rows": rows_n if rows_n else None,
            "role": role,
            "query": event.get("query") or event.get("statement"),
            "application": event.get("application_name") or event.get("app"),
        }
        metadata = {k: v for k, v in metadata.items() if v is not None}

        return Observation(
            id=str(event.get("id") or uuid4()),
            timestamp=_parse_timestamp(event.get("timestamp") or event.get("time")),
            source=self.SOURCE,
            event_type=event_type,
            user=str(user) if user else None,
            host=str(host) if host else None,
            source_ip=str(client_ip) if client_ip else None,
            destination_ip=None,
            action=action,
            severity=severity,
            tags=tags,
            metadata=metadata,
        )

    def parse_file(self, path: str) -> list[Observation]:
        import json
        from pathlib import Path

        raw = Path(path).read_text(encoding="utf-8")
        data = json.loads(raw)
        if isinstance(data, list):
            return [self.parse_event(e) for e in data]
        return [self.parse_event(data)]

    def parse_many(self, events: list[dict[str, Any]]) -> list[Observation]:
        return [self.parse_event(e) for e in events]
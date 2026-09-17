"""Observation model — normalized security event."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
import json


@dataclass
class Observation:
    """A single normalized security observation."""

    id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "unknown"
    event_type: str = "unknown"
    user: str | None = None
    host: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    action: str | None = None
    severity: int = 0
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Observation:
        ts = data.get("timestamp")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        elif ts is None:
            ts = datetime.now(timezone.utc)
        return cls(
            id=data.get("id", str(uuid4())),
            timestamp=ts,
            source=data.get("source", "unknown"),
            event_type=data.get("event_type", "unknown"),
            user=data.get("user"),
            host=data.get("host"),
            source_ip=data.get("source_ip"),
            destination_ip=data.get("destination_ip"),
            action=data.get("action"),
            severity=int(data.get("severity", 0)),
            tags=list(data.get("tags", [])),
            metadata=dict(data.get("metadata", {})),
        )

    @classmethod
    def from_json(cls, raw: str) -> Observation:
        return cls.from_dict(json.loads(raw))

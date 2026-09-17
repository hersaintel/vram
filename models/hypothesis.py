"""Hypothesis model."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
import json


@dataclass
class Hypothesis:
    """A security hypothesis with confidence and supporting evidence."""

    id: str = field(default_factory=lambda: str(uuid4()))
    title: str = ""
    description: str = ""
    confidence: float = 0.0
    status: str = "emerging"  # emerging | active | weakening | confirmed | dismissed
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: list[dict[str, Any]] = field(default_factory=list)
    related_users: list[str] = field(default_factory=list)
    related_hosts: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["created_at"] = self.created_at.isoformat()
        data["updated_at"] = self.updated_at.isoformat()
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Hypothesis:
        def parse_ts(val: Any) -> datetime:
            if isinstance(val, str):
                return datetime.fromisoformat(val)
            if isinstance(val, datetime):
                return val
            return datetime.now(timezone.utc)

        return cls(
            id=data.get("id", str(uuid4())),
            title=data.get("title", ""),
            description=data.get("description", ""),
            confidence=float(data.get("confidence", 0.0)),
            status=data.get("status", "emerging"),
            created_at=parse_ts(data.get("created_at")),
            updated_at=parse_ts(data.get("updated_at")),
            evidence=list(data.get("evidence", [])),
            related_users=list(data.get("related_users", [])),
            related_hosts=list(data.get("related_hosts", [])),
            tags=list(data.get("tags", [])),
        )

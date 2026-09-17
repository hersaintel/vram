"""Prediction model."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
import json


@dataclass
class Prediction:
    """A deterministic prediction about likely next activity."""

    id: str = field(default_factory=lambda: str(uuid4()))
    predicted_event: str = ""
    confidence: float = 0.0
    supporting_sequence: list[str] = field(default_factory=list)
    explanation: str = ""
    related_hypothesis_id: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["created_at"] = self.created_at.isoformat()
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Prediction:
        ts = data.get("created_at")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        elif ts is None:
            ts = datetime.now(timezone.utc)
        return cls(
            id=data.get("id", str(uuid4())),
            predicted_event=data.get("predicted_event", ""),
            confidence=float(data.get("confidence", 0.0)),
            supporting_sequence=list(data.get("supporting_sequence", [])),
            explanation=data.get("explanation", ""),
            related_hypothesis_id=data.get("related_hypothesis_id"),
            created_at=ts,
        )

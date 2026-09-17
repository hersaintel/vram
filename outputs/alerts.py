"""Structured alert generation."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from models.hypothesis import Hypothesis
from models.prediction import Prediction


@dataclass
class Alert:
    id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    severity: int = 0
    hypothesis_title: str = ""
    confidence: float = 0.0
    evidence: list[dict[str, Any]] = field(default_factory=list)
    explanation: str = ""
    prediction: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data


class AlertGenerator:
    """Produce structured alerts from hypotheses that cross a threshold."""

    def __init__(self, threshold: float = 0.70) -> None:
        self.threshold = threshold

    def maybe_alert(
        self,
        hypothesis: Hypothesis,
        prediction: Prediction | None = None,
    ) -> Alert | None:
        if hypothesis.confidence < self.threshold:
            return None
        severity = 3
        if hypothesis.confidence >= 0.90:
            severity = 5
        elif hypothesis.confidence >= 0.80:
            severity = 4
        return Alert(
            severity=severity,
            hypothesis_title=hypothesis.title,
            confidence=hypothesis.confidence,
            evidence=list(hypothesis.evidence),
            explanation=(
                f"Hypothesis '{hypothesis.title}' reached confidence "
                f"{hypothesis.confidence:.2f}."
            ),
            prediction=prediction.predicted_event if prediction else None,
        )

"""Confidence engine — explainable numeric confidence updates."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ConfidenceDelta:
    """Result of a confidence update."""

    old_confidence: float
    new_confidence: float
    delta: float
    reason: str


class ConfidenceEngine:
    """Simple, transparent confidence calculator.

    Rules:
    - Confidence always clamped to [0.0, 1.0]
    - Positive evidence increases confidence
    - Negative / mitigating evidence decreases confidence
    - Magnitude is small and additive for explainability
    """

    MIN = 0.0
    MAX = 1.0

    def clamp(self, value: float) -> float:
        return max(self.MIN, min(self.MAX, value))

    def apply(
        self,
        current: float,
        delta: float,
        reason: str = "",
    ) -> ConfidenceDelta:
        """Apply a delta and return an explainable result."""
        old = self.clamp(current)
        new = self.clamp(old + delta)
        return ConfidenceDelta(
            old_confidence=old,
            new_confidence=new,
            delta=new - old,
            reason=reason,
        )

    def increase(self, current: float, amount: float, reason: str = "") -> ConfidenceDelta:
        return self.apply(current, abs(amount), reason)

    def decrease(self, current: float, amount: float, reason: str = "") -> ConfidenceDelta:
        return self.apply(current, -abs(amount), reason)

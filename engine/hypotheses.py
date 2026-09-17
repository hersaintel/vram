"""Hypothesis engine — create, update, and track hypotheses."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from models.hypothesis import Hypothesis


class HypothesisEngine:
    """In-memory hypothesis store for V1 (persisted later if needed)."""

    def __init__(self) -> None:
        self._hypotheses: dict[str, Hypothesis] = {}

    def create(
        self,
        title: str,
        description: str = "",
        confidence: float = 0.1,
        tags: list[str] | None = None,
        related_users: list[str] | None = None,
        related_hosts: list[str] | None = None,
    ) -> Hypothesis:
        hyp = Hypothesis(
            id=str(uuid4()),
            title=title,
            description=description,
            confidence=confidence,
            status="emerging",
            tags=tags or [],
            related_users=related_users or [],
            related_hosts=related_hosts or [],
        )
        self._hypotheses[hyp.id] = hyp
        return hyp

    def get(self, hyp_id: str) -> Hypothesis | None:
        return self._hypotheses.get(hyp_id)

    def get_by_title(self, title: str) -> Hypothesis | None:
        for h in self._hypotheses.values():
            if h.title == title:
                return h
        return None

    def list_active(self) -> list[Hypothesis]:
        return [
            h for h in self._hypotheses.values()
            if h.status in ("emerging", "active", "weakening", "confirmed")
        ]

    def list_all(self) -> list[Hypothesis]:
        return list(self._hypotheses.values())

    def update_confidence(
        self,
        hyp_id: str,
        new_confidence: float,
        evidence_item: dict[str, Any] | None = None,
    ) -> Hypothesis | None:
        hyp = self._hypotheses.get(hyp_id)
        if not hyp:
            return None
        hyp.confidence = max(0.0, min(1.0, new_confidence))
        hyp.updated_at = datetime.now(timezone.utc)
        if evidence_item:
            hyp.evidence.append(evidence_item)
        # Status transitions — more aggressive dismissal of weak hypotheses
        if hyp.confidence >= 0.85:
            hyp.status = "confirmed"
        elif hyp.confidence >= 0.40:
            hyp.status = "active"
        elif hyp.confidence < 0.12:
            hyp.status = "dismissed" if hyp.status in ("active", "weakening", "confirmed") else "emerging"
        elif hyp.confidence < 0.25 and hyp.status in ("active", "confirmed"):
            hyp.status = "weakening"
        return hyp

    def dismiss(self, hyp_id: str) -> None:
        hyp = self._hypotheses.get(hyp_id)
        if hyp:
            hyp.status = "dismissed"
            hyp.updated_at = datetime.now(timezone.utc)

"""Central reasoning engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from models.observation import Observation
from models.hypothesis import Hypothesis
from models.prediction import Prediction
from engine.memory import Memory
from engine.confidence import ConfidenceEngine
from engine.hypotheses import HypothesisEngine
from engine.rules import RuleEngine
from engine.predictor import Predictor
from engine.graph import EntityGraph
from engine.narrative import NarrativeEngine


@dataclass
class ReasoningResult:
    """Fully explainable output of a single reasoning step."""

    observation: Observation
    relevant_context: list[Observation] = field(default_factory=list)
    updated_hypotheses: list[Hypothesis] = field(default_factory=list)
    new_hypotheses: list[Hypothesis] = field(default_factory=list)
    predictions: list[Prediction] = field(default_factory=list)
    explanation: str = ""
    narrative: str = ""


class Reasoner:
    """Orchestrates the full VRAM pipeline for one observation."""

    def __init__(
        self,
        memory: Memory | None = None,
        confidence: ConfidenceEngine | None = None,
        hypotheses: HypothesisEngine | None = None,
        rules: RuleEngine | None = None,
        predictor: Predictor | None = None,
        graph: EntityGraph | None = None,
        narrative: NarrativeEngine | None = None,
    ) -> None:
        self.memory = memory or Memory()
        self.confidence = confidence or ConfidenceEngine()
        self.hypotheses = hypotheses or HypothesisEngine()
        self.rules = rules or RuleEngine()
        self.predictor = predictor or Predictor()
        self.graph = graph or EntityGraph()
        self.narrative = narrative or NarrativeEngine()

    def process(self, observation: Observation) -> ReasoningResult:
        # 1. Store observation
        self.memory.add(observation)
        self._update_graph(observation)

        # 2. Retrieve relevant context
        context = self.memory.get_related(observation, limit=30)
        recent = self.memory.get_recent(limit=20)

        # 3. Evaluate rules → evidence deltas
        rule_results = self.rules.evaluate(observation, context)

        updated: list[Hypothesis] = []
        created: list[Hypothesis] = []
        seen_ids: set[str] = set()

        for rr in rule_results:
            hyp = self.hypotheses.get_by_title(rr.hypothesis_title)
            is_new = False
            if hyp is None:
                hyp = self.hypotheses.create(
                    title=rr.hypothesis_title,
                    description=f"Auto-created from rule evidence: {rr.reason}",
                    confidence=0.0,
                    tags=rr.tags,
                    related_users=[observation.user] if observation.user else [],
                    related_hosts=[observation.host] if observation.host else [],
                )
                created.append(hyp)
                is_new = True

            # Apply confidence delta
            delta_result = self.confidence.apply(
                hyp.confidence, rr.delta, reason=rr.reason
            )
            evidence_item = {
                "observation_id": observation.id,
                "event_type": observation.event_type,
                "reason": rr.reason,
                "delta": round(delta_result.delta, 4),
                "timestamp": observation.timestamp.isoformat(),
            }
            updated_hyp = self.hypotheses.update_confidence(
                hyp.id, delta_result.new_confidence, evidence_item
            )
            if updated_hyp and updated_hyp.id not in seen_ids:
                if observation.user and observation.user not in updated_hyp.related_users:
                    updated_hyp.related_users.append(observation.user)
                if observation.host and observation.host not in updated_hyp.related_hosts:
                    updated_hyp.related_hosts.append(observation.host)
                updated.append(updated_hyp)
                seen_ids.add(updated_hyp.id)

        # 4. Generate predictions
        active = self.hypotheses.list_active()
        predictions = self.predictor.predict(recent, active)

        # 5. Build explanation
        explanation = self._build_explanation(
            observation, context, updated, created, predictions
        )

        # 6. Narrative for the strongest hypothesis
        narrative = ""
        if updated:
            strongest = max(updated, key=lambda h: h.confidence)
            narrative = self.narrative.build_narrative(strongest, context + [observation])

        return ReasoningResult(
            observation=observation,
            relevant_context=context,
            updated_hypotheses=updated,
            new_hypotheses=created,
            predictions=predictions,
            explanation=explanation,
            narrative=narrative,
        )

    def _update_graph(self, obs: Observation) -> None:
        if obs.user and obs.host:
            self.graph.add_edge(obs.user, "logged_into", obs.host, {"event": obs.event_type})
        if obs.user and obs.source_ip:
            self.graph.add_edge(obs.user, "from_ip", obs.source_ip)
        if obs.host and obs.source_ip:
            self.graph.add_edge(obs.host, "connected_to", obs.source_ip)

    def _build_explanation(
        self,
        obs: Observation,
        context: list[Observation],
        updated: list[Hypothesis],
        created: list[Hypothesis],
        predictions: list[Prediction],
    ) -> str:
        parts: list[str] = []
        parts.append(f"EVENT: {obs.event_type} (user={obs.user}, host={obs.host})")
        if context:
            parts.append(
                f"Relevant prior context: {len(context)} related observation(s) retrieved."
            )
        for h in created:
            parts.append(f"NEW HYPOTHESIS: {h.title} (initial confidence {h.confidence:.2f})")
        for h in updated:
            parts.append(
                f"HYPOTHESIS UPDATE: {h.title} → confidence {h.confidence:.2f} [{h.status}]"
            )
        for p in predictions:
            parts.append(
                f"PREDICTION: {p.predicted_event} (confidence {p.confidence:.2f}) — {p.explanation}"
            )
        if not updated and not created:
            parts.append("No hypothesis significantly affected by this observation.")
        return "\n".join(parts)

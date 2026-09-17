"""Simple terminal dashboard for V1."""

from __future__ import annotations

from models.hypothesis import Hypothesis
from models.observation import Observation
from models.prediction import Prediction
from engine.hypotheses import HypothesisEngine
from engine.memory import Memory


class Dashboard:
    """Render a compact terminal view of VRAM state."""

    def __init__(
        self,
        memory: Memory,
        hypotheses: HypothesisEngine,
    ) -> None:
        self.memory = memory
        self.hypotheses = hypotheses

    def render(
        self,
        predictions: list[Prediction] | None = None,
        title: str = "VRAM Dashboard",
    ) -> str:
        lines: list[str] = []
        lines.append("=" * 72)
        lines.append(f"  {title}")
        lines.append("=" * 72)

        # Active hypotheses
        active = self.hypotheses.list_active()
        lines.append("\nACTIVE HYPOTHESES")
        lines.append("-" * 40)
        if not active:
            lines.append("  (none)")
        else:
            for h in sorted(active, key=lambda x: x.confidence, reverse=True):
                bar = self._bar(h.confidence)
                lines.append(f"  {h.title}")
                lines.append(f"    confidence {h.confidence:.2f} {bar}  [{h.status}]")
                if h.related_users:
                    lines.append(f"    users: {', '.join(h.related_users)}")
                if h.related_hosts:
                    lines.append(f"    hosts: {', '.join(h.related_hosts)}")

        # Recent observations
        recent = self.memory.get_recent(limit=8)
        lines.append("\nRECENT OBSERVATIONS")
        lines.append("-" * 40)
        if not recent:
            lines.append("  (none)")
        else:
            for obs in recent:
                ts = obs.timestamp.strftime("%H:%M:%S")
                lines.append(
                    f"  [{ts}] {obs.event_type:<22} user={obs.user or '-':<10} "
                    f"host={obs.host or '-'} sev={obs.severity}"
                )

        # Predictions
        lines.append("\nCURRENT PREDICTIONS")
        lines.append("-" * 40)
        if not predictions:
            lines.append("  (none)")
        else:
            for p in predictions:
                lines.append(f"  → {p.predicted_event}  (conf {p.confidence:.2f})")
                lines.append(f"    {p.explanation}")

        # High-risk entities
        high_risk_users, high_risk_hosts = self._high_risk(active)
        lines.append("\nHIGH-RISK USERS")
        lines.append("-" * 40)
        lines.append("  " + (", ".join(high_risk_users) if high_risk_users else "(none)"))
        lines.append("\nHIGH-RISK HOSTS")
        lines.append("-" * 40)
        lines.append("  " + (", ".join(high_risk_hosts) if high_risk_hosts else "(none)"))

        lines.append("\n" + "=" * 72)
        return "\n".join(lines)

    @staticmethod
    def _bar(confidence: float, width: int = 20) -> str:
        filled = int(round(confidence * width))
        return "[" + "#" * filled + "-" * (width - filled) + "]"

    @staticmethod
    def _high_risk(hypotheses: list[Hypothesis]) -> tuple[list[str], list[str]]:
        users: set[str] = set()
        hosts: set[str] = set()
        for h in hypotheses:
            if h.confidence >= 0.45:
                users.update(h.related_users)
                hosts.update(h.related_hosts)
        return sorted(users), sorted(hosts)

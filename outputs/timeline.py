"""Chronological timeline for a hypothesis."""

from __future__ import annotations

from models.hypothesis import Hypothesis
from models.observation import Observation


class Timeline:
    """Display chronological activity associated with a hypothesis."""

    def render(
        self,
        hypothesis: Hypothesis,
        observations: list[Observation],
    ) -> str:
        lines: list[str] = []
        lines.append(f"TIMELINE — {hypothesis.title} (conf {hypothesis.confidence:.2f})")
        lines.append("-" * 50)

        ordered = sorted(observations, key=lambda o: o.timestamp)
        if not ordered:
            lines.append("  (no observations)")
            return "\n".join(lines)

        for obs in ordered:
            ts = obs.timestamp.strftime("%H:%M")
            lines.append(f"  {ts}  {obs.event_type}")
            if obs.user:
                lines.append(f"        user={obs.user}  host={obs.host or '-'}")
        return "\n".join(lines)

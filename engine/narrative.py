"""Narrative engine — turn evidence into investigator-friendly stories."""

from __future__ import annotations

from models.hypothesis import Hypothesis
from models.observation import Observation


class NarrativeEngine:
    """Generate human-readable narratives from stored evidence only."""

    def build_narrative(self, hypothesis: Hypothesis, observations: list[Observation]) -> str:
        if not observations and not hypothesis.evidence:
            return f"Hypothesis '{hypothesis.title}' has no supporting evidence yet."

        ordered = sorted(observations, key=lambda o: o.timestamp)
        lines: list[str] = []

        if ordered:
            first = ordered[0]
            who = first.user or "an account"
            lines.append(
                f"At {first.timestamp.strftime('%H:%M')} {who} authenticated or became active "
                f"(source: {first.source})."
            )
            for obs in ordered[1:]:
                ts = obs.timestamp.strftime("%H:%M")
                src = obs.source.upper()
                if obs.event_type in ("privilege_escalation", "role_mapping", "impersonation"):
                    lines.append(
                        f"At {ts} {src} recorded privileged activity for {obs.user or who}."
                    )
                elif obs.event_type in ("database_query", "database_access", "database_write"):
                    table = obs.metadata.get("table") or "a database table"
                    lines.append(
                        f"At {ts} the same account accessed {table} via {src}."
                    )
                elif obs.event_type in ("database_export",) or "export" in (obs.tags or []):
                    rows = obs.metadata.get("rows")
                    row_txt = f" approximately {rows:,} records" if rows else " a large result set"
                    lines.append(
                        f"At {ts}{row_txt} were retrieved from "
                        f"{obs.metadata.get('table') or 'a sensitive table'}."
                    )
                elif obs.event_type in ("external_connection", "network_connection"):
                    lines.append(
                        f"At {ts} {src} detected an external/network connection from the host."
                    )
                elif obs.event_type in ("authentication_failure", "multiple_failed_logins"):
                    lines.append(
                        f"At {ts} {src} recorded authentication failure(s)."
                    )
                elif obs.event_type in ("mfa_verified",) or "mfa" in (obs.tags or []):
                    lines.append(
                        f"At {ts} MFA verification was observed (mitigating signal)."
                    )
                else:
                    lines.append(
                        f"At {ts} {src} reported '{obs.event_type}'."
                    )

        lines.append("")
        lines.append(
            f"These observations from multiple telemetry sources increased the confidence "
            f"of the '{hypothesis.title}' hypothesis to {hypothesis.confidence:.2f}."
        )
        if hypothesis.evidence:
            lines.append("Key evidence points:")
            for i, ev in enumerate(hypothesis.evidence[-6:], 1):
                lines.append(f"  {i}. {ev.get('reason', ev)}")

        return "\n".join(lines)

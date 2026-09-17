"""Syslog adapter stub."""

from __future__ import annotations

from typing import Any

from models.observation import Observation


class SyslogAdapter:
    SOURCE = "syslog"

    def parse_event(self, event: dict[str, Any]) -> Observation:
        return Observation(
            source=self.SOURCE,
            event_type=str(event.get("event_type") or "syslog"),
            user=event.get("user"),
            host=event.get("host") or event.get("hostname"),
            source_ip=event.get("source_ip") or event.get("ip"),
            action=event.get("action") or event.get("message"),
            severity=int(event.get("severity", 1)),
            tags=list(event.get("tags") or ["syslog"]),
            metadata={},
        )

    def parse_many(self, events: list[dict[str, Any]]) -> list[Observation]:
        return [self.parse_event(e) for e in events]

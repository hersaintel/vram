"""Keycloak event webhook receiver helpers.

Keycloak can send events via:
  - Event Listener SPI (HTTP)
  - Custom realm event webhook

This module validates and normalises inbound webhook payloads
before they enter the VRAM reasoner.
"""

from __future__ import annotations

from typing import Any

from inputs.keycloak import KeycloakAdapter
from models.observation import Observation


class KeycloakWebhookReceiver:
    """Accept Keycloak HTTP event payloads and return Observations."""

    def __init__(self) -> None:
        self._adapter = KeycloakAdapter()

    def receive(self, payload: dict[str, Any] | list[dict[str, Any]]) -> list[Observation]:
        """Handle a single event dict or a batch list."""
        if isinstance(payload, list):
            return [self._adapter.parse_event(e) for e in payload]
        # Some Keycloak listeners wrap under "events" or "event"
        if "events" in payload and isinstance(payload["events"], list):
            return [self._adapter.parse_event(e) for e in payload["events"]]
        if "event" in payload and isinstance(payload["event"], dict):
            return [self._adapter.parse_event(payload["event"])]
        return [self._adapter.parse_event(payload)]

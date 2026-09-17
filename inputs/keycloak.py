"""Keycloak identity / IAM event adapter.

Normalises Keycloak events into VRAM Observation objects.
No Keycloak-specific structures leave this module.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from models.observation import Observation


# Map Keycloak event types → VRAM event_type + tags + base severity
_KEYCLOAK_EVENT_MAP: dict[str, tuple[str, list[str], int]] = {
    "LOGIN": ("authentication_success", ["identity", "authentication"], 2),
    "LOGIN_ERROR": ("authentication_failure", ["identity", "authentication", "failure"], 3),
    "LOGOUT": ("logout", ["identity", "authentication"], 1),
    "CODE_TO_TOKEN": ("token_issued", ["identity", "token"], 1),
    "REFRESH_TOKEN": ("token_refresh", ["identity", "token"], 1),
    "UPDATE_PASSWORD": ("password_change", ["identity", "account"], 3),
    "UPDATE_PROFILE": ("profile_update", ["identity", "account"], 2),
    "USER_CREATED": ("user_created", ["identity", "lifecycle"], 2),
    "USER_DELETED": ("user_deleted", ["identity", "lifecycle"], 3),
    "ROLE_MAPPING": ("role_mapping", ["identity", "privilege", "role"], 4),
    "CLIENT_LOGIN": ("authentication_success", ["identity", "authentication", "client"], 2),
    "FEDERATED_IDENTITY_LINK": ("identity_link", ["identity"], 2),
    "REMOVE_FEDERATED_IDENTITY": ("identity_unlink", ["identity"], 2),
    "SEND_RESET_PASSWORD": ("password_reset_request", ["identity", "account"], 2),
    "RESET_PASSWORD": ("password_reset", ["identity", "account"], 3),
    "IMPERSONATE": ("impersonation", ["identity", "privilege"], 5),
    "CUSTOM_REQUIRED_ACTION": ("mfa_challenge", ["identity", "mfa"], 2),
}


def _parse_timestamp(raw: Any) -> datetime:
    if raw is None:
        return datetime.now(timezone.utc)
    if isinstance(raw, (int, float)):
        # Keycloak often emits milliseconds since epoch
        if raw > 1e12:
            raw = raw / 1000.0
        return datetime.fromtimestamp(raw, tz=timezone.utc)
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _extract_user(event: dict[str, Any]) -> str | None:
    for key in ("userId", "username", "user", "user_name"):
        val = event.get(key)
        if val:
            return str(val)
    details = event.get("details") or {}
    for key in ("username", "user_id", "userId"):
        val = details.get(key)
        if val:
            return str(val)
    return None


class KeycloakAdapter:
    """Convert Keycloak identity events into normalised Observations."""

    SOURCE = "keycloak"

    def parse_event(self, event: dict[str, Any]) -> Observation:
        """Parse a single Keycloak event dict into an Observation."""
        raw_type = str(event.get("type") or event.get("eventType") or "UNKNOWN").upper()
        mapped = _KEYCLOAK_EVENT_MAP.get(raw_type)

        if mapped:
            event_type, tags, severity = mapped
        else:
            event_type = raw_type.lower()
            tags = ["identity"]
            severity = 2

        # MFA success is often indicated via details or a specific type
        details = event.get("details") or {}
        if details.get("auth_method") == "mfa" or "mfa" in str(details).lower():
            if "mfa" not in tags:
                tags = tags + ["mfa"]
            if event_type == "authentication_success":
                event_type = "mfa_verified"
                severity = 1

        user = _extract_user(event)
        source_ip = (
            event.get("ipAddress")
            or event.get("ip_address")
            or details.get("ipAddress")
            or details.get("ip")
        )
        client = (
            event.get("clientId")
            or event.get("client_id")
            or details.get("clientId")
            or details.get("client_id")
        )
        session_id = event.get("sessionId") or event.get("session_id")

        metadata: dict[str, Any] = {
            "raw_type": raw_type,
            "client": client,
            "session_id": session_id,
            "realm": event.get("realmId") or event.get("realm"),
        }
        # Preserve useful original fields without leaking the whole structure
        if details:
            metadata["details"] = {
                k: v for k, v in details.items()
                if k in ("username", "auth_method", "redirect_uri", "consent", "code_id")
            }
        if event.get("error"):
            metadata["error"] = event["error"]

        return Observation(
            id=str(event.get("id") or uuid4()),
            timestamp=_parse_timestamp(event.get("time") or event.get("timestamp")),
            source=self.SOURCE,
            event_type=event_type,
            user=user,
            host=None,
            source_ip=str(source_ip) if source_ip else None,
            destination_ip=None,
            action=raw_type,
            severity=severity,
            tags=tags,
            metadata=metadata,
        )

    def parse_file(self, path: str) -> list[Observation]:
        """Parse a JSON file containing one event or a list of events."""
        import json
        from pathlib import Path

        raw = Path(path).read_text(encoding="utf-8")
        data = json.loads(raw)
        if isinstance(data, list):
            return [self.parse_event(e) for e in data]
        return [self.parse_event(data)]

    def parse_many(self, events: list[dict[str, Any]]) -> list[Observation]:
        return [self.parse_event(e) for e in events]
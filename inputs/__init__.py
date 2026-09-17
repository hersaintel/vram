"""Input adapters for security telemetry."""

from .wazuh import WazuhAdapter
from .keycloak import KeycloakAdapter
from .postgres import PostgresAuditAdapter

__all__ = ["WazuhAdapter", "KeycloakAdapter", "PostgresAuditAdapter"]

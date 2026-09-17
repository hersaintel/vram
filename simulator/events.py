"""Synthetic multi-source security event generator for demos and tests.

Healthcare sector framing (synthetic identities only).
Produces Keycloak + Wazuh + PostgreSQL style events that adapters normalise.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterator

from models.observation import Observation
from inputs.keycloak import KeycloakAdapter
from inputs.wazuh import WazuhAdapter
from inputs.postgres import PostgresAuditAdapter


class EventSimulator:
    """Produces deterministic synthetic telemetry scenarios across sources."""

    def __init__(self, base_time: datetime | None = None) -> None:
        self.base_time = base_time or datetime(2026, 8, 22, 9, 0, 0, tzinfo=timezone.utc)
        self.kc = KeycloakAdapter()
        self.wz = WazuhAdapter()
        self.pg = PostgresAuditAdapter()

    def _ts(self, minutes: int = 0, seconds: int = 0) -> str:
        t = self.base_time + timedelta(minutes=minutes, seconds=seconds)
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")

    # ------------------------------------------------------------------
    # Scenario A — Normal clinical staff activity
    # ------------------------------------------------------------------
    def scenario_normal(self) -> list[Observation]:
        return [
            self.kc.parse_event({
                "timestamp": self._ts(0),
                "type": "LOGIN",
                "userId": "jordan.lee",
                "clientId": "ehr-portal",
                "ipAddress": "10.0.1.42",
            }),
            self.wz.parse_event({
                "timestamp": self._ts(2),
                "rule": {"id": "5300", "level": 2, "description": "User session opened"},
                "agent": {"name": "clinic-ws-07"},
                "data": {"dstuser": "jordan.lee"},
            }),
            self.pg.parse_event({
                "timestamp": self._ts(5),
                "user": "jordan.lee",
                "database": "ehr_lab",
                "client_ip": "10.0.1.42",
                "action": "SELECT",
                "table": "encounters",
                "rows": 8,
            }),
            self.kc.parse_event({
                "timestamp": self._ts(30),
                "type": "LOGOUT",
                "userId": "jordan.lee",
                "ipAddress": "10.0.1.42",
            }),
        ]

    # ------------------------------------------------------------------
    # Scenario B — Credential abuse against workforce identity
    # ------------------------------------------------------------------
    def scenario_credential_abuse(self) -> list[Observation]:
        return [
            self.kc.parse_event({
                "timestamp": self._ts(0),
                "type": "LOGIN_ERROR",
                "userId": "alice",
                "ipAddress": "203.0.113.50",
                "error": "invalid_credentials",
            }),
            self.kc.parse_event({
                "timestamp": self._ts(0, 30),
                "type": "LOGIN_ERROR",
                "userId": "alice",
                "ipAddress": "203.0.113.50",
            }),
            self.kc.parse_event({
                "timestamp": self._ts(1),
                "type": "LOGIN_ERROR",
                "userId": "alice",
                "ipAddress": "203.0.113.50",
            }),
            self.kc.parse_event({
                "timestamp": self._ts(2),
                "type": "LOGIN",
                "userId": "alice",
                "clientId": "ehr-portal",
                "ipAddress": "203.0.113.50",
            }),
            self.wz.parse_event({
                "timestamp": self._ts(3),
                "rule": {
                    "id": "5501",
                    "level": 4,
                    "description": "Login session from unusual source IP",
                },
                "agent": {"name": "ehr-jump-01"},
                "data": {"dstuser": "alice", "srcip": "203.0.113.50"},
            }),
        ]

    # ------------------------------------------------------------------
    # Scenario C — Possible PHI / patient-data exfiltration (primary demo)
    # ------------------------------------------------------------------
    def scenario_exfiltration(self) -> list[Observation]:
        return [
            self.kc.parse_event({
                "timestamp": self._ts(3),
                "type": "LOGIN",
                "userId": "alice",
                "clientId": "ehr-portal",
                "ipAddress": "10.0.0.25",
            }),
            self.wz.parse_event({
                "timestamp": self._ts(7),
                "rule": {
                    "id": "5401",
                    "level": 7,
                    "description": "Successful sudo to ROOT executed",
                    "groups": ["sudo", "privilege_escalation"],
                },
                "agent": {"name": "ehr-app-01"},
                "data": {"dstuser": "alice", "srcuser": "alice", "srcip": "10.0.0.25"},
            }),
            self.pg.parse_event({
                "timestamp": self._ts(12),
                "user": "alice",
                "database": "ehr_lab",
                "client_ip": "10.0.0.25",
                "action": "SELECT",
                "table": "patient_records",
                "rows": 1200,
            }),
            self.pg.parse_event({
                "timestamp": self._ts(15),
                "user": "alice",
                "database": "ehr_lab",
                "client_ip": "10.0.0.25",
                "action": "SELECT",
                "table": "patient_records",
                "rows": 30000,
            }),
            self.wz.parse_event({
                "timestamp": self._ts(20),
                "rule": {
                    "id": "5700",
                    "level": 8,
                    "description": "Unusual outbound external connection detected",
                    "groups": ["firewall", "external_connection"],
                },
                "agent": {"name": "ehr-app-01"},
                "data": {
                    "dstuser": "alice",
                    "srcip": "10.0.0.25",
                    "dstip": "198.51.100.20",
                },
            }),
        ]

    # ------------------------------------------------------------------
    # Scenario D — False positive (MFA + normal chart access)
    # ------------------------------------------------------------------
    def scenario_false_positive(self) -> list[Observation]:
        return [
            self.kc.parse_event({
                "timestamp": self._ts(0),
                "type": "LOGIN",
                "userId": "carol",
                "clientId": "ehr-portal",
                "ipAddress": "198.51.100.8",
            }),
            self.wz.parse_event({
                "timestamp": self._ts(3),
                "rule": {
                    "id": "5401",
                    "level": 6,
                    "description": "Successful sudo to ROOT executed",
                },
                "agent": {"name": "clinic-laptop-22"},
                "data": {"dstuser": "carol", "srcip": "198.51.100.8"},
            }),
            self.pg.parse_event({
                "timestamp": self._ts(8),
                "user": "carol",
                "database": "ehr_lab",
                "client_ip": "198.51.100.8",
                "action": "SELECT",
                "table": "patient_records",
                "rows": 15000,
            }),
            self.kc.parse_event({
                "timestamp": self._ts(12),
                "type": "LOGIN",
                "userId": "carol",
                "ipAddress": "198.51.100.8",
                "details": {"auth_method": "mfa"},
            }),
            self.pg.parse_event({
                "timestamp": self._ts(18),
                "user": "carol",
                "database": "ehr_lab",
                "client_ip": "198.51.100.8",
                "action": "SELECT",
                "table": "encounters",
                "rows": 25,
            }),
        ]

    def scenario_normal_user(self) -> list[Observation]:
        return self.scenario_normal()

    def scenario_suspicious_auth(self) -> list[Observation]:
        return self.scenario_credential_abuse()

    def scenario_data_exfiltration(self) -> list[Observation]:
        return self.scenario_exfiltration()

    def demo_sequence(self) -> Iterator[Observation]:
        for obs in self.scenario_exfiltration():
            yield obs
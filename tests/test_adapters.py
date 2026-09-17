"""Normalisation tests for Keycloak, Wazuh, and PostgreSQL adapters."""

from datetime import datetime, timezone

import pytest

from inputs.keycloak import KeycloakAdapter
from inputs.wazuh import WazuhAdapter
from inputs.postgres import PostgresAuditAdapter


def test_keycloak_login():
    adapter = KeycloakAdapter()
    event = {
        "timestamp": "2026-08-22T09:03:01Z",
        "type": "LOGIN",
        "userId": "alice",
        "clientId": "payroll-app",
        "ipAddress": "10.0.0.25",
    }
    obs = adapter.parse_event(event)
    assert obs.source == "keycloak"
    assert obs.event_type == "authentication_success"
    assert obs.user == "alice"
    assert obs.source_ip == "10.0.0.25"
    assert "identity" in obs.tags
    assert "authentication" in obs.tags
    assert obs.metadata.get("client") == "payroll-app"


def test_keycloak_login_error():
    adapter = KeycloakAdapter()
    obs = adapter.parse_event({
        "type": "LOGIN_ERROR",
        "userId": "alice",
        "ipAddress": "10.0.0.25",
        "error": "invalid_credentials",
    })
    assert obs.event_type == "authentication_failure"
    assert "failure" in obs.tags


def test_keycloak_role_mapping():
    adapter = KeycloakAdapter()
    obs = adapter.parse_event({
        "type": "ROLE_MAPPING",
        "userId": "alice",
        "details": {"role": "admin"},
    })
    assert obs.event_type == "role_mapping"
    assert "privilege" in obs.tags
    assert obs.severity >= 3


def test_wazuh_ssh_failure():
    adapter = WazuhAdapter()
    event = {
        "timestamp": "2026-08-22T09:03:01Z",
        "rule": {
            "id": "5710",
            "level": 5,
            "description": "SSH authentication failed",
            "groups": ["authentication_failed", "sshd"],
        },
        "agent": {"name": "linux-01", "id": "001"},
        "data": {"srcip": "10.0.0.25", "dstuser": "alice"},
    }
    obs = adapter.parse_event(event)
    assert obs.source == "wazuh"
    assert obs.event_type == "authentication_failure"
    assert obs.user == "alice"
    assert obs.host == "linux-01"
    assert obs.source_ip == "10.0.0.25"
    assert obs.severity == 4  # level 5 → medium
    assert "authentication" in obs.tags


def test_wazuh_privilege_escalation():
    adapter = WazuhAdapter()
    obs = adapter.parse_event({
        "rule": {
            "id": "5401",
            "level": 7,
            "description": "Successful sudo to ROOT executed",
        },
        "agent": {"name": "linux-01"},
        "data": {"dstuser": "alice", "srcuser": "alice"},
    })
    assert obs.event_type == "privilege_escalation"
    assert "privilege" in obs.tags
    assert obs.severity >= 6


def test_wazuh_severity_mapping():
    adapter = WazuhAdapter()
    for level, expected_min in [(1, 0), (3, 2), (5, 4), (8, 6), (10, 8), (12, 9)]:
        obs = adapter.parse_event({
            "rule": {"level": level, "description": "test event"},
            "agent": {"name": "h1"},
        })
        assert obs.severity >= expected_min


def test_postgres_normal_select():
    adapter = PostgresAuditAdapter()
    obs = adapter.parse_event({
        "timestamp": "2026-08-22T09:15:42Z",
        "user": "bob",
        "database": "enterprise",
        "client_ip": "10.0.1.10",
        "action": "SELECT",
        "table": "employees",
        "rows": 50,
    })
    assert obs.source == "postgresql"
    assert obs.event_type == "database_query"
    assert obs.user == "bob"
    assert "database" in obs.tags
    assert obs.severity < 5  # employees is sensitive-ish but small


def test_postgres_large_payroll():
    adapter = PostgresAuditAdapter()
    obs = adapter.parse_event({
        "timestamp": "2026-08-22T09:15:42Z",
        "user": "alice",
        "database": "enterprise",
        "client_ip": "10.0.0.25",
        "action": "SELECT",
        "table": "payroll",
        "rows": 30000,
    })
    assert obs.event_type == "database_export"
    assert obs.severity >= 7
    assert "sensitive_data" in obs.tags
    assert "export" in obs.tags
    assert obs.metadata.get("rows") == 30000
    assert obs.metadata.get("table") == "payroll"


def test_postgres_missing_fields():
    adapter = PostgresAuditAdapter()
    obs = adapter.parse_event({"action": "SELECT"})
    assert obs.source == "postgresql"
    assert obs.event_type == "database_query"
    assert obs.user is None


def test_adapters_never_leak_source_structure():
    """Ensure Observation only contains normalised fields."""
    kc = KeycloakAdapter().parse_event({"type": "LOGIN", "userId": "u"})
    wz = WazuhAdapter().parse_event({"rule": {"description": "test"}, "agent": {}})
    pg = PostgresAuditAdapter().parse_event({"action": "SELECT"})
    for obs in (kc, wz, pg):
        d = obs.to_dict()
        assert "rule" not in d
        assert "agent" not in d
        assert "type" not in d or d.get("source") in ("keycloak", "wazuh", "postgresql")
        assert "event_type" in d
        assert "source" in d

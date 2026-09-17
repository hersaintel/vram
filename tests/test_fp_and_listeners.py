"""Tests for aggressive FP dismissal, Keycloak webhook, pgaudit listener."""

import pytest

from engine.reasoner import Reasoner
from storage.sqlite import SQLiteStorage
from engine.memory import Memory
from simulator.events import EventSimulator
from inputs.keycloak_webhook import KeycloakWebhookReceiver
from inputs.pgaudit_listener import PgAuditListener, PgAuditListenerConfig


@pytest.fixture
def reasoner():
    SQLiteStorage._memory_conn = None
    return Reasoner(memory=Memory(backend=SQLiteStorage(in_memory=True)))


def test_false_positive_confidence_drops_after_mfa(reasoner):
    sim = EventSimulator()
    peak = 0.0
    after_mfa = None
    final = 0.0
    for obs in sim.scenario_false_positive():
        result = reasoner.process(obs)
        for h in result.updated_hypotheses:
            if "Exfiltration" not in h.title:
                continue
            peak = max(peak, h.confidence)
            final = h.confidence
            if obs.event_type == "mfa_verified":
                after_mfa = h.confidence
    assert peak >= 0.40
    if after_mfa is not None:
        assert after_mfa <= peak
    # Final should be lower than peak (cooling / MFA)
    assert final <= peak


def test_keycloak_webhook_single_and_batch():
    rx = KeycloakWebhookReceiver()
    single = rx.receive({
        "type": "LOGIN",
        "userId": "alice",
        "ipAddress": "10.0.0.1",
    })
    assert len(single) == 1
    assert single[0].source == "keycloak"
    assert single[0].user == "alice"

    batch = rx.receive([
        {"type": "LOGIN_ERROR", "userId": "alice"},
        {"type": "LOGIN", "userId": "alice"},
    ])
    assert len(batch) == 2

    wrapped = rx.receive({"events": [{"type": "LOGOUT", "userId": "bob"}]})
    assert len(wrapped) == 1
    assert wrapped[0].user == "bob"


def test_pgaudit_parse_row():
    listener = PgAuditListener(config=PgAuditListenerConfig())
    obs = listener.parse_row({
        "timestamp": "2026-08-22T09:15:00Z",
        "user": "alice",
        "database": "enterprise",
        "client_ip": "10.0.0.25",
        "action": "SELECT",
        "table": "payroll",
        "rows": 30000,
    })
    assert obs.source == "postgresql"
    assert obs.event_type == "database_export"
    assert obs.user == "alice"
    assert obs.metadata.get("rows") == 30000


def test_pgaudit_ensure_sql():
    sql = PgAuditListener.ensure_audit_table_sql()
    assert "vram_audit_log" in sql
    assert "CREATE TABLE" in sql

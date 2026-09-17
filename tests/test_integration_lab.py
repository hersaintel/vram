"""Integration tests for the multi-source telemetry lab."""

import pytest

from engine.reasoner import Reasoner
from storage.sqlite import SQLiteStorage
from engine.memory import Memory
from simulator.events import EventSimulator
from inputs.keycloak import KeycloakAdapter
from inputs.wazuh import WazuhAdapter
from inputs.postgres import PostgresAuditAdapter


@pytest.fixture
def reasoner():
    SQLiteStorage._memory_conn = None
    return Reasoner(memory=Memory(backend=SQLiteStorage(in_memory=True)))


def test_exfiltration_confidence_threshold(reasoner):
    sim = EventSimulator()
    final_conf = 0.0
    for obs in sim.scenario_exfiltration():
        result = reasoner.process(obs)
        for h in result.updated_hypotheses:
            if "Exfiltration" in h.title:
                final_conf = h.confidence
    assert final_conf >= 0.80


def test_normal_scenario_no_critical(reasoner):
    sim = EventSimulator()
    for obs in sim.scenario_normal():
        reasoner.process(obs)
    active = reasoner.hypotheses.list_active()
    for h in active:
        assert h.confidence < 0.70, f"{h.title} should not be high on normal activity"


def test_user_identity_correlation(reasoner):
    sim = EventSimulator()
    for obs in sim.scenario_exfiltration():
        reasoner.process(obs)
    # All related users should resolve to alice
    for h in reasoner.hypotheses.list_all():
        if h.related_users:
            assert "alice" in h.related_users


def test_timeline_ordering(reasoner):
    sim = EventSimulator()
    for obs in sim.scenario_exfiltration():
        reasoner.process(obs)
    active = [h for h in reasoner.hypotheses.list_active() if "Exfiltration" in h.title]
    assert active
    h = active[0]
    events = reasoner.memory.get_by_user("alice")
    ordered = sorted(events, key=lambda o: o.timestamp)
    assert ordered[0].timestamp <= ordered[-1].timestamp
    assert ordered[0].source == "keycloak"


def test_adapters_roundtrip_sources():
    kc = KeycloakAdapter()
    wz = WazuhAdapter()
    pg = PostgresAuditAdapter()
    assert kc.parse_event({"type": "LOGIN", "userId": "u"}).source == "keycloak"
    assert wz.parse_event({"rule": {"description": "test"}, "agent": {}}).source == "wazuh"
    assert pg.parse_event({"action": "SELECT"}).source == "postgresql"

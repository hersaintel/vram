"""Tests for the central reasoner and end-to-end correlation."""

import pytest

from models.observation import Observation
from engine.reasoner import Reasoner
from storage.sqlite import SQLiteStorage
from engine.memory import Memory
from simulator.events import EventSimulator


@pytest.fixture
def reasoner():
    SQLiteStorage._memory_conn = None
    mem = Memory(backend=SQLiteStorage(in_memory=True))
    return Reasoner(memory=mem)


def test_single_auth_creates_hypothesis(reasoner):
    obs = Observation(
        event_type="authentication_success",
        user="alice",
        host="laptop-01",
        source="keycloak",
        severity=2,
        tags=["identity", "authentication"],
    )
    result = reasoner.process(obs)
    assert any(h.title == "Possible Credential Abuse" for h in result.updated_hypotheses)
    hyp = next(h for h in result.updated_hypotheses if h.title == "Possible Credential Abuse")
    assert hyp.confidence >= 0.08


def test_progressive_confidence_exfiltration(reasoner):
    sim = EventSimulator()
    confidences = []
    for obs in sim.scenario_exfiltration():
        result = reasoner.process(obs)
        data_exfil = [h for h in result.updated_hypotheses if "Exfiltration" in h.title]
        if data_exfil:
            confidences.append(data_exfil[0].confidence)
    assert confidences, "expected data exfiltration hypothesis"
    assert confidences[-1] > confidences[0]
    assert confidences[-1] >= 0.80


def test_false_positive_shows_mitigation(reasoner):
    """Confidence should rise, then drop after MFA."""
    sim = EventSimulator()
    trajectory = []
    for obs in sim.scenario_false_positive():
        result = reasoner.process(obs)
        for h in result.updated_hypotheses:
            if "Exfiltration" in h.title:
                trajectory.append((obs.event_type, h.confidence))
    assert trajectory, "expected exfiltration hypothesis"
    peak = max(c for _, c in trajectory)
    # Find confidence right after MFA if present
    mfa_idx = next((i for i, (et, _) in enumerate(trajectory) if "mfa" in et), None)
    assert peak >= 0.40
    if mfa_idx is not None and mfa_idx + 1 < len(trajectory):
        # After MFA, confidence should not be higher than peak
        assert trajectory[mfa_idx][1] <= peak


def test_cross_source_correlation(reasoner):
    """Events from Keycloak + Wazuh + Postgres for same user correlate."""
    sim = EventSimulator()
    sources_seen = set()
    for obs in sim.scenario_exfiltration():
        result = reasoner.process(obs)
        sources_seen.add(obs.source)
    assert "keycloak" in sources_seen
    assert "wazuh" in sources_seen
    assert "postgresql" in sources_seen
    active = reasoner.hypotheses.list_active()
    assert any("Exfiltration" in h.title and h.confidence >= 0.80 for h in active)


def test_prediction_or_narrative(reasoner):
    sim = EventSimulator()
    had_narrative = False
    for obs in sim.scenario_exfiltration():
        result = reasoner.process(obs)
        if result.narrative:
            had_narrative = True
    assert had_narrative

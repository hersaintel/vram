"""Tests for hypothesis engine."""

from engine.hypotheses import HypothesisEngine


def test_create_and_get():
    eng = HypothesisEngine()
    h = eng.create(title="Possible Credential Abuse", confidence=0.2)
    assert h.id
    assert eng.get(h.id) is h
    assert eng.get_by_title("Possible Credential Abuse") is h


def test_update_confidence():
    eng = HypothesisEngine()
    h = eng.create(title="Test", confidence=0.1)
    updated = eng.update_confidence(h.id, 0.6, {"reason": "evidence"})
    assert updated is not None
    assert updated.confidence == 0.6
    assert updated.status == "active"
    assert len(updated.evidence) == 1


def test_status_transitions():
    eng = HypothesisEngine()
    h = eng.create(title="T", confidence=0.1)
    eng.update_confidence(h.id, 0.9)
    assert eng.get(h.id).status == "confirmed"
    eng.update_confidence(h.id, 0.20)
    assert eng.get(h.id).status == "weakening"
    eng.update_confidence(h.id, 0.05)
    assert eng.get(h.id).status == "dismissed"


def test_list_active():
    eng = HypothesisEngine()
    eng.create(title="A", confidence=0.5)
    eng.create(title="B", confidence=0.2)
    eng.dismiss(eng.get_by_title("B").id)
    active = eng.list_active()
    assert len(active) == 1
    assert active[0].title == "A"

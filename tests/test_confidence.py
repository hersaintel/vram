"""Tests for confidence engine."""

import pytest

from engine.confidence import ConfidenceEngine


def test_clamp():
    eng = ConfidenceEngine()
    assert eng.clamp(-0.5) == 0.0
    assert eng.clamp(1.5) == 1.0
    assert eng.clamp(0.42) == 0.42


def test_increase():
    eng = ConfidenceEngine()
    result = eng.increase(0.2, 0.15, reason="test")
    assert result.new_confidence == pytest.approx(0.35)
    assert result.delta == pytest.approx(0.15)
    assert result.reason == "test"


def test_decrease():
    eng = ConfidenceEngine()
    result = eng.decrease(0.5, 0.2, reason="mitigation")
    assert result.new_confidence == pytest.approx(0.3)
    assert result.delta == pytest.approx(-0.2)


def test_bounds():
    eng = ConfidenceEngine()
    result = eng.increase(0.95, 0.2)
    assert result.new_confidence == 1.0
    result = eng.decrease(0.05, 0.2)
    assert result.new_confidence == 0.0

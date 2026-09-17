"""Tests for memory / SQLite storage."""

from datetime import datetime, timezone, timedelta

import pytest

from models.observation import Observation
from storage.sqlite import SQLiteStorage
from engine.memory import Memory


@pytest.fixture
def storage():
    # Fresh in-memory DB for each test
    SQLiteStorage._memory_conn = None
    return SQLiteStorage(in_memory=True)


@pytest.fixture
def memory(storage):
    return Memory(backend=storage)


def _obs(**kwargs) -> Observation:
    defaults = {
        "source": "test",
        "event_type": "login",
        "user": "alice",
        "host": "host-1",
        "severity": 1,
    }
    defaults.update(kwargs)
    return Observation(**defaults)


def test_add_and_get_by_id(memory):
    o = _obs()
    memory.add(o)
    got = memory.get_by_id(o.id)
    assert got is not None
    assert got.id == o.id
    assert got.user == "alice"


def test_get_recent(memory):
    for i in range(5):
        memory.add(_obs(event_type=f"evt_{i}"))
    recent = memory.get_recent(limit=3)
    assert len(recent) == 3


def test_get_by_user(memory):
    memory.add(_obs(user="alice"))
    memory.add(_obs(user="bob", event_type="logout"))
    results = memory.get_by_user("alice")
    assert len(results) == 1
    assert results[0].user == "alice"


def test_get_by_host(memory):
    memory.add(_obs(host="host-1"))
    memory.add(_obs(host="host-2", user="bob"))
    results = memory.get_by_host("host-1")
    assert len(results) == 1


def test_get_by_event_type(memory):
    memory.add(_obs(event_type="vpn_login"))
    memory.add(_obs(event_type="logout"))
    results = memory.get_by_event_type("vpn_login")
    assert len(results) == 1


def test_get_related(memory):
    o1 = _obs(user="alice", host="h1")
    memory.add(o1)
    o2 = _obs(user="alice", host="h2", event_type="file_access")
    memory.add(o2)
    related = memory.get_related(o1)
    assert any(r.id == o2.id for r in related)

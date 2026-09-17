"""Memory subsystem — historical observation store."""

from __future__ import annotations

from typing import Protocol

from models.observation import Observation


class MemoryBackend(Protocol):
    """Interface that any memory backend must implement.

    Designed so a graph backend can be swapped in later without
    changing the rest of the engine.
    """

    def add(self, observation: Observation) -> None: ...
    def get_by_id(self, obs_id: str) -> Observation | None: ...
    def get_recent(self, limit: int = 50) -> list[Observation]: ...
    def get_by_user(self, user: str, limit: int = 50) -> list[Observation]: ...
    def get_by_host(self, host: str, limit: int = 50) -> list[Observation]: ...
    def get_by_event_type(self, event_type: str, limit: int = 50) -> list[Observation]: ...
    def get_in_time_window(self, start, end) -> list[Observation]: ...
    def get_related(self, observation: Observation, limit: int = 20) -> list[Observation]: ...


class Memory:
    """High-level memory facade. V1 uses SQLite."""

    def __init__(self, backend: MemoryBackend | None = None) -> None:
        if backend is None:
            from storage.sqlite import SQLiteStorage
            backend = SQLiteStorage()
        self._backend = backend

    def add(self, observation: Observation) -> None:
        self._backend.add(observation)

    def get_by_id(self, obs_id: str) -> Observation | None:
        return self._backend.get_by_id(obs_id)

    def get_recent(self, limit: int = 50) -> list[Observation]:
        return self._backend.get_recent(limit)

    def get_by_user(self, user: str, limit: int = 50) -> list[Observation]:
        return self._backend.get_by_user(user, limit)

    def get_by_host(self, host: str, limit: int = 50) -> list[Observation]:
        return self._backend.get_by_host(host, limit)

    def get_by_event_type(self, event_type: str, limit: int = 50) -> list[Observation]:
        return self._backend.get_by_event_type(event_type, limit)

    def get_in_time_window(self, start, end) -> list[Observation]:
        return self._backend.get_in_time_window(start, end)

    def get_related(self, observation: Observation, limit: int = 20) -> list[Observation]:
        return self._backend.get_related(observation, limit)

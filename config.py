"""VRAM configuration.

All settings are environment-driven where possible.
Never hardcode passwords or tokens.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _env_int(key: str, default: int) -> int:
    raw = os.environ.get(key)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(key: str, default: float) -> float:
    raw = os.environ.get(key)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


# Base paths
BASE_DIR: Final[Path] = Path(__file__).resolve().parent
DATA_DIR: Final[Path] = BASE_DIR / "data"
DB_PATH: Final[Path] = DATA_DIR / "vram.db"

DATA_DIR.mkdir(exist_ok=True)

# Confidence bounds
CONFIDENCE_MIN: Final[float] = 0.0
CONFIDENCE_MAX: Final[float] = 1.0

# Memory
DEFAULT_RECENT_LIMIT: Final[int] = 50
DEFAULT_TIME_WINDOW_MINUTES: Final[int] = 60

# Context windows (minutes) — configurable
AUTHENTICATION_CONTEXT: Final[int] = _env_int("VRAM_AUTH_CONTEXT_MINUTES", 30)
PRIVILEGE_CONTEXT: Final[int] = _env_int("VRAM_PRIVILEGE_CONTEXT_MINUTES", 30)
DATABASE_CONTEXT: Final[int] = _env_int("VRAM_DATABASE_CONTEXT_MINUTES", 20)
EXFILTRATION_CONTEXT: Final[int] = _env_int("VRAM_EXFIL_CONTEXT_MINUTES", 60)

# Logging
LOG_LEVEL: Final[str] = _env("VRAM_LOG_LEVEL", "INFO")

# External services (lab only — never hardcode secrets)
KEYCLOAK_URL: Final[str] = _env("KEYCLOAK_URL", "http://localhost:8080")
KEYCLOAK_REALM: Final[str] = _env("KEYCLOAK_REALM", "vram-lab")
POSTGRES_HOST: Final[str] = _env("POSTGRES_HOST", "localhost")
POSTGRES_PORT: Final[int] = _env_int("POSTGRES_PORT", 5432)
POSTGRES_DB: Final[str] = _env("POSTGRES_DB", "enterprise")
POSTGRES_USER: Final[str] = _env("POSTGRES_USER", "vram")
POSTGRES_PASSWORD: Final[str] = _env("POSTGRES_PASSWORD", "")
WAZUH_URL: Final[str] = _env("WAZUH_URL", "http://localhost:55000")
VRAM_DATABASE_URL: Final[str] = _env("VRAM_DATABASE_URL", "")
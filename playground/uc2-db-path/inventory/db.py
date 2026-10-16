from __future__ import annotations

import sqlite3
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def settings() -> dict:
    with open(ROOT / "config" / "settings.toml", "rb") as handle:
        return tomllib.load(handle)


def connect() -> sqlite3.Connection:
    config = settings()["database"]
    connection = sqlite3.connect(config["path"], timeout=config["busy_timeout_ms"] / 1000)
    connection.row_factory = sqlite3.Row
    return connection


def applied_migrations(connection: sqlite3.Connection) -> list[str]:
    return [row["version"] for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")]

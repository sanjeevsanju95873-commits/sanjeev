"""
database.py - SQLite data layer for the AV7SCM Mini-SIEM (Login Alert Assistant).

Every helper opens its own short-lived connection inside a context manager, so each
call is an isolated transaction: it commits on success and rolls back on any error.
All SQL uses parameterized queries (never string formatting) to prevent injection.
"""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from typing import Iterator, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mini_siem.db")

_SCHEMA_EVENTS = """
CREATE TABLE IF NOT EXISTS security_events (
    event_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL,
    source_ip    TEXT NOT NULL,
    event_status TEXT NOT NULL,
    username     TEXT NOT NULL
)
"""

_SCHEMA_ALERTS = """
CREATE TABLE IF NOT EXISTS security_alerts (
    alert_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    severity            TEXT NOT NULL,
    source_ip           TEXT NOT NULL,
    failed_attempts     INTEGER NOT NULL,
    trigger_time        TEXT NOT NULL,
    remediation_message TEXT NOT NULL
)
"""


@contextmanager
def _transaction() -> Iterator[sqlite3.Connection]:
    """Open an isolated connection; commit on success, roll back on failure."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Create mini_siem.db and both tables if they do not already exist."""
    with _transaction() as conn:
        conn.execute(_SCHEMA_EVENTS)
        conn.execute(_SCHEMA_ALERTS)


def insert_event(timestamp: str, source_ip: str, status: str, username: str) -> int:
    """Insert one authentication event. Returns the new event_id."""
    with _transaction() as conn:
        cursor = conn.execute(
            "INSERT INTO security_events (timestamp, source_ip, event_status, username) "
            "VALUES (?, ?, ?, ?)",
            (timestamp, source_ip, status, username),
        )
        return int(cursor.lastrowid)


def insert_events_bulk(rows: list[tuple[str, str, str, str]]) -> int:
    """
    Insert many events atomically in a single transaction.
    Each row is (timestamp, source_ip, status, username). Returns rows inserted.
    """
    if not rows:
        return 0
    with _transaction() as conn:
        conn.executemany(
            "INSERT INTO security_events (timestamp, source_ip, event_status, username) "
            "VALUES (?, ?, ?, ?)",
            rows,
        )
    return len(rows)


def insert_alert(
    severity: str, source_ip: str, count: int, trigger_time: str, message: str
) -> int:
    """Insert one security alert. Returns the new alert_id."""
    with _transaction() as conn:
        cursor = conn.execute(
            "INSERT INTO security_alerts "
            "(severity, source_ip, failed_attempts, trigger_time, remediation_message) "
            "VALUES (?, ?, ?, ?, ?)",
            (severity, source_ip, int(count), trigger_time, message),
        )
        return int(cursor.lastrowid)


def fetch_alerts() -> list[dict]:
    """Return all alerts, newest first, as a list of dictionaries."""
    with _transaction() as conn:
        rows = conn.execute(
            "SELECT alert_id, severity, source_ip, failed_attempts, trigger_time, "
            "remediation_message FROM security_alerts ORDER BY alert_id DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def fetch_alert_by_id(alert_id: int) -> Optional[dict]:
    """Return a single alert by ID, or None if it does not exist."""
    with _transaction() as conn:
        row = conn.execute(
            "SELECT alert_id, severity, source_ip, failed_attempts, trigger_time, "
            "remediation_message FROM security_alerts WHERE alert_id = ?",
            (int(alert_id),),
        ).fetchone()
    return dict(row) if row else None


def fetch_event_count() -> int:
    """Return the total number of audited log events."""
    with _transaction() as conn:
        row = conn.execute("SELECT COUNT(*) AS total FROM security_events").fetchone()
    return int(row["total"])


def fetch_alert_count(severity: Optional[str] = None) -> int:
    """Return the number of alerts, optionally filtered by severity."""
    with _transaction() as conn:
        if severity is None:
            row = conn.execute("SELECT COUNT(*) AS total FROM security_alerts").fetchone()
        else:
            row = conn.execute(
                "SELECT COUNT(*) AS total FROM security_alerts WHERE severity = ?",
                (severity,),
            ).fetchone()
    return int(row["total"])


def fetch_failed_usernames(source_ip: str) -> list[str]:
    """Return distinct usernames that had failed logins from the given IP."""
    with _transaction() as conn:
        rows = conn.execute(
            "SELECT DISTINCT username FROM security_events "
            "WHERE source_ip = ? AND event_status = 'failed' ORDER BY username",
            (source_ip,),
        ).fetchall()
    return [row["username"] for row in rows]


def count_successes_from_ip(source_ip: str) -> int:
    """Return how many successful logins were recorded from the given IP."""
    with _transaction() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS total FROM security_events "
            "WHERE source_ip = ? AND event_status = 'success'",
            (source_ip,),
        ).fetchone()
    return int(row["total"])

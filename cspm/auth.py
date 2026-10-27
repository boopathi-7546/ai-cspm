"""User authentication, password hashing, and rate limiting for AI-CSPM."""
from __future__ import annotations

import logging
import os
import sqlite3
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import NamedTuple

from werkzeug.security import check_password_hash, generate_password_hash

logger = logging.getLogger(__name__)

AUTH_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'analyst',
  created_at TEXT NOT NULL
);
"""

DEFAULT_ADMIN_USER = os.getenv("CSPM_ADMIN_USER", "admin")
DEFAULT_ADMIN_PASSWORD = os.getenv("CSPM_ADMIN_PASSWORD", "admin123")


class RateLimiter:
    """In-memory sliding window rate limiter for login and sensitive actions."""

    def __init__(self, max_attempts: int = 5, window_seconds: int = 60):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._history: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        self._history[key] = [t for t in self._history[key] if t > cutoff]
        return len(self._history[key]) < self.max_attempts

    def record_attempt(self, key: str) -> None:
        self._history[key].append(time.time())

    def reset(self, key: str) -> None:
        self._history.pop(key, None)


login_rate_limiter = RateLimiter(max_attempts=5, window_seconds=60)


def init_auth_db(conn: sqlite3.Connection) -> None:
    """Ensure users table exists and seed/sync administrator user."""
    conn.executescript(AUTH_SCHEMA)
    admin_user = (os.getenv("CSPM_ADMIN_USER") or DEFAULT_ADMIN_USER).strip().lower()
    admin_pass = os.getenv("CSPM_ADMIN_PASSWORD") or DEFAULT_ADMIN_PASSWORD

    row = conn.execute("SELECT username, password_hash FROM users WHERE username = ?", (admin_user,)).fetchone()
    if row is None:
        create_user(
            conn,
            username=admin_user,
            password=admin_pass,
            role="admin",
        )
        logger.info("Initialized default administrator user: %s", admin_user)
    else:
        # If admin user already exists, update password hash if CSPM_ADMIN_PASSWORD was configured
        if os.getenv("CSPM_ADMIN_PASSWORD") and not check_password_hash(row["password_hash"], admin_pass):
            new_hash = generate_password_hash(admin_pass, method="scrypt")
            conn.execute(
                "UPDATE users SET password_hash = ?, role = 'admin' WHERE username = ?",
                (new_hash, admin_user),
            )
            conn.commit()
            logger.info("Synchronized administrator credentials for %s", admin_user)


def create_user(
    conn: sqlite3.Connection, username: str, password: str, role: str = "analyst"
) -> bool:
    """Create a new user with securely hashed password."""
    username = (username or "").strip().lower()
    if not username or len(username) < 3 or not password or len(password) < 6:
        raise ValueError("Username must be >= 3 chars and password >= 6 chars")
    if role not in ("admin", "analyst", "viewer"):
        role = "analyst"

    p_hash = generate_password_hash(password, method="scrypt")
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, p_hash, role, now_iso),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def verify_user(
    conn: sqlite3.Connection, username: str, password: str
) -> dict | None:
    """Verify username and password against database."""
    username = (username or "").strip().lower()
    if not username or not password:
        return None
    row = conn.execute(
        "SELECT username, password_hash, role, created_at FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if row is None:
        return None
    if check_password_hash(row["password_hash"], password):
        return {
            "username": row["username"],
            "role": row["role"],
            "created_at": row["created_at"],
        }
    return None


def get_user(conn: sqlite3.Connection, username: str) -> dict | None:
    """Retrieve user metadata without password hash."""
    username = (username or "").strip().lower()
    row = conn.execute(
        "SELECT username, role, created_at FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if row is None:
        return None
    return dict(row)

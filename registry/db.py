# Copyright 2025 Christ10-8 — Apache-2.0
"""SQLite storage. Simple a proposito: un archivo, cero ORM, deployable en cualquier lado."""
from __future__ import annotations
import os, sqlite3, threading

_LOCK = threading.Lock()          # serializa appends (lesson: race en registry append)
_conn: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS seals(
  seal_id TEXT PRIMARY KEY, n INTEGER UNIQUE NOT NULL, ts TEXT NOT NULL,
  entries_root TEXT NOT NULL, payload_json TEXT NOT NULL, issuer_sig TEXT NOT NULL,
  prev_hash TEXT NOT NULL, chain_hash TEXT NOT NULL, tsa_token_b64 TEXT,
  api_key_id INTEGER);
CREATE TABLE IF NOT EXISTS api_keys(
  id INTEGER PRIMARY KEY AUTOINCREMENT, key_hash TEXT UNIQUE NOT NULL,
  tier TEXT NOT NULL DEFAULT 'free', month TEXT NOT NULL DEFAULT '',
  used INTEGER NOT NULL DEFAULT 0, label TEXT, created TEXT NOT NULL,
  license_hash TEXT, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_seals_root ON seals(entries_root);
"""

def connect(path: str | None = None) -> sqlite3.Connection:
    global _conn
    if _conn is None:
        p = path or os.environ.get("REGISTRY_DB", "registry.db")
        _conn = sqlite3.connect(p, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.executescript(SCHEMA)
        _migrate(_conn)
        _conn.commit()
    return _conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns introduced after the first deploy. Safe to run on every start."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(api_keys)")}
    if "license_hash" not in cols:
        conn.execute("ALTER TABLE api_keys ADD COLUMN license_hash TEXT")
    if "revoked" not in cols:
        conn.execute("ALTER TABLE api_keys ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0")
    # Index goes here, not in SCHEMA: on an existing database the column only
    # exists after the ALTER above has run.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_keys_license ON api_keys(license_hash)")

def reset_for_tests(path: str) -> None:
    global _conn
    if _conn is not None:
        _conn.close()
    _conn = None
    if os.path.exists(path):
        os.remove(path)
    os.environ["REGISTRY_DB"] = path
    connect(path)

def lock() -> threading.Lock:
    return _LOCK

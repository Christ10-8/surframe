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
  used INTEGER NOT NULL DEFAULT 0, label TEXT, created TEXT NOT NULL);
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
        _conn.commit()
    return _conn

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

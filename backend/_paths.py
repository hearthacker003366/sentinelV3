"""
Sentinel Path Utility
======================
Single source of truth for filesystem locations for the Sentinel V3 SOC.
Every module in Sentinel V3 resolves its paths through this file to ensure
portability across different environments (Windows, Kali Linux, etc.).
"""

import os

def _compute_home() -> str:
    # This file lives at  <home>/backend/_paths.py
    return os.path.normpath(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SENTINEL_HOME = _compute_home()
BASE_DIR = SENTINEL_HOME

def ensure_home_guard() -> str:
    """Validate that SENTINEL_HOME is a valid project root containing required modules (§2.10)."""
    if not os.path.isdir(SENTINEL_HOME):
        raise RuntimeError(f"Invalid SENTINEL_HOME: directory does not exist ({SENTINEL_HOME})")
    if not os.path.isdir(os.path.join(SENTINEL_HOME, "backend")):
        raise RuntimeError(f"Corrupt Sentinel directory: 'backend' not found in {SENTINEL_HOME}")
    return SENTINEL_HOME

# ---------------------------------------------------------------------------
# Canonical location helpers — the ONLY way any module should find files.
# ---------------------------------------------------------------------------
def backend_dir() -> str:
    return os.path.join(SENTINEL_HOME, "backend")

def db_path() -> str:
    return os.path.join(backend_dir(), "sentinel.db")

def rules_dir() -> str:
    return os.path.join(backend_dir(), "detection", "rules")

def demo_auth_log() -> str:
    return os.path.join(backend_dir(), "demo_auth.log")

def memory_ledger_path() -> str:
    return os.path.join(backend_dir(), "reasoning", "memory_ledger.json")

def mcp_server_entry() -> str:
    return os.path.join(SENTINEL_HOME, "mcp_server", "server.py")

def cli_entry() -> str:
    return os.path.join(SENTINEL_HOME, "sentinel_cli.py")

def get_db_connection(path: str | None = None):
    """Return a hardened SQLite connection with WAL journal mode and busy timeout (§2.14)."""
    import sqlite3
    p = path or db_path()
    conn = sqlite3.connect(p, timeout=10.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
    except sqlite3.Error:
        pass
    return conn

if __name__ == "__main__":
    print(f"SENTINEL_HOME = {ensure_home_guard()}")

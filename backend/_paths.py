"""
Sentinel Path Seatbelt
======================
Single source of truth for filesystem locations, with a HARD GUARD that
refuses to operate inside protected locations.

Why this exists:
  The V1/V2 clone scripts hardcoded absolute paths to the ORIGINAL project
  folder (02_AI_Development\\Sentinel_BlueTeam). That folder is FROZEN.
  Every module in Sentinel V3 resolves its paths through this file instead.

Guard policy:
  * HARD REFUSE (RuntimeError): any home containing "02_ai_development".
  * WARN (stderr) when running outside the designated workspace folder
    ("glm freebuff" copy). Override with SENTINEL_ALLOW_ANY_HOME=1 for
    porting to the Kali VM / other hosts.
"""

import os
import sys

# Lowercased fragments that must NEVER contain a live Sentinel instance.
PROTECTED_FRAGMENTS = ("02_ai_development",)

# The designated working copy marker (lowercase substring compare).
DESIGNATED_MARKER = "glm freebuff"


def _compute_home() -> str:
    # This file lives at  <home>/backend/_paths.py
    return os.path.normpath(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


SENTINEL_HOME = _compute_home()


def ensure_home_guard() -> str:
    """Validate the resolved home. Call once at process start."""
    home_lower = SENTINEL_HOME.lower()

    for frag in PROTECTED_FRAGMENTS:
        if frag in home_lower:
            raise RuntimeError(
                "[SENTINEL GUARD] Refusing to operate inside a protected location: "
                f"{SENTINEL_HOME!r}. The original 02_AI_Development project is FROZEN. "
                "Move this code to the designated workspace copy instead."
            )

    if DESIGNATED_MARKER not in home_lower and os.environ.get("SENTINEL_ALLOW_ANY_HOME") != "1":
        sys.stderr.write(
            "[SentinelGuard] WARNING: operating outside the designated workspace "
            f"(expected a 'glm freebuff' path, got: {SENTINEL_HOME}). "
            "Set SENTINEL_ALLOW_ANY_HOME=1 to silence this when porting to the Kali VM.\n"
        )

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


# Drop-in compatibility constant for legacy scripts
BASE_DIR = SENTINEL_HOME

if __name__ == "__main__":
    print(f"SENTINEL_HOME = {ensure_home_guard()}")

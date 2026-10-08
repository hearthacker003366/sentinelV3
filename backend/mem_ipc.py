"""File-based IPC bridge between the MCP engine and the dashboard.

Both processes open the SAME backend/sentinel.db but each keeps its OWN
in-memory state. Without this bridge the dashboard shows a stale, divergent
incident view (RL +0.0, zero alerts, honeypot OFFLINE) while the MCP engine
that actually ran the kill chain holds the real values.

The MCP engine (mcp_server/server.py) is the WRITER: every call_tool() writes
a snapshot of its authoritative in-memory state here. The dashboard
(dashboard/server.py) is the READER and prefers this snapshot over its own
engine's memory.

Snapshot keys
-------------
last_alerts       list  Sigma alerts fired this episode
last_predictions  list  GraphSAGE predictions (most recent run)
stage_history     list  APT stages executed, in order
graph_elements    list  Cytoscape elements from the WRITER's graph
graph_summary     dict  node/edge/compromised counts from the WRITER
pending_tokens    list  Tier-2 HITL tokens awaiting human approval

Every write is atomic (tmp file + os.replace) so a reader can never observe a
half-serialised JSON document. Writes are best-effort: a failure here must
never break the tool call that triggered it.
"""

import json
import os
import tempfile
import time

from backend import _paths

MEM_STATE_FILENAME = "mem_state.json"
# Snapshot older than this is treated as stale by the reader.
DEFAULT_MAX_AGE_S = 3600.0
# A snapshot whose writer process has exited is treated as last-known-good and
# given this multiple of the normal max age before it is finally discarded.
FROZEN_MAX_AGE_FACTOR = 24


def writer_alive(pid) -> bool:
    """True when the process that wrote the snapshot is still running."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)          # signal 0 = existence check, no side effect
    except ProcessLookupError:
        return False
    except PermissionError:
        return True               # exists, owned by another user
    except OSError:
        return False
    return True


def mem_state_path() -> str:
    # _paths exposes backend_dir() as a FUNCTION; there is no BACKEND_DIR
    # constant. The original mem_ipc.py referenced the constant form, so every
    # read/write raised AttributeError and was swallowed -- the bridge silently
    # never worked. Resolve through the function, with a project-relative
    # fallback so the bridge still works if _paths ever changes shape.
    try:
        base = _paths.backend_dir()
    except Exception:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/backend"
    return os.path.join(base, MEM_STATE_FILENAME)


def _empty_state() -> dict:
    return {
        "last_alerts": [],
        "last_predictions": [],
        "stage_history": [],
        "graph_elements": [],
        "graph_summary": {},
        "pending_tokens": [],
        "updated_at": 0.0,
        "writer_pid": None,
    }


def write_mem_state(engine, extra: dict = None) -> dict:
    """Serialise the writer engine's authoritative state. Never raises."""
    state = _empty_state()
    try:
        state["last_alerts"] = list(getattr(engine, "last_alerts", []) or [])
        state["last_predictions"] = list(getattr(engine, "last_predictions", []) or [])
        state["stage_history"] = list(getattr(engine, "stage_history", []) or [])

        # Graph lives on the writer; serialise it through the same helper the
        # get_threat_graph tool uses so the shapes match exactly.
        try:
            elements = engine.graph.get_cytoscape_elements()
            state["graph_elements"] = elements
            state["graph_summary"] = {
                "nodes": len([e for e in elements if "source" not in e["data"]]),
                "edges": len([e for e in elements if "source" in e["data"]]),
                "compromised": [
                    e["data"]["id"] for e in elements
                    if e["data"].get("status") in ("COMPROMISED", "ISOLATED")
                ],
            }
        except Exception:
            pass

        # Pending Tier-2 HITL tokens live on the SOAR engine.
        try:
            pend = getattr(engine.soar, "pending_tokens", {}) or {}
            state["pending_tokens"] = [
                dict(v) if isinstance(v, dict) else {"token": str(v), "status": "AWAITING_HUMAN_APPROVAL"}
                for v in pend.values()
            ]
        except Exception:
            pass

        if extra:
            state.update(extra)

        state["updated_at"] = time.time()
        state["writer_pid"] = os.getpid()

        path = mem_state_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # Atomic: write to a temp file in the same dir, then rename over it.
        fd, tmp = tempfile.mkstemp(prefix=".mem_state.", suffix=".tmp", dir=os.path.dirname(path))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(state, f, default=str)
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return state
    except Exception:
        # Best-effort by design: a broken bridge must not fail the tool call.
        return {}


def read_mem_state(max_age_s: float = DEFAULT_MAX_AGE_S) -> dict:
    """Return the writer's snapshot, or an empty state if absent/stale/corrupt."""
    state = _empty_state()
    try:
        with open(mem_state_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return state
    except Exception:
        return state

    age = time.time() - float(data.get("updated_at") or 0)
    for key in state:
        if key in data:
            state[key] = data[key]

    alive = writer_alive(data.get("writer_pid"))
    # A DEAD writer means no fresher state is coming -- it does NOT mean the
    # last snapshot is worthless. Expiring it on age alone would throw away a
    # real incident view and fall back to the reader's own empty engine, which
    # is precisely the two-process bug this bridge exists to fix. So a snapshot
    # from a dead writer is FROZEN: still shown, flagged as last-known, and only
    # expired against a much longer horizon.
    if alive:
        stale = age > max_age_s
    else:
        stale = age > max_age_s * FROZEN_MAX_AGE_FACTOR

    # Meta flags go on the RETURNED state: the copy loop above only carries keys
    # already present in the empty-state template.
    state["_age_s"] = round(age, 1)
    state["_stale"] = stale
    state["_available"] = True
    state["_writer_alive"] = alive
    state["_frozen"] = not alive
    return state
"""
Sentinel V3 SOC Web Dashboard
=============================
Zero-dependency (stdlib-only) HTTP server that serves the SOC dashboard and a
JSON state API backed by a live SentinelUnifiedServer engine instance.

Endpoints:
  GET  /                -> dashboard UI (index.html)
  GET  /api/state       -> full SOC state (graph, threats, RL, honeypot, alerts, predictions)
  POST /api/run_stage   {"stage": 1..5}  -> run one APT stage through the pipeline
  POST /api/reset       -> reset episode state
  POST /api/honeypot    -> deploy the real honeypot

Port 8515 by default (the honeypot owns 8080 now; the old globe map_server is
archived in legacy/). Bind 127.0.0.1 by default; --host 0.0.0.0 for VM access.
"""

import os
import sys
import json
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from backend import _paths  # noqa: E402
_paths.ensure_home_guard()

from mcp_server.server import SentinelUnifiedServer
from backend.mem_ipc import read_mem_state  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
INDEX_PATH = os.path.join(HERE, "index.html")

ENGINE: SentinelUnifiedServer = None  # set in main()


class SOCHandler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str = "application/json"):
        self.send_response(code)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload, code: int = 200):
        self._send(code, json.dumps(payload, default=str).encode("utf-8"))

    # ------------------------------------------------------------------
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            with open(INDEX_PATH, "rb") as f:
                self._send(200, f.read(), ctype="text/html")
        elif self.path == "/api/state":
            self._json(self._state())
        else:
            self._json({"error": "not found"}, code=404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            body = {}

        if self.path == "/api/run_stage":
            result = ENGINE.call_tool("simulate_apt_scenario", {"stage": body.get("stage", 1)})
            self._json(result)
        elif self.path == "/api/reset":
            self._json(ENGINE.call_tool("reset_episode", {}))
        elif self.path == "/api/honeypot":
            self._json(ENGINE.call_tool("deploy_honeypot", {}))
        elif self.path == "/api/approve":
            token = str(body.get("token", ""))
            self._json(ENGINE.call_tool("approve_isolation", {"token": token, "analyst": body.get("analyst", "DASHBOARD_ANALYST")}))
        elif self.path == "/api/ingest_threat":
            # Bridge the Two Universes (D7): Inject terminal threats into the visual graph
            event = {
                "event_type": "NETWORK_CONNECTION",
                "host": "TERMINAL_WATCHER",
                "network": {"dest_ip": body.get("ip", "0.0.0.0"), "dest_port": 22},
                "timestamp": body.get("timestamp", ""),
                "description": body.get("details", "")
            }
            try:
                ENGINE.graph.ingest_normalized_event(event)
                ENGINE.last_alerts.append({
                    "rule_id": "TERMINAL_DETECT", "title": "Terminal Attacker Script Detected",
                    "level": "CRITICAL", "host": "TERMINAL_WATCHER", "timestamp": event["timestamp"]
                })
                self._json({"status": "ingested_to_graph"})
            except Exception as e:
                self._json({"error": str(e)}, code=500)
        else:
            self._json({"error": "unknown action"}, code=404)

    # ------------------------------------------------------------------
    def _state(self) -> dict:
        # mem_ipc bridge (Fix 2): the MCP engine is the WRITER and holds the
        # authoritative state for the incident it actually ran. This dashboard
        # runs its own engine instance, so its memory is a second, divergent
        # copy. Prefer the bridge whenever it is present and fresh; fall back to
        # local engine values only when the bridge is unavailable/stale, so the
        # UI still works if the MCP server is down.
        mem = read_mem_state()
        bridge_ok = bool(mem.get("_available")) and not mem.get("_stale")

        graph = ENGINE.call_tool("get_threat_graph", {})
        threats = ENGINE.call_tool("query_threats", {})
        rl = ENGINE.call_tool("get_rl_score", {})
        hp = ENGINE.honeypot.get_status()
        captures = ENGINE.call_tool("get_honeypot_captures", {"limit": 8})
        audit = ENGINE.call_tool("get_audit_trail", {})

        # ---- graph: writer's graph wins ----
        if bridge_ok and mem.get("graph_elements"):
            graph = {"elements": mem["graph_elements"],
                     "summary": mem.get("graph_summary") or graph.get("summary", {})}

        # ---- alerts ----
        alert_source = mem.get("last_alerts", []) if bridge_ok else getattr(ENGINE, "last_alerts", [])
        alerts = [
            {"rule_id": a.get("rule_id"), "title": a.get("title"), "level": a.get("level"),
             "mitre": a.get("mitre_attack", []), "host": a.get("host"),
             "timestamp": a.get("timestamp")}
            for a in alert_source[-14:][::-1]
        ]

        # ---- RL: read durable SQLite, not this process's in-memory score ----
        # get_rl_score() serves self.rl.cumulative_reward loaded at boot, so a
        # score earned by the MCP engine after our boot was invisible here.
        if bridge_ok:
            try:
                import sqlite3
                dbp = _paths.db_path()
                with sqlite3.connect(dbp) as conn:
                    row = conn.execute(
                        "SELECT value FROM rl_state_v3 WHERE key='cumulative'").fetchone()
                if row is not None:
                    cum = float(row[0])
                    rl = dict(rl or {})
                    rl["cumulative_reward"] = cum
                    rl["standing"] = f"{cum:+.1f} PTS"
                    rl["episodes_logged"] = max(int(rl.get("episodes_logged") or 0),
                                                1 if cum else 0)
            except Exception:
                pass

        # ---- pending HITL tokens: writer's SOAR queue ----
        pending = mem.get("pending_tokens", []) if bridge_ok else [
            t for t in (ENGINE.soar.pending_tokens or {}).values()]

        # ---- stage history (Fix 4) ----
        stage_history = mem.get("stage_history", []) if bridge_ok else list(
            getattr(ENGINE, "stage_history", []) or [])
        stages_run = sorted({int(s) for s in stage_history if str(s).isdigit()})
        latest_stage = max(stages_run) if stages_run else 0

        intel = ENGINE.intel.check_ip("185.220.101.49")

        return {
            "mode": "REAL_PIPELINE_ON_SYNTHETIC_DATA",
            "graph": {"elements": graph.get("elements", []), "summary": graph.get("summary", {})},
            "predictions": mem.get("last_predictions", []) if bridge_ok else [],
            "alerts": alerts,
            "threats": threats.get("threats", [])[:10],
            "threats_count": threats.get("count", 0),
            "rl": rl,
            "honeypot": hp,
            "captures": captures.get("captures", []),
            "audit_count": len(audit.get("entries", [])),
            "audit_tail": audit.get("entries", [])[:6],
            "pending_tokens": pending,
            "stage_history": stage_history,
            "stages_run": stages_run,
            "latest_stage": latest_stage,
            "sync": {
                "bridge": "mem_ipc",
                "available": bool(mem.get("_available")),
                "stale": bool(mem.get("_stale")),
                "age_s": mem.get("_age_s"),
                "writer_pid": mem.get("writer_pid"),
                "writer_alive": mem.get("_writer_alive"),
                "frozen": mem.get("_frozen"),
                "applied": bridge_ok,
            },
            "intel_mode": intel["mode"],
        }

    def log_message(self, fmt, *args):  # quiet
        pass


def main():
    try:
        from dotenv import load_dotenv; load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '.env'))
    except ImportError:
        pass
    global ENGINE
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=os.getenv("SENTINEL_DASH_BIND", "0.0.0.0"))
    ap.add_argument("--port", type=int, default=8515)
    args = ap.parse_args()

    print("[Dashboard] Booting Sentinel engine (loads torch, seeds inventory)...", flush=True)
    ENGINE = SentinelUnifiedServer()
    # This process is a READER of the mem_ipc bridge, not the writer: it has its
    # own engine copy, so publishing from here would clobber the MCP server's
    # authoritative snapshot with this process's empty state on every poll.
    ENGINE.mem_ipc_writer = False
    httpd = ThreadingHTTPServer((args.host, args.port), SOCHandler)
    print(f"[Dashboard] SENTINEL V3 SOC live at http://{args.host}:{args.port}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()




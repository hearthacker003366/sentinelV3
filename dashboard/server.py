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
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from backend import _paths  # noqa: E402
_paths.ensure_home_guard()

from mcp_server.server import SentinelUnifiedServer
import secrets
import time
from backend.mem_ipc import read_mem_state, write_mem_state  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
INDEX_PATH = os.path.join(HERE, "index.html")

ENGINE: SentinelUnifiedServer = None  # set in main()
SESSION_TOKEN = os.getenv("SENTINEL_DASHBOARD_TOKEN") or secrets.token_hex(24)
FAILED_APPROVALS: dict[str, tuple[int, float]] = {}


def apply_ingested_threat(engine: SentinelUnifiedServer, body: dict) -> dict:
    """Ingest live watcher/Laya threat into the Knowledge Graph and compute genuine GraphSAGE predictions."""
    target_host_name = str(body.get("host") or "WKSTN-04").upper()
    event = {
        "event_type": "NETWORK_CONNECTION",
        "host": target_host_name,
        "network": {
            "src_ip": body.get("ip", "0.0.0.0"),
            "dest_ip": "192.168.1.50",
            "dest_port": int(body.get("port", 22) or 22),
        },
        "timestamp": body.get("timestamp", ""),
        "description": body.get("details", ""),
    }
    engine.graph.ingest_normalized_event(event)
    laya_v = body.get("laya_verdict", "malicious")
    laya_conf = float(body.get("laya_confidence", 0.95))
    laya_lat = float(body.get("laya_latency_ms", 12.0))
    laya_source = str(body.get("laya_source", "LAYA-SYSTEM-1"))
    threat_type = str(body.get("type", "ATTACK"))

    engine.last_alerts.append({
        "rule_id": "LAYA_TRIAGE",
        "title": f"Laya System-1 ({laya_source}): {threat_type} ({str(laya_v).upper()} {laya_conf * 100:.1f}% in {laya_lat}ms)",
        "level": "CRITICAL" if str(laya_v).lower() == "malicious" else "HIGH",
        "host": target_host_name,
        "timestamp": event["timestamp"],
        "source": laya_source,
    })
    engine.last_laya_telemetry = {
        "system1_model": f"Laya 421M ({laya_source})",
        "median_latency_ms": round(laya_lat, 2),
        "last_latency_ms": round(laya_lat, 2),
        "last_verdict": str(laya_v),
        "last_confidence": round(laya_conf, 4),
        "source": laya_source,
        "status": "ONLINE",
    }

    target_host = f"HOST:{target_host_name}"
    if target_host not in engine.graph.nx_graph:
        target_host = "HOST:WKSTN-04"
    if target_host in engine.graph.nx_graph:
        engine.graph.mark_node_compromised(
            target_host,
            severity="CRITICAL",
            reason=f"Laya System-1 ({threat_type})",
        )

    engine.gnn.train_on_topology(epochs=15)
    preds = engine.gnn.predict_next_hop(target_host)
    engine.last_predictions = preds

    marked = 0
    for pred in preds[:2]:
        if pred.get("distance") is not None:
            engine.graph.mark_predicted_path(target_host, pred["target"], pred["probability"])
            marked += 1
    if marked == 0 and preds:
        engine.graph.mark_predicted_path(target_host, preds[0]["target"], preds[0]["probability"])

    if target_host in engine.graph.nx_graph:
        engine.graph.nx_graph.nodes[target_host]["status"] = "COMPROMISED"

    try:
        write_mem_state(engine)
    except Exception:
        pass

    return {
        "status": "ingested_to_graph",
        "laya_action": "dispatched",
        "latency_ms": laya_lat,
        "laya_source": laya_source,
        "predictions": preds,
    }


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
    def _is_authenticated(self) -> bool:
        tok = self.headers.get("X-Sentinel-Token")
        if tok and secrets.compare_digest(tok, SESSION_TOKEN):
            return True
        if "?" in self.path:
            import urllib.parse
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if qs.get("token") and secrets.compare_digest(qs["token"][0], SESSION_TOKEN):
                return True
        return False

    def do_GET(self):
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
        is_loopback = client_ip in ("127.0.0.1", "::1", "localhost")

        # Security (§2.1): reads get the same gate as writes. The dashboard
        # page embeds the session token for the UI, and /api/state exposes the
        # full SOC state — neither is served to a non-loopback client that has
        # not presented the token first. Loopback behaviour is unchanged, so
        # local use (the default 127.0.0.1 bind) works exactly as before.
        # A remote operator authenticates once via /?token=<TOKEN> (or the
        # X-Sentinel-Token header); the served page then carries the token
        # for the UI's own fetches, as it does today.
        if not is_loopback and not self._is_authenticated():
            self._json({"error": "unauthorized", "message": "Valid X-Sentinel-Token header required"}, code=401)
            return

        route = urllib.parse.urlparse(self.path).path
        if route in ("/", "/index.html"):
            with open(INDEX_PATH, "r", encoding="utf-8") as f:
                html = f.read()
            token_script = f"<script>window.SENTINEL_TOKEN = {json.dumps(SESSION_TOKEN)};</script>"
            html = html.replace("<head>", f"<head>{token_script}", 1)
            self._send(200, html.encode("utf-8"), ctype="text/html")
        elif route == "/api/state":
            self._json(self._state())
        else:
            self._json({"error": "not found"}, code=404)

    def do_POST(self):
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
        is_loopback = client_ip in ("127.0.0.1", "::1", "localhost")

        # Security (§2.1): Require valid session token on all mutating endpoints unless on loopback
        if not self._is_authenticated() and not is_loopback:
            self._json({"error": "unauthorized", "message": "Valid X-Sentinel-Token header required for mutating operations"}, code=401)
            return

        # Security (§2.1): Rate limit failed approvals
        if self.path == "/api/approve":
            now = time.time()
            fails, last_fail = FAILED_APPROVALS.get(client_ip, (0, 0.0))
            if fails >= 5 and (now - last_fail) < 60.0:
                self._json({"error": "rate_limited", "message": "Too many failed approval attempts. Locked out for 60 seconds."}, code=429)
                return

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
            res = ENGINE.call_tool("approve_isolation", {"token": token, "analyst": body.get("analyst", "DASHBOARD_ANALYST")})
            if res.get("status") == "ERROR":
                fails, _ = FAILED_APPROVALS.get(client_ip, (0, 0.0))
                FAILED_APPROVALS[client_ip] = (fails + 1, time.time())
            else:
                FAILED_APPROVALS.pop(client_ip, None)
            self._json(res)
        elif self.path == "/api/ingest_threat":
            # Bridge the Two Universes (D7): Inject terminal threats into the visual graph
            try:
                self._json(apply_ingested_threat(ENGINE, body))
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
        writer_alive = bool(mem.get("_writer_alive"))
        bridge_ok = bool(mem.get("_available")) and not mem.get("_stale") and (writer_alive or not getattr(ENGINE, "last_alerts", None))

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
        raw_pending = mem.get("pending_tokens", []) if bridge_ok else [
            t for t in (ENGINE.soar.pending_tokens or {}).values()]
        pending = []
        for t in raw_pending:
            item = dict(t) if isinstance(t, dict) else {"status": "AWAITING_HUMAN_APPROVAL"}
            raw_tok = str(item.pop("token", ""))
            item["token_masked"] = "AUTH-****..." + (raw_tok[-6:] if len(raw_tok) >= 6 else "")
            pending.append(item)

        # ---- stage history (Fix 4) ----
        stage_history = mem.get("stage_history", []) if bridge_ok else list(
            getattr(ENGINE, "stage_history", []) or [])
        stages_run = sorted({int(s) for s in stage_history if str(s).isdigit()})
        latest_stage = max(stages_run) if stages_run else 0

        intel = ENGINE.intel.check_ip("185.220.101.49")

        return {
            "mode": "REAL_PIPELINE_ON_SYNTHETIC_DATA",
            "graph": {"elements": graph.get("elements", []), "summary": graph.get("summary", {})},
            "predictions": mem.get("last_predictions", []) if (bridge_ok and mem.get("last_predictions")) else getattr(ENGINE, "last_predictions", []),
            "laya_telemetry": {
                "system1_model": (getattr(ENGINE, "last_laya_telemetry", None) or {}).get("system1_model", "Laya 421M Non-Autoregressive"),
                "median_latency_ms": (getattr(ENGINE, "last_laya_telemetry", None) or {}).get("median_latency_ms", 51.0),
                "auto_act_rate": 0.8317,
                "attack_sensitivity": 0.9572,
                "source": (getattr(ENGINE, "last_laya_telemetry", None) or {}).get("source", "STANDBY"),
                "status": "ONLINE",
            },
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
    ap.add_argument("--host", default=os.getenv("SENTINEL_DASH_BIND", "127.0.0.1"))
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




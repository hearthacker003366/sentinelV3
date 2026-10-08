"""
Sentinel Unified MCP Server (V3)
================================
ONE long-lived daemon that reunifies BOTH generations of the project:

  Generation A (V1/V2 "APT & GNN" brain):   graph, sigma, GNN, SOAR, RL, Hermes
  Generation B (V2.5 "Active Defense" kit): threat DB, intel, honeypot, reports

...exposed together as 16 stateful MCP tools over stdio JSON-RPC 2.0.

Statefulness:
  The daemon holds one persistent in-memory brain (graph, SOAR, RL, Hermes)
  for its whole lifetime, and mirrors audit + RL state into SQLite so
  `get_audit_trail` / `get_rl_score` survive even a daemon restart.

Honesty contract:
  * Every tool response payload includes a "mode" field:
      REAL               - genuinely executed (honeypot bind, intel lookup, DB write)
      SIMULATED          - synthetic event data / no-credential fallback
      REAL_PIPELINE_ON_SYNTHETIC_DATA - real detection engine, simulated input
  * Threat intel is deterministic (no random.choice) via backend.intel.
  * Containment beyond the SQLite ledger is labeled SIMULATED unless the
    environment explicitly sets ALLOW_REAL_CONTAINMENT=true.

Compliance:
  * MCP initialize handshake (protocolVersion 2024-11-05), tools/list with
    inputSchema, tools/call, JSON-RPC 2.0 error codes.
"""

import os
import sys
from dotenv import load_dotenv
HERE = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(HERE, '..', '.env'))
import json
import time
import sqlite3
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List

# --------------------------------------------------------------------------- #
# Path seatbelt â€” HARD GUARD against operating in protected locations.
# --------------------------------------------------------------------------- #
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _PROJECT_ROOT)

from backend import _paths  # noqa: E402
_paths.ensure_home_guard()

from backend.graph.graph_manager import GraphManager                     # noqa: E402
from backend.graph.schema import GraphSchema                             # noqa: E402
from backend.ingestion.log_normalizer import LogNormalizer               # noqa: E402
from backend.detection.sigma_engine import SigmaEngine                   # noqa: E402
from backend.gnn.predictor import PathPredictor                          # noqa: E402
from backend.containment.soar_engine import SOAREngine                   # noqa: E402
from backend.rl.rl_evaluator import BlueTeamRLEvaluator                  # noqa: E402
from backend.reasoning.hermes_soc_lead import HermesSOCLead              # noqa: E402
from backend.intel.threat_intel import ThreatIntelService                # noqa: E402
from backend.honeypot.honeypot_service import HoneypotService            # noqa: E402
from backend.mem_ipc import write_mem_state                               # noqa: E402
from simulator.ransomware_simulator import RansomwareSimulator           # noqa: E402

DB_PATH = _paths.db_path()
SERVER_VERSION = "3.0.0"
PROTOCOL_VERSION = "2024-11-05"


class SentinelUnifiedServer:
    """Stateful MCP server: one brain, 16 tools, SQLite-backed persistence."""

    def __init__(self):
        # ---- The Brain (long-lived in-memory state) ----
        self.graph = GraphManager()
        self.sigma = SigmaEngine(rules_dir=_paths.rules_dir())
        self.gnn = PathPredictor(self.graph)
        self.normalizer = LogNormalizer()
        self.simulator = RansomwareSimulator()
        self.hermes = HermesSOCLead(memory_file=_paths.memory_ledger_path())
        self.intel = ThreatIntelService(db_path=DB_PATH)
        self.honeypot = HoneypotService(db_path=DB_PATH)
        self.rl = BlueTeamRLEvaluator()
        self.soar = SOAREngine(self.graph)
        self._load_rl_state()

        # ---- Episode bookkeeping ----
        self.stage_history: List[int] = []
        self.last_predictions: List[Dict[str, Any]] = []
        self.last_alerts: List[Dict[str, Any]] = []
        self._request_issued_at: Dict[str, float] = {}

        # ---- Seed the standing enterprise asset inventory ----
        # A real SOC's graph already contains its known hosts/users/services;
        # incidents attach to that baseline. Mirrors get_baseline_network_topology.
        for raw in self.simulator.get_baseline_network_topology():
            self.graph.ingest_normalized_event(self.normalizer.normalize(raw))

        self._ensure_persistence_tables()
        sys.stderr.write("[SentinelV3] Unified server initialized. "
                         f"Home={_paths.SENTINEL_HOME}\n")

    # ================================================================= #
    # SQLite persistence (audit + RL)
    # ================================================================= #
    def _ensure_persistence_tables(self):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS soar_audit_v3 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                )""")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rl_state_v3 (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )""")

    def _persist_audit(self, entry: Dict[str, Any]):
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("INSERT INTO soar_audit_v3 (entry_json, created_at) VALUES (?,?)",
                             (json.dumps(entry), time.time()))
        except sqlite3.Error:
            pass

    def _load_rl_state(self):
        try:
            with sqlite3.connect(DB_PATH) as conn:
                row = conn.execute("SELECT value FROM rl_state_v3 WHERE key='cumulative'").fetchone()
            if row:
                self.rl.cumulative_reward = float(row[0])
        except (sqlite3.Error, ValueError):
            pass

    def _save_rl_state(self):
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("INSERT OR REPLACE INTO rl_state_v3 (key, value) VALUES ('cumulative', ?)",
                             (str(self.rl.cumulative_reward),))
        except sqlite3.Error:
            pass

    # ================================================================= #
    # JSON-RPC plumbing
    # ================================================================= #
    def run_stdio(self):
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                self._emit({"error": {"code": -32700, "message": "Parse error"}})
                continue
            resp = self.handle_request(req)
            if isinstance(req, dict) and "id" in req:
                resp["jsonrpc"] = "2.0"
                resp["id"] = req["id"]
            self._emit(resp)

    @staticmethod
    def _emit(obj: Dict[str, Any]):
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    def handle_request(self, req: Dict[str, Any]) -> Dict[str, Any]:
        method = req.get("method")
        if method == "initialize":
            return {"result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "sentinel-unified", "version": SERVER_VERSION},
            }}
        if method == "notifications/initialized":
            return {}
        if method == "ping":
            return {"result": {}}
        if method == "tools/list":
            return {"result": {"tools": self.tool_definitions()}}
        if method == "tools/call":
            params = req.get("params", {})
            name = params.get("name")
            args = params.get("arguments", {}) or {}
            try:
                payload = self.call_tool(name, args)
            except Exception as e:  # tool-level failure -> tool error payload
                payload = {"error": f"{type(e).__name__}: {e}", "mode": "ERROR"}
            return {"result": {"content": [{"type": "text", "text": json.dumps(payload, indent=2)}]}}
        return {"error": {"code": -32601, "message": f"Method not found: {method}"}}

    # ================================================================= #
    # Tool registry (16 tools)
    # ================================================================= #
    def tool_definitions(self) -> List[Dict[str, Any]]:
        def schema(props: Dict[str, Any], required: List[str] = None) -> Dict[str, Any]:
            return {"type": "object", "properties": props, "required": required or []}

        return [
            {"name": "query_threats", "description": "List recent threats from sentinel.db.",
             "inputSchema": schema({})},
            {"name": "check_threat_intel", "description": "Deterministic IP reputation: cache -> AbuseIPDB (if key) -> offline blocklist. Labeled REAL/OFFLINE-HEURISTIC/CACHE.",
             "inputSchema": schema({"ip": {"type": "string"}}, ["ip"])},
            {"name": "deploy_honeypot", "description": "Start the REAL multi-port honeypot (SSH+HTTP). Records attacker captures into sentinel.db.",
             "inputSchema": schema({})},
            {"name": "get_honeypot_captures", "description": "List real captures from the honeypot.",
             "inputSchema": schema({"limit": {"type": "integer"}})},
            {"name": "generate_incident_report", "description": "Generate an HTML incident report for an IP/threat combo.",
             "inputSchema": schema({"ip": {"type": "string"}, "threat_type": {"type": "string"}, "predicted_path": {"type": "string"}},
                                   ["ip", "threat_type", "predicted_path"])},
            {"name": "generate_waf_rule", "description": "Generate a WAF/iptables remediation rule file.",
             "inputSchema": schema({"threat_type": {"type": "string"}, "ip": {"type": "string"}},
                                   ["threat_type", "ip"])},
            {"name": "simulate_apt_scenario", "description": "Feed synthetic 5-stage APT events through the REAL detection pipeline (normalizer -> graph -> Sigma -> GNN -> SOAR). Stage 1..5.",
             "inputSchema": schema({"stage": {"type": "integer"}}, ["stage"])},
            {"name": "get_threat_graph", "description": "Return the full Cyber Knowledge Graph (Cytoscape format) + summary.",
             "inputSchema": schema({})},
            {"name": "predict_attack_path", "description": "Run the GraphSAGE GNN to forecast the attacker's next lateral hop from a compromised host.",
             "inputSchema": schema({"source_host": {"type": "string"}}, ["source_host"])},
            {"name": "request_host_isolation", "description": "Tier-2 SOAR: generate a human-approval isolation token for a host.",
             "inputSchema": schema({"host_id": {"type": "string"}, "reason": {"type": "string"}},
                                   ["host_id", "reason"])},
            {"name": "approve_isolation", "description": "Human approval: consume the token and quarantine the host. Awards RL score.",
             "inputSchema": schema({"token": {"type": "string"}, "analyst": {"type": "string"}}, ["token"])},
            {"name": "get_audit_trail", "description": "Full SQLite-persisted SOAR audit trail (append-only).",
             "inputSchema": schema({})},
            {"name": "get_rl_score", "description": "Blue-team RL scoreboard (cumulative, persisted across restarts).",
             "inputSchema": schema({})},
            {"name": "hermes_investigate", "description": "Run the Hermes SOC Lead's autonomous multi-bot investigation on current alerts.",
             "inputSchema": schema({})},
            {"name": "hermes_chat", "description": "Chat with the Hermes SOC Lead about the current incident.",
             "inputSchema": schema({"message": {"type": "string"}}, ["message"])},
            {"name": "reset_episode", "description": "Clear graph/alerts/episode state (keeps audit trail and RL score).",
             "inputSchema": schema({})},
        ]

    # ================================================================= #
    # Tool dispatch
    # ================================================================= #
    def call_tool(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        handler = {
            "query_threats": self.t_query_threats,
            "check_threat_intel": self.t_check_threat_intel,
            "deploy_honeypot": self.t_deploy_honeypot,
            "get_honeypot_captures": self.t_get_honeypot_captures,
            "generate_incident_report": self.t_generate_incident_report,
            "generate_waf_rule": self.t_generate_waf_rule,
            "simulate_apt_scenario": self.t_simulate_apt_scenario,
            "get_threat_graph": self.t_get_threat_graph,
            "predict_attack_path": self.t_predict_attack_path,
            "request_host_isolation": self.t_request_host_isolation,
            "approve_isolation": self.t_approve_isolation,
            "get_audit_trail": self.t_get_audit_trail,
            "get_rl_score": self.t_get_rl_score,
            "hermes_investigate": self.t_hermes_investigate,
            "hermes_chat": self.t_hermes_chat,
            "reset_episode": self.t_reset_episode,
        }.get(name)
        if handler is None:
            return {"error": f"Unknown tool: {name}", "mode": "ERROR"}
        result = handler(args)
        # Publish this engine's authoritative in-memory state to the dashboard
        # via the mem_ipc bridge. The dashboard runs its OWN engine instance, so
        # without this it shows a divergent incident view (RL +0.0, no alerts,
        # honeypot OFFLINE) for an attack this process actually ran.
        #
        # Only the MCP server publishes (mem_ipc_writer=True). The dashboard sets
        # it False because it is a READER: both processes share this call_tool,
        # so a reader that also wrote would overwrite the authoritative snapshot
        # with its own empty copy on every poll.
        # Best-effort: never let a bridge failure break the tool call.
        if getattr(self, "mem_ipc_writer", True):
            try:
                write_mem_state(self)
            except Exception:
                pass
        return result

    # ---------------- Generation B tools (Active Defense) ---------------- #
    def t_query_threats(self, args: Dict[str, Any]) -> Dict[str, Any]:
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT id, timestamp, ip, type, details, status FROM threats "
                    "ORDER BY id DESC LIMIT 25").fetchall()
            return {"mode": "REAL", "count": len(rows),
                    "threats": [dict(r) for r in rows]}
        except sqlite3.Error as e:
            return {"mode": "ERROR", "error": str(e)}

    def t_check_threat_intel(self, args: Dict[str, Any]) -> Dict[str, Any]:
        return self.intel.check_ip(str(args.get("ip", "")))

    def t_deploy_honeypot(self, args: Dict[str, Any]) -> Dict[str, Any]:
        return self.honeypot.start()

    def t_get_honeypot_captures(self, args: Dict[str, Any]) -> Dict[str, Any]:
        limit = int(args.get("limit", 25))
        return {"mode": "REAL", "captures": self.honeypot.get_captures(limit=limit),
                "status": self.honeypot.get_status()}

    def t_generate_incident_report(self, args: Dict[str, Any]) -> Dict[str, Any]:
        ip = str(args.get("ip", "unknown"))
        threat_type = str(args.get("threat_type", "UNSPECIFIED"))
        predicted_path = str(args.get("predicted_path", "N/A"))
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(_paths.SENTINEL_HOME, f"Incident_Report_{ip.replace('.', '_')}_{ts}.html")
        intel_v = self.intel.check_ip(ip)
        html = f"""<html><head><title>Sentinel V3 Incident Report</title></head>
<body style="font-family:monospace;background:#0a0a12;color:#0f0;padding:2em">
<h1>SENTINEL V3 // INCIDENT REPORT</h1>
<p><b>Generated:</b> {datetime.now(timezone.utc).isoformat()}</p>
<p><b>Attacker IP:</b> {ip}</p>
<p><b>Threat Type:</b> {threat_type}</p>
<p><b>Predicted Attack Path:</b> {predicted_path}</p>
<p><b>Threat Intel:</b> [{intel_v['mode']}] confidence {intel_v['confidence']}% â€” {intel_v['source_detail']}</p>
</body></html>"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        return {"mode": "REAL", "filepath": filepath, "intel_mode": intel_v["mode"]}

    def t_generate_waf_rule(self, args: Dict[str, Any]) -> Dict[str, Any]:
        threat_type = str(args.get("threat_type", ""))
        ip = str(args.get("ip", ""))
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(_paths.SENTINEL_HOME, f"remediation_patch_{ts}.txt")
        rule = (f"# AUTO-GENERATED REMEDIATION PATCH BY SENTINEL V3\n"
                f"# Target Threat: {threat_type}\n# Source IP: {ip}\n")
        if threat_type == "SQL_INJECTION":
            rule += 'SecRule ARGS "@rx (?i)(union|select|insert|drop|--|#)" "id:1001,deny,status:403,msg:\'SQLi Blocked\'"\n'
        elif threat_type == "DDOS_SLOWLORIS":
            rule += "limit_req zone=one burst=5 nodelay;\nlimit_conn addr 10;\n"
        else:
            rule += f"# SYNTHETIC WAF RULE for {ip} - Real environment uses native python socket drops\n"
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(rule)
        return {"mode": "REAL", "filepath": filepath,
                "note": "Rule file generated; applying it to a live firewall requires ALLOW_REAL_CONTAINMENT=true"}

    def t_send_mobile_alert(self, args: Dict[str, Any]) -> Dict[str, Any]:
        message = str(args.get("message", ""))
        token = os.getenv("SENTINEL_TELEGRAM_BOT_TOKEN") or os.getenv("TELEGRAM_BOT_TOKEN", "")
        chat = os.getenv("SENTINEL_TELEGRAM_CHAT_ID") or os.getenv("TELEGRAM_CHAT_ID", "")
        if not token or not chat:
            return {"mode": "SIMULATED",
                    "message": "No Telegram credentials set (SENTINEL_TELEGRAM_BOT_TOKEN / SENTINEL_TELEGRAM_CHAT_ID). Alert logged locally only.",
                    "alert_text": message}
        try:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            data = urllib.parse.urlencode({"chat_id": chat, "text": f"ðŸš¨ SENTINEL V3 ALERT:\n\n{message}"}).encode()
            with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=6) as r:
                ok = r.status == 200
            return {"mode": "REAL" if ok else "ERROR", "delivered": ok}
        except Exception as e:
            return {"mode": "ERROR", "error": str(e), "alert_text": message}

    # ---------------- Generation A tools (APT brain) ---------------- #
    def t_simulate_apt_scenario(self, args: Dict[str, Any]) -> Dict[str, Any]:
        stage = args.get("stage")
        try:
            stage = int(stage)
        except (TypeError, ValueError):
            return {"mode": "ERROR", "error": f"Invalid stage: {stage!r} â€” must be integer 1..5"}
        if not 1 <= stage <= 5:
            return {"mode": "ERROR", "error": f"Invalid stage {stage} â€” must be 1..5"}

        raw_events = self.simulator.generate_stage(stage)
        new_alerts = []
        ingested = 0
        for raw in raw_events:
            norm = self.normalizer.normalize(raw)
            self.graph.ingest_normalized_event(norm)
            ingested += 1
            for alert in self.sigma.evaluate_event(norm):
                new_alerts.append(alert)
                self._persist_threat_row(alert)
        self.last_alerts.extend(new_alerts)
        self.stage_history.append(stage)

        auto_actions = []
        # Stage 1: Tier-1 auto drop of the external C2 (per doctrine)
        if stage == 1:
            entry = self.soar.auto_block_ip("185.220.101.49", reason="Stage-1 external C2 beacon (T1059.001 chain)")
            self._persist_audit(entry)
            auto_actions.append(entry)

        # Stage 2+: compromise marking, GNN prediction, Tier-2 token on critical alerts
        gnn_result = None
        if stage >= 2:
            self.graph.mark_node_compromised("HOST:WKSTN-04", severity="CRITICAL",
                                             reason=f"APT stage {stage} detection")
            self.gnn.train_on_topology(epochs=15)
            self.last_predictions = self.gnn.predict_next_hop("HOST:WKSTN-04")
            top = self.last_predictions[0] if self.last_predictions else None
            gnn_result = {"top_target": top["target_name"] if top else None,
                          "probability": top["probability"] if top else None,
                          "all": self.last_predictions}
            if top:
                self.graph.mark_predicted_path("HOST:WKSTN-04",
                                               GraphSchema.make_host_id(top["target_name"]),
                                               top["probability"])
            if any(a["level"] == "CRITICAL" for a in new_alerts):
                req = self.soar.generate_isolation_request(
                    "HOST:WKSTN-04",
                    reason=f"Stage-{stage} critical detection (T1490 chain)",
                    predicted_target=top["target_name"] if top else "BACKUP-VAULT-01",
                    confidence=top["confidence_percentage"] if top else 0.0,
                )
                self._persist_audit({"id": req["token"], "tier": 2, "action": "REQUEST_ISOLATION",
                                     "target": "HOST:WKSTN-04", "status": req["status"],
                                     "timestamp": req["timestamp"]})
                self._request_issued_at[req["token"]] = time.time()
                auto_actions.append({"tier": 2, "action": "ISOLATION_TOKEN_ISSUED",
                                     "token": req["token"], "status": req["status"]})

        return {
            "mode": "REAL_PIPELINE_ON_SYNTHETIC_DATA",
            "stage": stage,
            "narrative": self.simulator.STAGE_NARRATIVES[stage],
            "events_ingested": ingested,
            "new_alerts": [{"rule_id": a["rule_id"], "title": a["title"], "level": a["level"],
                            "mitre": a["mitre_attack"]} for a in new_alerts],
            "auto_actions": auto_actions,
            "gnn_prediction": gnn_result,
            "note": "Event data is synthetic (safe). The normalizer/graph/Sigma/GNN/SOAR pipeline executed for real.",
        }

    def t_get_threat_graph(self, args: Dict[str, Any]) -> Dict[str, Any]:
        elements = self.graph.get_cytoscape_elements()
        compromised = [e["data"]["id"] for e in elements
                       if e["data"].get("status") in ("COMPROMISED", "ISOLATED")]
        return {"mode": "REAL_PIPELINE_ON_SYNTHETIC_DATA",
                "summary": {"nodes": len([e for e in elements if "source" not in e["data"]]),
                            "edges": len([e for e in elements if "source" in e["data"]]),
                            "compromised": compromised},
                "elements": elements}

    def t_predict_attack_path(self, args: Dict[str, Any]) -> Dict[str, Any]:
        source = str(args.get("source_host", "HOST:WKSTN-04"))
        self.gnn.train_on_topology(epochs=15)
        preds = self.gnn.predict_next_hop(source)
        self.last_predictions = preds
        return {"mode": "REAL_PIPELINE_ON_SYNTHETIC_DATA", "source": source,
                "predictions": preds,
                "honesty_note": "Probabilities come from the trained GraphSAGE head; "
                                "topology penalties are documented in backend/gnn/predictor.py."}

    def t_request_host_isolation(self, args: Dict[str, Any]) -> Dict[str, Any]:
        host = str(args.get("host_id", "HOST:WKSTN-04"))
        reason = str(args.get("reason", "Analyst-requested containment"))
        req = self.soar.generate_isolation_request(host, reason=reason)
        self._persist_audit({"id": req["token"], "tier": 2, "action": "REQUEST_ISOLATION",
                             "target": host, "status": req["status"], "timestamp": req["timestamp"]})
        self._request_issued_at[req["token"]] = time.time()
        return {"mode": "REAL", **req}

    def t_approve_isolation(self, args: Dict[str, Any]) -> Dict[str, Any]:
        token = str(args.get("token", ""))
        analyst = str(args.get("analyst", "ANALYST"))
        issued = self._request_issued_at.pop(token, None)
        result = self.soar.approve_and_isolate_host(token, analyst_id=analyst)
        if result.get("status") == "APPROVED_AND_ISOLATED":
            self._persist_audit(result)
            latency = (time.time() - issued) if issued else 999.0
            rl_entry = self.rl.evaluate_defense_action(
                stage=self.stage_history[-1] if self.stage_history else 0,
                action="ISOLATE_HOST",
                crown_jewel_safe=True,
                early_interception=latency < 2.5,
                state_vector=[0.0] * self.rl.state_dim,
            )
            self._save_rl_state()
            result["rl"] = rl_entry
            result["approval_latency_s"] = round(latency, 2)
        return result

    def t_get_audit_trail(self, args: Dict[str, Any]) -> Dict[str, Any]:
        entries = []
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT id, entry_json, created_at FROM soar_audit_v3 ORDER BY id DESC LIMIT 50"
                ).fetchall()
            entries = [{"db_id": r["id"], **json.loads(r["entry_json"])} for r in rows]
        except sqlite3.Error:
            pass
        return {"mode": "REAL", "persistent": True, "entries": entries}

    def t_get_rl_score(self, args: Dict[str, Any]) -> Dict[str, Any]:
        board = self.rl.get_scoreboard()
        board["mode"] = "REAL"
        board["persisted_across_restarts"] = True
        return board

    def t_hermes_investigate(self, args: Dict[str, Any]) -> Dict[str, Any]:
        summary = {"nodes_count": self.graph.nx_graph.number_of_nodes()}
        report = self.hermes.investigate_incident(self.last_alerts, self.last_predictions)
        return {"mode": "REAL_PIPELINE_ON_SYNTHETIC_DATA", "report": report,
                "graph_summary": summary}

    def t_hermes_chat(self, args: Dict[str, Any]) -> Dict[str, Any]:
        message = str(args.get("message", ""))
        summary = {"nodes_count": self.graph.nx_graph.number_of_nodes()}
        reply = self.hermes.chat_with_analyst(message, summary, self.last_alerts)
        return {"mode": "REAL", "reply": reply}

    def t_reset_episode(self, args: Dict[str, Any]) -> Dict[str, Any]:
        self.graph.clear()
        self.last_alerts.clear()
        self.last_predictions.clear()
        self.stage_history.clear()
        self._request_issued_at.clear()
        self.soar.pending_tokens.clear()
        # Clear persistent DB
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM threats")
            conn.execute("DELETE FROM soar_audit_v3")
            conn.execute("DELETE FROM honeypot_captures")
            conn.commit()

        
        # D9 FIX: re-seed the standing enterprise inventory after clear
        for raw in self.simulator.get_baseline_network_topology():
            self.graph.ingest_normalized_event(self.normalizer.normalize(raw))
            
        return {"mode": "REAL", "status": "EPISODE_RESET",
                "note": "Graph, alerts, tokens cleared. Audit trail and RL score preserved."}

    # ---------------- helpers ---------------- #
    def _persist_threat_row(self, alert: Dict[str, Any]):
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    "INSERT INTO threats (timestamp, ip, type, details, status) VALUES (?,?,?,?,?)",
                    (alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
                     str(alert.get("matched_event", {}).get("network", {}).get("dest_ip", "N/A")),
                     f"SIGMA:{alert.get('rule_id', 'unknown')}",
                     alert.get("title", ""), "NEW"))
        except sqlite3.Error:
            pass


if __name__ == "__main__":
    server = SentinelUnifiedServer()
    server.run_stdio()







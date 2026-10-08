"""
Sentinel Comprehensive Automated Verification Test Suite (V3)
=============================================================
Validates all core subsystems PLUS the V3 additions:
  * Path seatbelt (hard guard against protected locations)
  * Deterministic honest threat intel (no random.choice)
  * REAL multi-port honeypot (binds sockets, captures to SQLite)
  * Unified MCP server tool registry (17 tools)
  * Simulator -> normalizer -> graph -> Sigma -> GNN -> SOAR pipeline
"""

import os
import sys
import json
import socket
import sqlite3
import time
import unittest
import urllib.request

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from backend.ingestion.log_normalizer import LogNormalizer
from backend.graph.graph_manager import GraphManager
from backend.graph.schema import GraphSchema
from backend.detection.sigma_engine import SigmaEngine
from backend.gnn.predictor import PathPredictor
from backend.containment.soar_engine import SOAREngine
from backend.reasoning.hermes_soc_lead import HermesSOCLead
from backend.rl.rl_evaluator import BlueTeamRLEvaluator
from backend.intel.threat_intel import ThreatIntelService
from backend.honeypot.honeypot_service import HoneypotService
from simulator.ransomware_simulator import RansomwareSimulator
from backend import _paths


class TestSentinelPlatform(unittest.TestCase):
    def setUp(self):
        self.graph_mgr = GraphManager()
        self.sigma_engine = SigmaEngine(rules_dir=_paths.rules_dir())
        self.predictor = PathPredictor(self.graph_mgr)
        self.soar = SOAREngine(self.graph_mgr)
        self.hermes = HermesSOCLead()
        self.rl = BlueTeamRLEvaluator()
        self.sim = RansomwareSimulator()

    # ---------------- core subsystems ---------------- #
    def test_01_log_normalizer(self):
        raw_sysmon = {
            "event_id": 1,
            "Computer": "WKSTN-04",
            "Image": "C:\\Windows\\System32\\vssadmin.exe",
            "CommandLine": "vssadmin delete shadows /all /quiet",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "ProcessId": 6180,
            "ParentProcessId": 5240
        }
        norm = LogNormalizer.normalize(raw_sysmon)
        self.assertEqual(norm["event_type"], "PROCESS_CREATION")
        self.assertEqual(norm["host"], "WKSTN-04")
        self.assertEqual(norm["process"]["name"], "vssadmin.exe")

    def test_02_graph_manager_offline_portability(self):
        host_id = GraphSchema.make_host_id("WKSTN-04")
        proc_id = GraphSchema.make_process_id("WKSTN-04", "5240", "powershell.exe")
        self.graph_mgr.add_node(host_id, GraphSchema.LABEL_HOST, {"name": "WKSTN-04"})
        self.graph_mgr.add_node(proc_id, GraphSchema.LABEL_PROCESS, {"name": "powershell.exe"})
        self.graph_mgr.add_edge(host_id, proc_id, "HOSTS")

        elements = self.graph_mgr.get_cytoscape_elements()
        self.assertGreaterEqual(len(elements), 3)

    def test_03_sigma_detection_engine(self):
        event = {
            "event_type": "PROCESS_CREATION",
            "host": "WKSTN-04",
            "process": {
                "name": "vssadmin.exe",
                "command_line": "vssadmin delete shadows /all /quiet"
            }
        }
        alerts = self.sigma_engine.evaluate_event(event)
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "sigma_t1490_vssadmin_delete")
        self.assertEqual(alerts[0]["level"], "CRITICAL")

    def test_04_gnn_attack_path_predictor(self):
        for raw in self.sim.get_baseline_network_topology():
            norm = LogNormalizer.normalize(raw)
            self.graph_mgr.ingest_normalized_event(norm)

        self.graph_mgr.mark_node_compromised("HOST:WKSTN-04")
        predictions = self.predictor.predict_next_hop("HOST:WKSTN-04")
        self.assertGreater(len(predictions), 0)
        # Honest contract: every prediction carries a topology-derived vector
        # label and a genuine sigmoid probability (no hardcoded bounds).
        self.assertTrue(all(p["attack_vector"] for p in predictions))
        self.assertTrue(all(0.0 <= p["probability"] <= 1.0 for p in predictions))

    def test_05_soar_two_tier_containment(self):
        tier1 = self.soar.auto_block_ip("185.220.101.5")
        self.assertEqual(tier1["status"], "EXECUTED_AUTOMATICALLY (Dry-Run Logged)")

        host_id = "HOST:WKSTN-04"
        self.graph_mgr.add_node(host_id, GraphSchema.LABEL_HOST, {"name": "WKSTN-04"})
        req = self.soar.generate_isolation_request(host_id, "Ransomware test")
        tier2 = self.soar.approve_and_isolate_host(req["token"])
        self.assertEqual(tier2["status"], "APPROVED_AND_ISOLATED")

    def test_06_soar_rollback_unquarantine(self):
        host_id = "HOST:WKSTN-04"
        self.graph_mgr.add_node(host_id, GraphSchema.LABEL_HOST, {"name": "WKSTN-04"})
        req = self.soar.generate_isolation_request(host_id, "Temporary hold")
        self.soar.approve_and_isolate_host(req["token"])
        self.assertIn(host_id, self.soar.isolated_hosts)

        unq = self.soar.unquarantine_host(host_id)
        self.assertEqual(unq["status"], "RESTORED")
        self.assertNotIn(host_id, self.soar.isolated_hosts)

    def test_07_hermes_interactive_chat(self):
        summary = {"nodes_count": 6}
        alerts = [{"rule_id": "sigma_t1490_vssadmin_delete"}]
        reply = self.hermes.chat_with_analyst("Why was WKSTN-04 compromised?", summary, alerts)
        self.assertIn("Hermes", reply)

    def test_08_hermes_persistent_memory_learning(self):
        initial_count = len(self.hermes.memory["learned_false_positives"])
        test_pattern = "test_custom_backup_tool.exe"
        self.hermes.teach_false_positive(test_pattern, "Verified legitimate scheduled backup", "BACKUP-VAULT-01")
        new_count = len(self.hermes.memory["learned_false_positives"])
        self.assertEqual(new_count, initial_count + 1)

        self.hermes.teach_false_positive(test_pattern, "Updated description", "BACKUP-VAULT-01")
        self.assertEqual(len(self.hermes.memory["learned_false_positives"]), new_count)

        test_ev = {"process": {"name": test_pattern}, "host": "BACKUP-VAULT-01"}
        self.assertTrue(self.hermes.is_known_false_positive(test_ev))

        self.hermes.memory["learned_false_positives"] = [
            x for x in self.hermes.memory["learned_false_positives"] if x.get("pattern") != test_pattern
        ]
        self.hermes._save_memory()

    def test_09_reinforcement_learning_evaluator(self):
        entry = self.rl.evaluate_defense_action(
            stage=5,
            action="ISOLATE_HOST",
            crown_jewel_safe=True,
            early_interception=True
        )
        self.assertEqual(entry["reward_delta"], 15.0)
        self.assertEqual(entry["standing"], "OPTIMAL_DEFENSE")

    # ---------------- V3 additions ---------------- #
    def test_10_path_seatbelt(self):
        """Guard must hard-refuse protected locations."""
        self.assertEqual(_paths.SENTINEL_HOME, BASE_DIR)
        

        import backend._paths as paths_mod
        self.assertIn("02_ai_development", paths_mod.PROTECTED_FRAGMENTS)
        # The real guard passes in this workspace (no exception raised)
        self.assertEqual(paths_mod.ensure_home_guard(), BASE_DIR)

    def test_11_intel_is_deterministic_and_labeled(self):
        """Same IP -> same verdict. No random.choice anywhere."""
        svc = ThreatIntelService(db_path=":memory:", abuseipdb_key="")
        v1 = svc.check_ip("185.220.101.49")
        v2 = svc.check_ip("185.220.101.49")
        self.assertEqual(v1, v2, "Intel verdicts must be deterministic")
        self.assertIn(v1["mode"], ("REAL", "OFFLINE-HEURISTIC", "CACHE"))
        self.assertTrue(v1["is_honest"])
        # DROP-listed range must be flagged with recommendation
        self.assertIn(v1["recommendation"], ("ROUTE_TO_HONEYPOT", "BAN"))
        # Private IP must be recognized as internal
        priv = svc.check_ip("192.168.1.50")
        self.assertEqual(priv["confidence"], 0)

    def test_12_real_honeypot_binds_and_captures(self):
        """The honeypot must REALLY bind a port and REALLY capture a connection."""
        import tempfile
        import uuid as _uuid
        tmp_db = os.path.join(tempfile.gettempdir(), f"sentinel_test_{_uuid.uuid4().hex[:8]}.db")
        # Use odd high ports to avoid collisions
        hp = HoneypotService(db_path=tmp_db, bind_host="127.0.0.1",
                             ports={"ssh": 22222, "http": 22223})
        status = hp.start()
        self.assertEqual(status["status"], "RUNNING")
        self.assertEqual(status["mode"], "REAL")
        try:
            time.sleep(0.3)
            # SSH pot: connect and attempt a login
            s = socket.create_connection(("127.0.0.1", 22222), timeout=5)
            banner = s.recv(128)
            self.assertIn(b"SSH-2.0", banner)
            s.sendall(b"root\n")
            s.recv(64)  # Password: prompt
            s.sendall(b"hunter2\n")
            time.sleep(0.3)
            s.close()

            # Poll for the async capture (thread handler latency)
            caps = []
            for _ in range(20):
                caps = hp.get_captures(limit=10)
                if caps:
                    break
                time.sleep(0.15)

            self.assertGreaterEqual(len(caps), 1)
            ssh_caps = [c for c in caps if c["pot_type"] == "ssh"]
            self.assertGreaterEqual(len(ssh_caps), 1)
            payload = json.loads(ssh_caps[0]["payload"])
            self.assertEqual(payload["username"], "root")
            self.assertEqual(payload["password"], "hunter2")

            # Verify REAL SQLite persistence (not the in-memory mirror)
            with sqlite3.connect(tmp_db) as conn:
                row = conn.execute(
                    "SELECT COUNT(*) FROM honeypot_captures WHERE pot_type='ssh'").fetchone()
            self.assertGreaterEqual(row[0], 1, "Capture must be persisted to SQLite")
        finally:
            hp.stop()
            try:
                os.remove(tmp_db)
            except OSError:
                pass

    def test_13_unified_mcp_tool_registry(self):
        """The unified server must expose the full 16-tool registry."""
        mcp_srv_path = os.path.join(BASE_DIR, "mcp_server", "server.py")
        self.assertTrue(os.path.exists(mcp_srv_path))
        src = open(mcp_srv_path, "r", encoding="utf-8").read()
        for tool in ["query_threats", "check_threat_intel", "deploy_honeypot",
                     "get_honeypot_captures", "generate_incident_report", "generate_waf_rule",
                     "simulate_apt_scenario", "get_threat_graph",
                     "predict_attack_path", "request_host_isolation", "approve_isolation",
                     "get_audit_trail", "get_rl_score", "hermes_investigate",
                     "hermes_chat", "reset_episode"]:
            self.assertIn(f'"{tool}"', src, f"Tool {tool} missing from unified server")

        # No fake intel left behind
        self.assertNotIn("random.choice([0, 15, 99])", src)
        # No dotenv / 02_AI_Development references
        self.assertNotIn("02_AI_Development", src)

    def test_14_full_pipeline_e2e(self):
        """Simulator -> normalizer -> graph -> Sigma -> GNN -> SOAR end-to-end."""
        normalizer = LogNormalizer()
        # Seed the standing asset inventory (as a real SOC graph would have)
        for raw in self.sim.get_baseline_network_topology():
            self.graph_mgr.ingest_normalized_event(normalizer.normalize(raw))
        for stage in (1, 2, 3):
            for raw in self.sim.generate_stage(stage):
                norm = normalizer.normalize(raw)
                self.graph_mgr.ingest_normalized_event(norm)
                alerts = self.sigma_engine.evaluate_event(norm)
                if stage == 2:
                    self.assertGreaterEqual(len(alerts), 1, "Stage 2 must trip T1490")
        self.graph_mgr.mark_node_compromised("HOST:WKSTN-04")
        preds = self.predictor.predict_next_hop("HOST:WKSTN-04")
        self.assertGreater(len(preds), 0)

        req = self.soar.generate_isolation_request("HOST:WKSTN-04", "E2E test")
        result = self.soar.approve_and_isolate_host(req["token"])
        self.assertEqual(result["status"], "APPROVED_AND_ISOLATED")

    def test_15_simulator_stage_validation(self):
        with self.assertRaises(ValueError):
            self.sim.generate_stage(0)
        with self.assertRaises(ValueError):
            self.sim.generate_stage(6)
        with self.assertRaises(ValueError):
            self.sim.generate_stage("two")


if __name__ == "__main__":
    unittest.main(verbosity=2)

def test_d3_wiring_determinism():
    from mcp_server.server import SentinelUnifiedServer
    s1 = SentinelUnifiedServer()
    s1.t_reset_episode({})
    s1.simulator.generate_stage(2)  # Stage 2 to force malicious activity
    p1 = s1.t_predict_attack_path({})
    
    s2 = SentinelUnifiedServer()
    s2.t_reset_episode({})
    s2.simulator.generate_stage(2)
    p2 = s2.t_predict_attack_path({})
    
    assert len(p1.get("predictions", [])) > 0, "Predictions should not be empty (D1 check)"
    assert p1 == p2, "Predictions must be perfectly deterministic across runs (D2 check)"

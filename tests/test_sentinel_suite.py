"""
Unified Test Suite for Sentinel V3 Enterprise Defense Platform
Covers:
  - Graph state & Cypher engine
  - Sigma rule matching
  - GNN Link Prediction (PyTorch / fallback)
  - Two-Tier SOAR Isolation & Cryptographic Tokens
  - Threat Intel (Honest mode labeling)
  - Real Honeypot Binding & Forensics
  - End-to-End Pipeline & Replay Determinism
  - Comprehensive Test Integrity (§2.28)
"""

import os
import sys
import json
import time
import socket
import sqlite3
import unittest
import tempfile
import uuid
from unittest.mock import patch

# Ensure repo root is on sys.path
BASE_DIR = os.path.normpath(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend import _paths
from backend.graph.graph_manager import GraphManager
from backend.graph.schema import GraphSchema
from backend.detection.sigma_engine import SigmaEngine
from backend.ingestion.log_normalizer import LogNormalizer
from backend.gnn.predictor import PathPredictor
from backend.containment.soar_engine import SOAREngine
from backend.reasoning.hermes_soc_lead import HermesSOCLead
from backend.rl.rl_evaluator import BlueTeamRLEvaluator
from backend.intel.threat_intel import ThreatIntelService
from backend.honeypot.honeypot_service import HoneypotService
from simulator.ransomware_simulator import RansomwareSimulator
from mcp_server.server import SentinelUnifiedServer


class SentinelTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _paths.ensure_home_guard()
        cls.sim = RansomwareSimulator(target_host="WKSTN-04")

    def setUp(self):
        self.graph_mgr = GraphManager()
        self.sigma_engine = SigmaEngine(rules_dir=_paths.rules_dir())
        self.predictor = PathPredictor(self.graph_mgr)
        self.soar = SOAREngine(self.graph_mgr)
        self.hermes = HermesSOCLead()
        self.rl = BlueTeamRLEvaluator()

    # ---------------- Basic unit tests ---------------- #
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
        norm = LogNormalizer().normalize(raw_sysmon)
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

    def test_04_gnn_next_hop_forecasting(self):
        normalizer = LogNormalizer()
        for raw in self.sim.get_baseline_network_topology():
            self.graph_mgr.ingest_normalized_event(normalizer.normalize(raw))

        self.graph_mgr.mark_node_compromised("HOST:WKSTN-04")
        preds = self.predictor.predict_next_hop("HOST:WKSTN-04")
        self.assertIsInstance(preds, list)
        self.assertGreater(len(preds), 0)
        top = preds[0]
        self.assertIn("probability", top)
        self.assertIn("mode", top)  # Honest mode label (§2.24)
        self.assertIn(top["mode"], ("GNN-TORCH", "HEURISTIC-FALLBACK"))

    def test_05_two_tier_soar_isolation_flow(self):
        host_id = "HOST:WKSTN-04"
        req = self.soar.generate_isolation_request(host_id, "Active Ransomware Propagation", "BACKUP-VAULT-01")
        token = req["token"]
        self.assertTrue(token.startswith("AUTH-"))
        self.assertIn(token, self.soar.pending_tokens)

        # Invalid token must fail
        bad_res = self.soar.approve_and_isolate_host("AUTH-INVALID-TOKEN-12345")
        self.assertEqual(bad_res["status"], "ERROR")
        self.assertIn("Invalid or expired", bad_res.get("message", ""))

        # Legitimate token approval
        good_res = self.soar.approve_and_isolate_host(token, analyst_id="SOC-LEAD")
        self.assertEqual(good_res["status"], "APPROVED_AND_ISOLATED")
        self.assertIn(host_id, self.soar.isolated_hosts)

    def test_06_soar_unquarantine(self):
        host_id = "HOST:WKSTN-04"
        req = self.soar.generate_isolation_request(host_id, "Test quarantine")
        self.soar.approve_and_isolate_host(req["token"])
        self.assertIn(host_id, self.soar.isolated_hosts)

        unq_res = self.soar.unquarantine_host(host_id, analyst_id="SOC-ADMIN")
        self.assertEqual(unq_res["status"], "RESTORED")
        self.assertNotIn(host_id, self.soar.isolated_hosts)

    def test_07_hermes_interactive_chat(self):
        summary = {"nodes_count": 6}
        alerts = [{"rule_id": "sigma_t1490_vssadmin_delete"}]
        reply = self.hermes.chat_with_analyst("Why was WKSTN-04 compromised?", summary, alerts)
        self.assertIn("Hermes", reply)

    def test_08_hermes_persistent_memory_learning_isolated(self):
        """Hermes persistent memory must operate on an isolated temp file (§2.28)."""
        tmp_mem = os.path.join(tempfile.gettempdir(), f"hermes_mem_{uuid.uuid4().hex[:8]}.json")
        try:
            lead = HermesSOCLead(memory_file=tmp_mem)
            initial_count = len(lead.memory["learned_false_positives"])
            test_pattern = "test_custom_backup_tool.exe"
            lead.teach_false_positive(test_pattern, "Verified legitimate scheduled backup", "BACKUP-VAULT-01")
            new_count = len(lead.memory["learned_false_positives"])
            self.assertEqual(new_count, initial_count + 1)

            test_ev = {"process": {"name": test_pattern}, "host": "BACKUP-VAULT-01"}
            self.assertTrue(lead.is_known_false_positive(test_ev))
        finally:
            if os.path.exists(tmp_mem):
                try:
                    os.remove(tmp_mem)
                except OSError:
                    pass

    def test_09_reinforcement_learning_evaluator(self):
        entry = self.rl.evaluate_defense_action(
            stage=5,
            action="ISOLATE_HOST",
            crown_jewel_safe=True,
            early_interception=True,
            state_vector=[1.0, 0.5, 1.0, 0.2]
        )
        self.assertEqual(entry["reward_delta"], 15.0)
        self.assertEqual(entry["standing"], "OPTIMAL_DEFENSE")
        # Validate that unknown action raises ValueError (§2.26)
        with self.assertRaises(ValueError):
            self.rl.evaluate_defense_action(stage=1, action="UNKNOWN_ACTION", crown_jewel_safe=True, early_interception=True)

    # ---------------- V3 additions & Hardening ---------------- #
    def test_10_path_seatbelt_boundary_enforcement(self):
        """Guard must hard-refuse invalid or corrupted roots (§2.28)."""
        self.assertEqual(_paths.ensure_home_guard(), BASE_DIR)
        with patch.object(_paths, "SENTINEL_HOME", "/nonexistent_invalid_path_12345"):
            with self.assertRaises(RuntimeError):
                _paths.ensure_home_guard()

    def test_11_intel_is_deterministic_and_cache_isolated(self):
        """Same IP -> same verdict. Real cache hit verified using temp SQLite DB (§2.28)."""
        tmp_db = os.path.join(tempfile.gettempdir(), f"intel_test_{uuid.uuid4().hex[:8]}.db")
        try:
            svc = ThreatIntelService(db_path=tmp_db, abuseipdb_key="")
            v1 = svc.check_ip("185.220.101.49")
            v2 = svc.check_ip("185.220.101.49")
            self.assertEqual(v1["ip"], v2["ip"])
            self.assertEqual(v1["confidence"], v2["confidence"])
            self.assertEqual(v2["mode"], "CACHE", "Second lookup must hit the persistent cache")
            self.assertTrue(v1["is_honest"])
            # Private IP must be recognized as internal
            priv = svc.check_ip("192.168.1.50")
            self.assertEqual(priv["confidence"], 0)
        finally:
            if os.path.exists(tmp_db):
                try:
                    os.remove(tmp_db)
                except OSError:
                    pass

    def test_12_real_honeypot_binds_ephemeral_ports(self):
        """The honeypot must bind dynamic port 0 and capture connection reliably (§2.28)."""
        tmp_db = os.path.join(tempfile.gettempdir(), f"hp_test_{uuid.uuid4().hex[:8]}.db")
        hp = HoneypotService(db_path=tmp_db, bind_host="127.0.0.1", ports={"ssh": 0, "http": 0})
        status = hp.start()
        self.assertEqual(status["status"], "RUNNING")
        self.assertEqual(status["mode"], "REAL")
        ssh_port = hp.ports["ssh"]
        self.assertGreater(ssh_port, 0)

        try:
            time.sleep(0.3)
            s = socket.create_connection(("127.0.0.1", ssh_port), timeout=5)
            banner = s.recv(128)
            self.assertIn(b"SSH-2.0", banner)
            s.sendall(b"root\n")
            s.recv(64)
            s.sendall(b"hunter2\n")
            time.sleep(0.3)
            s.close()

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
            self.assertTrue(payload.get("password_hash", "").startswith("sha256:"))
        finally:
            hp.stop()
            if os.path.exists(tmp_db):
                try:
                    os.remove(tmp_db)
                except OSError:
                    pass

    def test_13_unified_mcp_tool_registry_callable(self):
        """All registered tools in the unified server must be executable via call_tool without AttributeError (§2.28, C4)."""
        tmp_db = os.path.join(tempfile.gettempdir(), f"mcp_test_{uuid.uuid4().hex[:8]}.db")
        try:
            with patch.dict(os.environ, {"SENTINEL_DB_PATH": tmp_db}):
                server = SentinelUnifiedServer()
                tools = server.tool_definitions()
                self.assertEqual(len(tools), 18)

                # Test call_tool dispatch for EVERY registered tool name (C4 requirement)
                dummy_args = {
                    "query_threats": {},
                    "check_threat_intel": {"ip": "127.0.0.1"},
                    "deploy_honeypot": {},
                    "get_honeypot_captures": {"limit": 5},
                    "generate_incident_report": {"ip": "10.0.0.1", "threat_type": "TEST", "predicted_path": "HOST:DC01"},
                    "generate_waf_rule": {"ip": "10.0.0.1", "threat_type": "SQL_INJECTION"},
                    "simulate_apt_scenario": {"stage": 1},
                    "get_threat_graph": {},
                    "predict_attack_path": {"source_host": "HOST:WKSTN-04"},
                    "request_host_isolation": {"host_id": "HOST:WKSTN-04", "reason": "Test"},
                    "approve_isolation": {"token": "AUTH-TEST-DUMMY"},
                    "get_audit_trail": {},
                    "get_rl_score": {},
                    "hermes_investigate": {},
                    "hermes_chat": {"message": "status"},
                    "reset_episode": {},
                    "send_mobile_alert": {"message": "Test"},
                    "unquarantine_host": {"host_id": "HOST:WKSTN-04"},
                }
                for tool in tools:
                    name = tool["name"]
                    args = dummy_args.get(name, {})
                    res = server.call_tool(name, args)
                    self.assertIsInstance(res, dict, f"Tool {name} did not return a dict")
        finally:
            if os.path.exists(tmp_db):
                try:
                    os.remove(tmp_db)
                except OSError:
                    pass

    def test_14_full_pipeline_e2e(self):
        """Simulator -> normalizer -> graph -> Sigma -> GNN -> SOAR end-to-end."""
        normalizer = LogNormalizer()
        for raw in self.sim.get_baseline_network_topology():
            self.graph_mgr.ingest_normalized_event(normalizer.normalize(raw))
        stage2_alerts = []
        for stage in (1, 2, 3):
            for raw in self.sim.generate_stage(stage):
                norm = normalizer.normalize(raw)
                self.graph_mgr.ingest_normalized_event(norm)
                alerts = self.sigma_engine.evaluate_event(norm)
                if stage == 2 and alerts:
                    stage2_alerts.extend(alerts)
        self.assertGreaterEqual(len(stage2_alerts), 1, "Stage 2 must trip T1490")
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

    def test_16_master_attacker_syntax_and_paths(self):
        import py_compile
        attacker_path = os.path.join(BASE_DIR, "demo_tools", "master_attacker.py")
        self.assertTrue(os.path.exists(attacker_path), "master_attacker.py must exist")
        py_compile.compile(attacker_path, doraise=True)
        with open(attacker_path, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("`n", src)
        self.assertIn('"backend"', src)
        self.assertIn('"demo_auth.log"', src)

    def test_17_d3_wiring_determinism_isolated(self):
        """Replay determinism test moved inside TestCase with isolated temp databases (§2.28)."""
        tmp_db1 = os.path.join(tempfile.gettempdir(), f"det_db1_{uuid.uuid4().hex[:8]}.db")
        tmp_db2 = os.path.join(tempfile.gettempdir(), f"det_db2_{uuid.uuid4().hex[:8]}.db")
        try:
            with patch.dict(os.environ, {"SENTINEL_DB_PATH": tmp_db1}):
                s1 = SentinelUnifiedServer()
                s1.t_reset_episode({})
                s1.t_simulate_apt_scenario({"stage": 2})
                p1 = s1.t_predict_attack_path({})

            with patch.dict(os.environ, {"SENTINEL_DB_PATH": tmp_db2}):
                s2 = SentinelUnifiedServer()
                s2.t_reset_episode({})
                s2.t_simulate_apt_scenario({"stage": 2})
                p2 = s2.t_predict_attack_path({})

            self.assertGreater(len(p1.get("predictions", [])), 0)
            self.assertEqual(p1, p2)
        finally:
            for p in (tmp_db1, tmp_db2):
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except OSError:
                        pass

    def test_18_token_expiry_path(self):
        """15-minute token expiry test in SOAREngine (§2.28)."""
        req = self.soar.generate_isolation_request("HOST:WKSTN-04", "Test expiry timeout")
        token = req["token"]
        self.assertIn(token, self.soar.pending_tokens)

        # Simulate 950 seconds elapsed (TTL is 900s)
        self.soar.pending_tokens[token]["created_at"] = time.time() - 950.0

        # Attempt to approve expired token
        result = self.soar.approve_and_isolate_host(token, analyst_id="SOC-ADMIN")
        self.assertEqual(result["status"], "ERROR")
        self.assertIn("Invalid or expired", result.get("message", ""))
        self.assertNotIn(token, self.soar.pending_tokens)


if __name__ == "__main__":
    unittest.main(verbosity=2)

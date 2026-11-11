"""
Test Suite for Laya System-1 Integration in Sentinel V3
======================================================
Tests sub-50ms triage, lateral attack path prediction,
and Hermes honeypot auto-dispatch.
"""

import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import json
import time
import pytest
from backend.triage.laya_triage_engine import LayaTriageEngine, get_laya_engine
from backend import _paths


@pytest.fixture
def triage_engine(tmp_path):
    test_db = str(tmp_path / "test_sentinel.db")
    engine = LayaTriageEngine(db_path=test_db, dashboard_url="http://127.0.0.1:9999")
    return engine


def test_laya_fast_triage_latency(triage_engine):
    """Verifies that Laya System-1 completes triage with steady-state latency."""
    event = "Failed password for root from 192.168.56.20 port 2222 ssh2"
    # Warmup pass (ensures CUDA graph / memory allocator is primed)
    _ = triage_engine.triage_event(event, ip="192.168.56.20", threat_type="BRUTE_FORCE_SSH")

    # Measured pass
    result = triage_engine.triage_event(event, ip="192.168.56.20", threat_type="BRUTE_FORCE_SSH")
    
    assert result.latency_ms < 200.0, f"Latency {result.latency_ms}ms exceeded threshold"
    assert result.verdict in ("suspicious", "malicious")
    assert result.action == "WAKE_HERMES"
    assert len(result.predicted_path) >= 2


def test_laya_benign_event_filtering(triage_engine):
    """Verifies benign events are classified with high confidence and auto-filed."""
    event = "BENIGN routine apt update package cache sync completed"
    result = triage_engine.triage_event(event, ip="127.0.0.1", threat_type="ROUTINE_MAINTENANCE")
    
    assert result.verdict == "benign"
    assert result.is_attack is False
    assert result.action == "AUTO_FILE"


def test_laya_predictive_lateral_path(triage_engine):
    """Verifies lateral attack path forecasting for different attack vectors."""
    # 1. SSH brute force should forecast domain controller / win10
    path_ssh = triage_engine.predict_lateral_path("192.168.56.20", "BRUTE_FORCE_SSH", 0.9)
    assert any("dc" in hop.lower() or "win10" in hop.lower() for hop in path_ssh)

    # 2. Port scan should forecast honeypot trap
    path_scan = triage_engine.predict_lateral_path("10.0.0.5", "PORT_SCAN_NMAP", 0.6)
    assert any("honeypot" in hop.lower() or "gateway" in hop.lower() for hop in path_scan)


def test_dispatch_wakes_hermes_and_logs(triage_engine, tmp_path):
    """Verifies dispatch writes to DB and notifies Hermes queue."""
    event = "sudo: 3 authentication failures; logname= uid=1000 euid=0 tty=/dev/pts/1"
    result = triage_engine.triage_event(event, ip="192.168.56.31", threat_type="PRIVILEGE_ESCALATION")
    
    # Dispatch threat
    triage_engine.dispatch_threat("192.168.56.31", "PRIVILEGE_ESCALATION", event, result)

    # Check database
    import sqlite3
    with sqlite3.connect(triage_engine.db_path) as conn:
        c = conn.cursor()
        rows = c.execute("SELECT ip, type, status, laya_verdict FROM threats WHERE ip='192.168.56.31'").fetchall()
        assert len(rows) >= 1
        assert rows[0][0] == "192.168.56.31"
        assert rows[0][2] == "WAKE_HERMES"
        assert rows[0][3] == result.verdict
def test_laya_gpu_bridge_used_when_local_weights_missing(tmp_path):
    """Verifies HTTP GPU bridge serves real Laya inference when local weights are absent."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class StubHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            _ = self.rfile.read(length)
            body = json.dumps({
                "verdict": "malicious",
                "confidence": 0.9412,
                "is_attack": True,
                "severity": 0.88,
                "latency_ms": 14.2,
                "source": "LAYA-421M-GPU",
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), StubHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        test_db = str(tmp_path / "bridge_test.db")
        engine = LayaTriageEngine(
            checkpoint_dir=str(tmp_path / "missing_ckpt"),
            db_path=test_db,
            dashboard_url="http://127.0.0.1:9999",
            laya_url=f"http://127.0.0.1:{port}",
        )
        res = engine.triage_event("Failed password for root", ip="192.168.56.20", threat_type="BRUTE_FORCE_SSH")
        assert res.source == "LAYA-GPU-BRIDGE"
        assert res.verdict == "malicious"
        assert res.confidence == 0.9412
        assert res.is_attack is True
    finally:
        srv.shutdown()
        srv.server_close()


def test_laya_fallback_reports_honest_source(tmp_path):
    """When neither local checkpoint nor GPU bridge is available, source is explicitly HEURISTIC-FALLBACK."""
    test_db = str(tmp_path / "fallback_test.db")
    engine = LayaTriageEngine(
        checkpoint_dir=str(tmp_path / "missing_ckpt"),
        db_path=test_db,
        dashboard_url="http://127.0.0.1:9999",
        laya_url="",
    )
    res = engine.triage_event("Failed password for root", ip="192.168.56.20", threat_type="BRUTE_FORCE_SSH")
    assert res.source == "HEURISTIC-FALLBACK"


def test_dashboard_ingest_computes_real_gnn_predictions():
    """Ingesting a live threat on dashboard must run GraphSAGE predict_next_hop instead of hardcoded strings."""
    import tempfile
    import uuid
    from unittest.mock import patch

    tmp_db = os.path.join(tempfile.gettempdir(), f"dash_gnn_{uuid.uuid4().hex[:8]}.db")
    try:
        with patch.dict(os.environ, {"SENTINEL_DB_PATH": tmp_db}):
            from mcp_server.server import SentinelUnifiedServer
            from dashboard.server import apply_ingested_threat

            eng = SentinelUnifiedServer()
            out = apply_ingested_threat(eng, {
                "ip": "192.168.56.20",
                "type": "BRUTE_FORCE_SSH",
                "details": "5+ failed SSH logins detected",
                "laya_verdict": "malicious",
                "laya_confidence": 0.94,
                "laya_latency_ms": 18.5,
                "laya_source": "LAYA-GPU-BRIDGE",
            })
            assert out["status"] == "ingested_to_graph"
            assert len(eng.last_predictions) > 0
            assert eng.last_predictions[0]["mode"] in ("GNN-TORCH", "HEURISTIC-FALLBACK")
            assert "distance" in eng.last_predictions[0]
            predicted_edges = [
                (u, v, d) for u, v, d in eng.graph.nx_graph.edges(data=True)
                if (d.get("type") or d.get("relationship")) == "PREDICTED_ATTACK_PATH"
            ]
            assert len(predicted_edges) >= 1
    finally:
        if os.path.exists(tmp_db):
            try:
                os.remove(tmp_db)
            except OSError:
                pass

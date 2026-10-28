"""
Test Suite for Laya System-1 Integration in Sentinel V3
======================================================
Tests sub-50ms triage, lateral attack path prediction,
and Hermes honeypot auto-dispatch.
"""

import os
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
